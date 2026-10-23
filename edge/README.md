# edge/ — 엣지 피처 추출 + DB 보안 (새 버전)

각 호스트가 로그를 **그 자리에서 피처로 요약**하고, **숫자 벡터만** 중앙 collector로 보낸다.
원본 로그(민감·개인정보 포함)는 호스트 밖으로 나가지 않는다.

```
[웹 호스트]  nginx 로그 ─▶ edge_agent --kind web ─┐
                          (웹 피처 벡터)           │
                                                   ├─▶ collector ─▶ 저장모델 판정 / 규칙 ─▶ 🚨 경보
[DB 호스트]  MySQL log ─▶ edge_agent --kind db ───┘      + 스풀(spool.jsonl)에 벡터 적재
                          (DB 피처 벡터, 원본 쿼리 전송 안 함)
```

`../consumer`(단순)와의 차이: 소비자는 중앙이 **원본 로그 전체**를 읽는다. 엣지는 **벡터만** 전송 → 대역폭·개인정보에 유리, 다중 호스트 확장에 맞음.

## 파일

| 파일 | 역할 |
|---|---|
| `edge_agent.py` | 호스트에서 돈다. `--kind web`(nginx) / `--kind db`(MySQL) → 피처 벡터를 collector로 전송 |
| `db_features.py` | **MySQL general query log → DB 피처** (BOLA·SQLi·대량수집·AI 간격). 원본 쿼리는 숫자로만 요약 |
| `collector.py` | 중앙 수신·판정·적재. 웹 벡터는 `.joblib`로, DB 벡터는 임시 규칙으로 1차 경보 |

## DB 피처 (db_features.py) — DB 보안 관점

HTTP 로그가 못 보는 것을 쿼리 로그가 본다.

| 피처 | 잡는 것 |
|---|---|
| `distinct_where_ids` | **BOLA/열거** — WHERE 절(`=N`, `IN(...)`)에서 접근한 서로 다른 레코드 id 수. 정상 1~2, 공격 수십 |
| `sqli_token_hits` | **SQLi** — UNION·주석(`--`,`/*`)·`information_schema`·`sleep()`·`OR 1=1`·`0x..` 등 |
| `uniq_templates` | 쿼리 템플릿 다양성 (리터럴을 `?`로 정규화) — 비정상 쿼리 패턴 |
| `select_ratio`/`write_ratio`/`distinct_tables` | 읽기·쓰기 비율, 건드린 테이블 수 |
| `interval_cv` | 요청 간격 규칙성 — **AI 에이전트**는 기계적으로 일정(낮음) |

MySQL general log 켜기: `SET GLOBAL general_log='ON'; SET GLOBAL log_output='FILE';`

## 사용

```bash
# 1) 중앙 collector (분석 PC) — 웹 모델 연결, 받은 벡터는 스풀에 적재
python edge/collector.py --model models/model.joblib --port 8000 --spool edge/spool.jsonl

# 2) 웹 호스트에서
python edge/edge_agent.py --kind web --log /var/log/nginx/juiceshop_access.log \
    --collector http://<분석PC>:8000 --interval 60 --host-id web01

# 3) DB 호스트에서 (원본 쿼리는 전송 안 됨)
python edge/edge_agent.py --kind db --log /var/lib/mysql/db.log \
    --collector http://<분석PC>:8000 --interval 60 --host-id db01

# 전송 전 확인: 보내지 않고 벡터만 보기
python edge/edge_agent.py --kind db --log general.log --once --dry-run
python edge/db_features.py --log general.log --print
```

## DB 모델은 아직 규칙 — 다음 단계

웹은 학습 모델(`model.joblib`)이 있지만 **DB 피처는 아직 모델이 없어** collector가 임시 규칙(SQLi 토큰>0, WHERE id ≥ 임계값)으로 1차 경보한다. 쌓인 DB 벡터(`spool.jsonl`)를 CSV로 모아 `ml/train_export.py`로 **DB 전용 모델**을 학습하면, 웹과 같은 IF·LOF·RF 판정으로 넘어갈 수 있다. (DB 피처로 정상/공격을 모아 `features`/`answer` 형식에 맞추면 그대로 재사용)

## 주의

- `spool.jsonl`은 적재 파일이라 git에 올리지 않는다(`.gitignore`).
- collector는 LAN 내부에서만. 외부 노출 금지(인증 없음 — 랩 전용).
