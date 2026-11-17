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
| `correlate.py` | **출발지 귀속**(docs/14 §4): `--mode tier`(DB 티어 전체 단위) / `--mode join`(웹-DB 시간 상관으로 웹 IP에 db_* 피처 결합) |
| `host_metrics.py` | **node_exporter 지표 → 호스트 피처**(`host_v1` 12개: CPU 지속·송신 편중·연결 수…). Prometheus API / 저장 JSON / `/metrics` 스냅샷(`--collect`, Prometheus 없는 랩) 3입력. `docs/27` §3 |
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

## DB 모델 학습됨 (`models/db_model.joblib`)

DB 피처로도 웹과 같은 IF·LOF·RF 모델을 학습했다. collector에 `--db-model`을 주면 규칙 대신 모델로 판정한다.

```bash
# DB 학습 데이터(합성) → 피처 → 모델
python tools/gen_db_traffic.py --out data/general_lab.log --answer data/answer_db.csv
python edge/db_features.py --log data/general_lab.log --out data/features_db.csv
python ml/train_export.py data/features_db.csv --answer data/answer_db.csv --contamination 0.05 --out models/db_model.joblib

# collector에 DB 모델 연결
python edge/collector.py --model models/model.joblib --db-model models/db_model.joblib --port 8000
```

결과(합성, scikit-learn 1.9.1): E2 탐지율 LOF 1.00 / IF 0.78(IF가 놓치고 LOF가 잡은 느린 BOLA 2구간, H5), 종류 분류 5/9 — sqli·scrape는 정확, 느린 bola는 일부 정상으로. **웹 계층과 같은 경향**이 DB 계층에서도 재현됨.
`--db-model` 없이 돌리면 임시 규칙(SQLi 토큰>0, WHERE id ≥ 임계값)으로 1차 경보한다.
한계: 합성 데이터라 경향 확인용. 실제 MySQL 로그로 재검증 필요. DB 사용자가 하나면 쿼리의 출발지 구분 보강 필요.

## 호스트 지표 (host_metrics.py) — 자원/가용성 공격

로그가 못 보는 채굴·연결 폭주·유출을 본다(API 로직 공격엔 무신호 — `docs/26` §2). **호스트마다 따로 학습**한다(통합 모델은 한 호스트의 이상이 다른 호스트의 평소에 묻힘).

```bash
# Prometheus 없는 랩: 분석 PC 에서 /metrics 를 15초마다 떠 둔다 (최소 하루 = 계절성 1주기)
python edge/host_metrics.py --collect http://10.16.1.10:9100/metrics --out-dir data/host_snap --interval 15 --duration 86400
python edge/host_metrics.py --snapshots data/host_snap --out data/host_features.csv
# Prometheus 가 있으면
python edge/host_metrics.py --prom http://<prom>:9090 --start 2026-10-25T00:00:00Z --end 2026-10-26T00:00:00Z --out data/host_features.csv
# 통합 vs 호스트별 모델 비교 → 호스트별 학습
python ml/per_key_eval.py data/host_features.csv --answer data/host_answer.csv
```
합성 시험: `python tools/gen_host_metrics.py` → `--matrix data/host_matrix.json.gz`.

## 주의

- `spool.jsonl`은 적재 파일이라 git에 올리지 않는다(`.gitignore`).
- collector는 LAN 내부에서만. 외부 노출 금지(인증 없음 — 랩 전용).
