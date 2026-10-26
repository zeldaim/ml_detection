# inbox/ — 다른 인프라의 로그를 넣는 곳

> **폴더 하나 만들고 → 파일 넣고 → 명령 한 줄.** 파일 이름은 상관없다(내용을 보고 종류를 알아본다).
> 이 폴더의 내용물은 git 에 안 올라간다(이 README 만). 실제 로그엔 IP·경로 등 민감정보가 있다.
> 파일을 손으로 넣는 대신 **VM·원격 Wazuh 에서 자동으로 받으려면** `docs/29` — Logstash 가 `inbox/live/<출처>/<로그종류>/` 에 쌓아 주고, 그 폴더에 똑같이 `ingest.py` 를 돌린다.

## 1. 3단계

```bash
# ① 실험 폴더 만들기 (이름 자유)
mkdir inbox/company_a

# ② 받은 파일을 그냥 넣기  (.gz 그대로 OK, 하위 폴더 OK)
#    access.log, access.log.1.gz, archives.json, mysql-general.log, prometheus 덤프, 정답지 …

# ③ 실행
python ml/ingest.py inbox/company_a              # 우리 모델로 판정만
python ml/ingest.py inbox/company_a --retrain    # 그 인프라의 '평소'로 다시 학습 후 판정 (보통 이쪽)
```
결과: `inbox/company_a/out/REPORT.md` — 무엇을 알아봤고, **어떤 명령을 어떤 순서로 돌렸고**, 무엇이 이상으로 나왔는지.

## 2. 안에서 무슨 일이 일어나나 (흐름)

```
inbox/company_a/
 ├ access.log.gz ──┐
 ├ archives.json ──┤ ① 내용으로 종류 판별 (ml/ingest.py 의 sniff)
 ├ general.log ────┤
 ├ prom.json.gz ───┤
 └ answer_web.csv ─┘   (정답지 — 있으면 채점)
          │
          ▼ ② 피처 추출: 로그 → "출발지 × 5분" 숫자 표
   웹   ml/features.py  → ml/relative_features.py (평소 대비 배수)   → out/features_web_rel.csv
   DB   edge/db_features.py                                        → out/features_db.csv
   호스트 edge/host_metrics.py  (호스트별로 쪼갬)                    → out/features_host.csv, host_by_host/
          │
          ▼ ③ 모델
   판정 모드   : models/ 의 저장 모델(웹 v3.1, DB v2)로 ml/predict.py
   --retrain   : ml/train_export.py 로 이 데이터의 정상에서 새로 학습 → ml/predict.py
                 (정답지가 있으면 정상 앞 70% 로 학습, 나머지 = 처음 보는 데이터로 채점)
          │
          ▼ ④ out/REPORT.md  (+ pred_*.csv 구간별 판정, model_*.joblib 새 모델, logs/ 단계별 출력)
```
`ingest.py` 는 새 로직이 아니라 **기존 스크립트를 순서대로 부르는 지휘자**다. 보고서의 "돌린 명령"을 복사하면 손으로 똑같이 재현된다.

## 3. 알아보는 파일

| 넣는 것 | 알아보는 기준 | 계층 |
|---|---|---|
| nginx 액세스 로그 (combined) | `IP - 사용자 [시각] "메서드 경로` 형태 | 웹 |
| Wazuh `archives.json` | JSON 줄에 `full_log` | 웹 (nginx 와 같이 있으면 nginx 만 씀 — 이중 집계 방지) |
| MySQL general log | `시각 연결id Query/Connect…` | DB |
| Prometheus `query_range` 응답 JSON | `"resultType"` | 호스트 |
| node_exporter 스냅샷 폴더 | `<폴더>/<호스트>/<epoch>.prom` | 호스트 |
| **이미 뽑은 피처 CSV** | 헤더 `ip,window_start,…` + 피처셋 열 | 웹/DB/호스트 (예: DB 서버에서 `db_features.py` 로 만든 CSV 만 받은 경우) |
| 정답지 CSV | 헤더 `attack_id,src,start,end,type` 또는 `ip,label,type` | 채점용 |
| **그 밖의 웹 요청 로그** (Gateway JSON·FortiWeb syslog·CSV 내보내기·IIS 등) | 위 형식이 아니면 **공통 요청 형식으로 읽히는지 시험** (`normalize/README.md`). 필드 이름이 다르면 `meta.json` 의 `fields` | 웹 (nginx/archives 가 같이 있으면 안 씀 — 이중 집계 방지) |

- 정답지가 계층마다 다르면 이름에 `web`/`db`/`host` 를 넣는다(`answer_web.csv`, `answer_db.csv`). 하나뿐이면 아무 이름이나.
- Wazuh `alerts.json` 은 안 쓴다(룰에 걸린 것만 — 학습은 전체인 archives, `docs/08` §2-4).
- 못 알아본 파일은 보고서에 "⚠ 안 씀: 이유" 로 남는다.

## 4. 설정 (선택) — `inbox/company_a/meta.json`

```json
{
  "owned_paths": ["/api/orders/{id}", "/api/addresses/{id}"],
  "window": 5,
  "contamination": 0.05
}
```
- **`owned_paths` 는 다른 앱이면 거의 필수.** BOLA 신호(`uniq_objects`)는 "주인만 봐야 하는 자원" 경로만 센다. 기본값은 Juice Shop 경로라서 다른 앱에선 0 이 된다.
- `window` 분 단위 구간, `contamination` 정상 중 이상으로 볼 비율(경계).
- 공통 요청 형식으로 읽는 로그용(선택): `"fields": {"user": "consumer.username"}`(필드 위치), `"tz": "+09:00"`(시간대 없는 시각), `"trusted_proxies": ["10.16.1.2"]`(XFF 복원) — `normalize/README.md` §3.

## 5. 어느 모드를 쓰나

| 상황 | 명령 | 의미 |
|---|---|---|
| "우리 모델이 거기서도 통하나?" | `ingest.py <폴더>` | 우리 랩의 '평소' 기준. 다른 인프라면 **오탐이 많은 게 정상**(평소가 다름) |
| 정답지 있음 (통제 공격을 했다) | `ingest.py <폴더> --retrain` | 그 인프라 정상 앞 70% 학습 → 나머지 + 공격으로 채점 = 제대로 된 성능 |
| 정답지 없음, 언제부터 이상한지 모름 | `ingest.py <폴더> --retrain --baseline-until 2026-11-01T00:00:00Z` | 그 시각 전을 평소로 학습 → 이후를 판정 = **조사 후보 목록** |
| 정답지도 기준 시각도 없음 | `ingest.py <폴더> --retrain` | 전체를 평소로 가정 → 가장 튀는 ~5% 표시 (참고용) |

> 실제 예(저장소 데이터로 재현): 합성으로 학습한 DB 모델을 DB 아크 데이터에 그대로 쓰면 **정상 오탐 69/72**,
> `--retrain` 하면 **10/22**. 같은 앱이라도 '평소'가 다르면 다시 학습해야 한다는 게 이 입구의 존재 이유.

## 6. 체험 (저장소 데이터로)

```bash
mkdir -p inbox/demo
cp datasets/real_web/real_canon_access.log.gz inbox/demo/
cp datasets/real_web/real_canon_answer.csv    inbox/demo/answer_web.csv
cp datasets/real_db/db_arc_general.log.gz      inbox/demo/
cp datasets/real_db/db_arc_answer.csv          inbox/demo/answer_db.csv
python tools/gen_host_metrics.py --out inbox/demo/host.json.gz --answer inbox/demo/answer_host.csv
python ml/ingest.py inbox/demo --retrain
# → 웹 탐지 29/32·오탐 0/65 · DB 24/24·10/22 · 호스트 25/25·12/81 (호스트는 합성)
```

## 7. 주의
- 받은 로그는 **민감정보**다. 이 폴더 밖(특히 git·메신저)으로 옮기지 않는다. 다 쓰면 원본은 지운다.
- 시각은 로그 원문 시각을 그대로 쓴다. 정답지 시각은 **UTC** 로(`Z`). 서버 시계가 틀리면 채점이 어긋난다.
- Windows Git Bash 에서 `--owned-path` 를 명령줄로 줄 땐 `MSYS_NO_PATHCONV=1` 필요 — `meta.json` 으로 주면 상관없음.
