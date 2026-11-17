# ml_detection — 룰이 놓친 이상행위를 ML로 탐지 (웹·DB 2계층)

> **방화벽·룰이 못 거르는 앱/DB 계층 이상행위(BOLA·SQLi·느린 공격)를, 비지도 ML(IF·LOF·Autoencoder)이 *발견*하고 지도 ML(RandomForest)이 *종류를 분류*하는 2계층 탐지.**
> 데이터센터 인텔리전트 보안 엔지니어 과정 프로젝트 · PHP/MySQL 쇼핑몰 API 시나리오 · scikit-learn only(딥러닝 라이브러리 불필요).

> 🔖 **이어서 작업하려면 [`HANDOFF.md`](HANDOFF.md)부터** — 현재 상태·다음 할 일·재현법.
> 📥 **다른 인프라 로그로 실험 = [`inbox/README.md`](inbox/README.md)** — 폴더에 파일 넣고 `python ml/ingest.py inbox/<이름> --retrain` 한 줄. 실시간 수집(Logstash·Filebeat·Fluent Bit)과 결정 근거는 `docs/29`.
> 📇 **모델 카드 = [`models/MODEL_CARD.md`](models/MODEL_CARD.md)** — `model_web_v3.1` 의 용도·한계·재현. 피처 확정 근거 `docs/27`.
> ⚠ **현재 단계 = PoC (운영 투입 전).** 실제 랩 로그에서 처음 보는 공격 탐지 약 90%, **처음 보는 정상 사용자 오탐 10~15%** (`docs/33`·`docs/35`·`docs/37`). 2026-10 의 "오탐 0" 수치는 정정됐다(아래 "정정 기록").

## 한 장 요약

- **문제:** WAF/룰은 "알려진 나쁜 문자열"만 막는다. 문법은 정상인데 패턴이 공격인 것(남의 주문 열람=BOLA, 느린 대입, 대량 수집)은 통과한다.
- **접근:** 로그를 `출발지 × 5분` 피처로 바꿔, 비지도 모델로 "평소와 다름"을 찾고(룰이 없어도), 지도 모델로 "무슨 공격인지" 이름을 붙인다.
- **확인된 것 (실제 랩 로그):**
  - 120초 빈도 룰이 놓치는 **느린 BOLA 를 LOF 가 잡는다** — 출발지 7곳 전부 (`docs/37`).
  - 느린 대입·수집·스캐닝도 룰 없이 잡는다. IsolationForest 는 느린 공격에 약하고 LOF·Autoencoder 가 보완한다.
- **아직 안 되는 것:**
  - 처음 보는 정상 사용자 오탐 10~15% — 운영 불가 수준.
  - BOLA 만 보면 `uniq_objects ≥ 5` 임계값 룰 한 줄이 같은 탐지에 오탐 0 이다. ML 이 꼭 필요하다는 근거는 BOLA 에는 없다 (`docs/37` §4).
  - 느린 수집(harvest_slow)은 어떤 모델로도 거의 못 잡는다.

## 아키텍처

```
[공격자/AI 에이전트]
     │ (방화벽/WAF 통과 — 문법 정상)
     ▼
[웹 티어] nginx+PHP ─▶ 웹 접근 로그 ─┐
[DB 티어] MySQL     ─▶ 쿼리 로그    ─┤
                                     ▼
                   features (출발지 × 5분)
                                     ▼
        ┌──────────── 비지도 (발견) ────────────┐   ┌─ 지도 (분류) ─┐
        │ IsolationForest · LOF · Autoencoder   │ + │ RandomForest  │
        └───────────────────────────────────────┘   └───────────────┘
                                     ▼
                     🚨 이상 + 공격 종류  (consumer/ · edge/ 로 자동화)
```

## 핵심 결과 (실제 랩 로그 `datasets/real_web/real_canon_*`, scikit-learn 1.9.1)

**웹 — 처음 보는 공격 종류 탐지 · 처음 보는 정상 출발지 오탐** (출발지 단위 분할, seed 0~4 합, `docs/35` §3-3 의 A):

| 모델 | 탐지 (공격 160구간) | 정상 오탐률 | 메모 |
|---|---|---|---|
| RandomForest (지도) | 62% | 5.4% | 학습에 없던 종류는 놓침, 불안정 |
| IsolationForest | 43% | 5.2% | 느린 공격에 약함 |
| LOF | 91% | 10.1% | 느린 BOLA·느린 대입까지 |
| Autoencoder | 87% | 9.0% | seed 에 따라 흔들림 |
| IF \| LOF \| AE | 92% | 15.0% | 탐지는 최고, 오탐도 최고 |

**BOLA — 룰과 비교** (`docs/37`, numpy 재현):

| 방법 | 빠른 BOLA | 느린 BOLA (출발지 7곳) | 정상 오탐 |
|---|---|---|---|
| 빈도 룰 (120초 안에 객체 10개) | 일부 탐지 | **전부 미탐** | 0 |
| 임계값 룰 (5분 `uniq_objects` ≥ 5) | 전부 탐지 | 205/210 구간 | 0/356 |
| LOF | 34/35 구간 | **210/210 구간** | 52/356 (14.6%) |

- 표본이 작다: 공격 32구간(9종), 종류당 2~6구간, 정상 출발지 14곳. 수치는 방향 확인용이다.
- 정상은 스크립트 생성기 트래픽이다. 실제 사람 정상으로 재는 것이 다음 단계다(`docs/36`).

### 정정 기록

| 이전 주장 | 정정 | 근거 |
|---|---|---|
| 합성 데이터에서 LOF·AE 탐지 1.00 · 오탐 0.00, "IF 가 놓친 느린 BOLA 4구간이 핵심 증거" | **철회.** 합성 데이터는 `err_ratio` 하나로 전부 갈리고, 그 '느린 BOLA'는 분당 6회였다 | `docs/33` §2 |
| 실제 랩 로그에서 "평가 정상 오탐 0/65" | 시각순 분할의 누수였다. 출발지 단위로 나누면 10~15% | `docs/33` §5-1 |
| IF\|LOF\|AE 0.97 | AE seed 하나의 값. seed 평균 0.91 | `docs/27` |

> 합성 데이터 결과(`run_demo`, `docs/13`)는 파이프라인이 끝까지 도는지 보는 용도로만 남긴다. 성능 근거가 아니다.

## 의사결정 흐름 (왜 그렇게 했나 — 숫자보다 중요)

1. 비지도 ML로 시작 (룰이 놓친 **처음 보는** 공격을 잡으려면) → `docs/09`
2. IF 단독은 **느린 공격을 놓침** 발견 → **LOF 추가**(국소 이상치) → `docs/12`
3. LOF도 완벽치 않아 **Autoencoder 추가**(재구성 오차) → `docs/16` §0, 모델 v2
4. RF는 "발견"이 아니라 **"종류 분류"** 역할로 (BOLA/SQLi/대량수집 이름 붙이기) → `docs/13` §6-2
5. 공개 데이터(CSIC)로 교차검증 → **내용 공격 ≠ 행위 공격** 발견, 둘을 구분 → `docs/16` §6
6. "완벽한 점수"를 의심 → 평가셋에 정상이 빠진 걸 발견하고 고침(정상을 평가셋에 남김) → `docs/17` #1
7. "오탐 0"을 의심 → 정상을 시각순이 아니라 **출발지 단위**로 나누니 오탐 12% → 합성 데이터의 지름길(`err_ratio`)도 발견, 이전 결론 철회 → `docs/33`
8. 정상이 생성기 출신이라는 한계 → 공개 클릭스트림(OTTO) 재생 정상을 더해 AE 오탐 9.0→5.7% → `docs/34`·`docs/35`
9. "ML 이 룰보다 나은가"를 직접 비교 → 느린 BOLA 는 빈도 룰이 놓치고 LOF 가 잡지만, 임계값 룰 한 줄이 오탐 0 으로 같은 일을 함 → `docs/37`

## 빠른 재현 (외부 데이터 없이, 명령 한 줄)

```bash
pip install -r requirements.txt
bash run_demo.sh          # (Windows PowerShell: ./run_demo.ps1)
```

**깨끗한 환경에서 검증 (Docker)** — 모델을 학습한 버전(Python 3.15.1 · scikit-learn 1.9.1, `requirements.txt` 고정)으로 이미지를 만들어 `verification/verify.sh` 를 돌린다:

```bash
docker build -t ml-detection .
docker run --rm ml-detection                                                      # 환경 검사 12항목 (2026-10-27 12/12 통과)
docker run --rm -v "$PWD/inbox:/app/inbox" ml-detection python ml/ingest.py inbox/<폴더> --retrain   # 내 로그 판정
```

`run_demo`는 합성 데이터를 만들어 → 피처 → IF·LOF·AE·RF 비교 → 채점까지 돌린다. 파이프라인 동작 확인용이며 위 "핵심 결과"(실제 랩 로그)를 재생성하지는 않는다.

**실제 랩 로그 결과 재현:**

```bash
bash docs/37_결과/run.sh                                                                  # BOLA: 빈도 룰 vs LOF vs 임계값 룰 (numpy 만 필요)
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD:/app" ml-detection bash /app/docs/33_결과/run.sh   # 출발지 분할 (sklearn)
```

## 자동 수집·판정

| 방식 | 디렉토리 | 설명 |
|---|---|---|
| 단순 소비자 | `consumer/` | 한 호스트가 원본 로그를 읽어 저장모델로 반복 판정 |
| **엣지 + DB** | `edge/` | 각 호스트가 **피처 벡터만** 중앙 collector로 전송(원본 로그 안 나감). MySQL 쿼리 로그 → BOLA·SQLi DB 피처 |

```bash
python consumer/consumer.py --nginx <로그> --model models/model.joblib --interval 60   # 단순
python edge/collector.py --model models/model.joblib --db-model models/db_model.joblib --port 8000
python edge/edge_agent.py --kind db --log <mysql log> --collector http://<중앙>:8000      # 엣지(DB 호스트)
```

## 정직한 한계

- **PoC 단계**: 실시간 경로(collector)는 아직 합성 데이터로 학습한 v2 모델을 쓴다. v3.1 은 오프라인 평가만 했다.
- **소규모 데이터**: 공격 32구간·정상 출발지 14곳. 수치는 "경향·틀 확인"이지 확정 성능이 아니다.
- **오탐 10~15%**: 처음 보는 정상 사용자 기준(출발지 분할). 평가 정상도 생성기 출신이라 실제 사람에서는 달라질 수 있다 → `docs/36`.
- **BOLA 에는 임계값 룰이 더 싸다**: `uniq_objects` 피처에 임계값을 걸면 같은 탐지에 오탐 0. ML 의 몫은 룰을 미리 안 쓴 종류(느린 대입·수집·스캐닝)다 → `docs/37`.
- **느린 수집은 못 잡는다**: 공개 자원을 합법 속도로 긁는 공격은 범위·속도 피처 어느 쪽에도 안 걸린다.
- **DB 출발지 귀속**: DB가 앱 서버만 볼 때의 해결(티어 단위 / 웹-DB 시간 상관)은 `edge/correlate.py`·`docs/14` §4.
- **CSIC 교차검증**: CSIC은 내용(페이로드) 공격이라 우리 행위 피처와 다른 종류 — `ml/load_csic.py`는 내용 피처로 변환.

## 문서 지도

| 범주 | 문서 |
|---|---|
| 개념 | `docs/02`(Isolation Forest), `docs/12`(지도 vs 비지도, LOF·AE 근거) |
| 계획 | `docs/07`(메인 컨셉), `docs/08`(환경 구축), `docs/10`(7~8주차 파이프라인) |
| **결과 (현재 기준)** | **`docs/33`(출발지 분할·지름길 진단 — 오탐 정정)**, **`docs/35`(OTTO 재생 정상 실험)**, **`docs/37`(BOLA: 빈도 룰 vs LOF vs 임계값 룰)**, `docs/34`(공개 클릭스트림 매핑), `docs/36`(실제 사람 정상 수집 계획) |
| 결과 (초기, 합성) | `docs/13`(종합 결과) — 웹·DB 2계층. 합성 데이터 수치는 `docs/33` 에서 철회 |
| 심화 | `docs/14`(실제 MySQL 재검증), `docs/15`(API 공격·피처 카탈로그), `docs/16`(레퍼런스) |
| **확정** | **`docs/27`(피처셋 v1 확정 + node_exporter 입구)**, **`docs/28`(랩 확장: DB VM·Prometheus·Wazuh 배치 런북)**, **`docs/29`(로그 수집·저장 결정과 비교)**, **`models/MODEL_CARD.md`(모델 카드)**, `docs/26`(탐지 아키텍처), **`docs/30`(저장 모델로 처음 보는 공격 탐지 — 필요한 것·주의)**, **`docs/31`(WAF 층 — ModSecurity·CRS, WAF가 잡는 것/못 잡는 것)**, **`docs/32`(피처 선택 원칙 — 공격별이 아니라 축별, 많을수록 좋지 않은 이유, 엣지는 DB 에만)** |
| 기록 | `docs/09`(설계 논의 히스토리), **`docs/17`(검증 함정·디버깅 로그)**, `models/README.md`(모델 체인지로그) |
| 그림 | **`docs/18`(토폴로지·다이어그램 — draw.io 밑그림)** |
| 공부 | `learn/`(내 데이터로 배우는 pandas·ML) |

## 코드 지도

| 경로 | 내용 |
|---|---|
| `ml/features.py` | 로그 → 출발지 × 구간 피처 (웹/alerts/archives) |
| `ml/models.py` | 룰·Z-score·IF·LOF·OCSVM·**Autoencoder** 비교 → P/R/F1 |
| `ml/supervised.py` | RF vs 비지도(IF·LOF·AE) leave-one-group-out 비교 (E1·E2) |
| `ml/classify_type.py` | RF 다중 분류 — 공격 **종류** 맞히기 |
| `ml/train_export.py` · `predict.py` | 학습 모델 저장(.joblib) · 저장 모델로 판정 |
| `ml/load_csic.py` | CSIC 2010 공개 데이터 → 내용 피처 (교차검증) |
| **`ml/ingest.py`** | **폴더 투입구** — 로그 종류 자동 인식 → 피처 → 판정/재학습 → `REPORT.md`(돌린 명령 포함) |
| `ml/feature_spec.py` · `ablation.py` | **확정 피처셋**(web_v1·db_v1·host_v1) 단일 출처 · drop-one 소거 실험(seed 평균) |
| `ml/relative_features.py` · `per_key_eval.py` | UEBA 상대 피처 · 통합 vs 키(호스트)별 기준선 모델 비교 |
| `edge/host_metrics.py` | **node_exporter 지표 → 호스트 피처** (Prometheus API / 저장 JSON / `/metrics` 스냅샷) |
| `edge/` | 엣지 피처 추출(웹·DB·호스트 지표) + 중앙 collector + 출발지 귀속(`correlate.py`) |
| `consumer/` | 단순 자동 소비자 |
| **`normalize/`** | **어떤 웹 요청 로그든 → 공통 요청 형식** (JSON·CSV·key=value·W3C 자동 인식, 안 맞으면 설정으로). `ml/features.py --requests`·`ingest.py` 가 받음 |
| `waf_gateway/` | **WAF + API Gateway 로그 → 사용자 키 표 + IP 키 표** (인증 후 공격은 사용자, 인증 전 공격은 IP) |
| `tools/` | 트래픽 생성기 (정상·공격·DB·호스트 지표 합성) |
| `models/` | 학습된 모델 + `archive/`(이전 버전) + 체인지로그 |
| `detector/wazuh_ml_detect.py` | 초기 단일 파일 탐지기 (alerts.json → IF) |

## 주의

- 공격 재현은 **직접 통제하는 랩에서만**. Juice Shop·shopapi 등은 의도적 취약 앱 → 외부 노출 금지.
- 자동 차단은 오탐 시 정상 IP를 끊을 수 있음 — 랩에서만.

## 관련

- [zeldaim/finance_secure](https://github.com/zeldaim/finance_secure) — 금융권 보안사고 분석·제안서 (원 프로젝트)
