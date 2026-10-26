# ml_detection — 룰이 놓친 이상행위를 ML로 탐지 (웹·DB 2계층)

> **방화벽·룰이 못 거르는 앱/DB 계층 이상행위(BOLA·SQLi·느린 공격)를, 비지도 ML(IF·LOF·Autoencoder)이 *발견*하고 지도 ML(RandomForest)이 *종류를 분류*하는 2계층 탐지.**
> 데이터센터 인텔리전트 보안 엔지니어 과정 프로젝트 · PHP/MySQL 쇼핑몰 API 시나리오 · scikit-learn only(딥러닝 라이브러리 불필요).

> 🔖 **이어서 작업하려면 [`HANDOFF.md`](HANDOFF.md)부터** — 현재 상태·다음 할 일·재현법.
> 📥 **다른 인프라 로그로 실험 = [`inbox/README.md`](inbox/README.md)** — 폴더에 파일 넣고 `python ml/ingest.py inbox/<이름> --retrain` 한 줄. 실시간 수집(Logstash·Filebeat·Fluent Bit)과 결정 근거는 `docs/29`.
> 📇 **운영 후보 모델 = [`models/MODEL_CARD.md`](models/MODEL_CARD.md)** — 실제 랩 로그 기준 IF|LOF|AE 0.91±0.04 · 평가 정상 오탐 0/65, 용도·한계·재현까지. 피처 확정 근거 `docs/27`.

## 한 장 요약

- **문제:** WAF/룰은 "알려진 나쁜 문자열"만 막는다. 문법은 정상인데 패턴이 공격인 것(남의 주문 열람=BOLA, 느린 대입, 대량 수집)은 통과한다.
- **접근:** 로그를 `출발지 × 5분` 피처로 바꿔, 비지도 모델로 "평소와 다름"을 찾고(룰이 없어도), 지도 모델로 "무슨 공격인지" 이름을 붙인다.
- **핵심 발견:** **느린 공격은 IsolationForest가 놓치고, LOF·Autoencoder가 잡는다.** → 한 모델이 아니라 **여러 모델을 함께** 써야 한다. (이 결론은 학계·실무와도 일치 — `docs/16`)

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

## 핵심 결과 (랩 합성 데이터, scikit-learn 1.9.1)

**웹 — 처음 보는 공격 탐지율 (E2, 종류를 빼고 학습):**

| 모델 | 탐지율 | 정상 오탐률 | 메모 |
|---|---|---|---|
| RandomForest (지도) | 0.29 | 0.00 | 학습에 없던 종류는 놓침 |
| IsolationForest | 0.43 | 0.00 | **느린 BOLA 놓침** |
| LOF | 1.00 | 0.00 | 국소 이상치까지 |
| **Autoencoder** | **1.00** | **0.00** | IF 외삽 한계 보완 |
| IF \| LOF \| AE | 1.00 | 0.00 | 함께 쓰면 완전 |

> **IF가 놓치고 LOF·AE가 잡은 느린 BOLA 구간 4개** = 이 프로젝트의 핵심 증거.
> DB 계층(SQLi·BOLA·대량수집)에서도 같은 경향 재현 (`docs/13` §4).

## 의사결정 흐름 (왜 그렇게 했나 — 숫자보다 중요)

1. 비지도 ML로 시작 (룰이 놓친 **처음 보는** 공격을 잡으려면) → `docs/09`
2. IF 단독은 **느린 공격을 놓침** 발견 → **LOF 추가**(국소 이상치) → `docs/12`
3. LOF도 완벽치 않아 **Autoencoder 추가**(재구성 오차) → `docs/16` §0, 모델 v2
4. RF는 "발견"이 아니라 **"종류 분류"** 역할로 (BOLA/SQLi/대량수집 이름 붙이기) → `docs/13` §6-2
5. 공개 데이터(CSIC)로 교차검증 → **내용 공격 ≠ 행위 공격** 발견, 둘을 구분 → `docs/16` §6
6. "완벽한 점수"를 의심 → 평가셋에 정상이 빠진 걸 발견하고 고침(정상을 평가셋에 남김) → `docs/17` #1

## 빠른 재현 (외부 데이터 없이, 명령 한 줄)

```bash
pip install -r requirements.txt
bash run_demo.sh          # (Windows PowerShell: ./run_demo.ps1)
```

`run_demo`는 합성 데이터를 만들어 → 피처 → IF·LOF·AE·RF 비교 → 채점까지 돌리고, 위 "핵심 결과"를 재생성한다. (실제 랩 로그·CSIC은 `docs/08`·`docs/14`·`docs/16` 참고.)

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

- **합성·소규모 데이터**: 수치는 "경향·틀 확인"이지 확정 성능이 아니다. 실제 로그 재검증은 `docs/14`.
- **오탐은 늘 함께 본다**: 정상만으로도 IF·LOF는 5~12% 경보 → 결과엔 탐지율과 오탐률을 같이.
- **DB 출발지 귀속**: DB가 앱 서버만 볼 때의 해결(티어 단위 / 웹-DB 시간 상관)은 `edge/correlate.py`·`docs/14` §4.
- **CSIC 교차검증**: CSIC은 내용(페이로드) 공격이라 우리 행위 피처와 다른 종류 — `ml/load_csic.py`는 내용 피처로 변환.

## 문서 지도

| 범주 | 문서 |
|---|---|
| 개념 | `docs/02`(Isolation Forest), `docs/12`(지도 vs 비지도, LOF·AE 근거) |
| 계획 | `docs/07`(메인 컨셉), `docs/08`(환경 구축), `docs/10`(7~8주차 파이프라인) |
| **결과** | **`docs/13`(종합 결과)** — 웹·DB 2계층, 2층 구조 결론 |
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
| `waf_gateway/` | **WAF + API Gateway 로그 → 사용자 키 표 + IP 키 표** (인증 후 공격은 사용자, 인증 전 공격은 IP) |
| `tools/` | 트래픽 생성기 (정상·공격·DB·호스트 지표 합성) |
| `models/` | 학습된 모델 + `archive/`(이전 버전) + 체인지로그 |
| `detector/wazuh_ml_detect.py` | 초기 단일 파일 탐지기 (alerts.json → IF) |

## 주의

- 공격 재현은 **직접 통제하는 랩에서만**. Juice Shop·shopapi 등은 의도적 취약 앱 → 외부 노출 금지.
- 자동 차단은 오탐 시 정상 IP를 끊을 수 있음 — 랩에서만.

## 관련

- [zeldaim/finance_secure](https://github.com/zeldaim/finance_secure) — 금융권 보안사고 분석·제안서 (원 프로젝트)
