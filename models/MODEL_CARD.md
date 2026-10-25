# Model Card — 웹 API 행위 이상탐지 `model_web_v3.1`

> 형식: Mitchell et al., *Model Cards for Model Reporting* (FAT* 2019)을 보안 탐지 모델에 맞게 줄였다.
> 이 카드의 모든 수치는 저장소만으로 재현된다(§9). 근거 문서: `docs/27`(피처 확정), `docs/21`(실험), `docs/26`(탐지 아키텍처).

## 1. 모델 개요

| 항목 | 내용 |
|---|---|
| 파일 | `models/model_web_v3.1.joblib` (4.2 MB, joblib 번들) |
| 버전 / 날짜 | v3.1 · 2026-10-25 (v3 결함 수정판, §8) |
| 과제 | 웹 API 접근 로그의 **출발지 × 5분 구간**이 평소와 다른지 판정(이상탐지) + 공격 종류 이름 붙이기(분류) |
| 구성 | 비지도 **LOF**(주) · **Autoencoder**(MLP, 보완) · IsolationForest(보조) + 지도 **RandomForest**(종류 분류) + StandardScaler |
| 입력 | 피처셋 **`web_v1`** 10개 (`ml/feature_spec.py`) — 번들의 `feature_set`·`features` 순서와 같아야 함 |
| 하이퍼파라미터 | contamination 0.05 · LOF k=20, novelty · AE 은닉 5(=10//2), relu, 경계=정상 재구성오차 95분위(0.3173) · IF/RF 300 트리 |
| 학습 데이터 | 실제 랩 정본 `datasets/real_web/real_canon_*` 의 **정상 214구간**(비지도) / 정상+공격 9종 246구간(RF) |
| 런타임 | Python 3.12–3.15 · scikit-learn 1.9.1 (번들에 버전 기록, 다른 버전 로드 시 경고 가능) |
| 소유 | 데이터센터 인텔리전트 보안 엔지니어 과정 프로젝트 ML 파트 |

## 2. 의도한 사용

- **용도:** WAF·레이트 룰을 통과한 **느린·처음 보는·다변량** API 남용(BOLA 열거, 저속 대입, 수집)을 *발견*해 **분석가 티켓**을 만든다.
  `docs/26` 층 구조에서 "행위/준실시간" 층. 아는 공격의 실시간 차단은 룰의 몫.
- **사용자:** SOC 분석가(티켓 검토), SOAR 워크플로(조회·태깅 자동화).
- **범위 밖 (쓰지 말 것):**
  - **자동 차단 단독 근거** — 오탐이 정상 사용자를 끊는다(§6, `docs/26` §5).
  - 페이로드 공격(SQLi·XSS 문자열) — 행위 피처라 내용을 안 본다. CSIC 교차검증에서 내용 피처가 따로 필요했다(`docs/16` §6).
  - 자원/가용성 공격(채굴·DoS) — 호스트 지표 입구(`edge/host_metrics.py`) 몫.
  - Juice Shop 이외 앱에 그대로 이식 — `uniq_objects` 의 소유 자원 경로(`OWNED_PREFIXES`)를 앱마다 지정해야 함.

## 3. 입력 피처 (`web_v1`)

| 피처 | 겨냥 | 소거 시 앙상블 (기준 0.91) |
|---|---|---|
| `uniq_objects` | BOLA (소유 자원 ID 열거) | **0.78** |
| `max_req_1min` | 고속 대입·열거 | **0.82** |
| `rel_req_count`·`rel_max_req_1min` | 자기 평소 대비 급변(탈취형, UEBA) | LOF 0.88→**0.81** |
| `interval_cv`·`endpoint_entropy` | 봇 규칙성 · 내용 다양성 | LOF 0.88→**0.81** (`interval_cv` 단독 0.84) |
| `req_count`·`uniq_paths`·`err_ratio` | 수집·스캐닝·대입 | 중립(노이즈 내) |
| `write_ratio` | BFLA·대량 쓰기 | 측정 불가(정본에 해당 공격 없음) |

- **식별자·원문(IP·UA·경로·쿼리)은 피처가 아니다.** IP 는 묶음 키로만 쓴다(누수·개인정보, `docs/25`).
- `rel_*` 는 `ml/relative_features.py --mode self`(각 출발지의 앞 40% 구간 중앙값 대비 배수)로 만든다. **추론 때도 같은 방식으로 계산해야 한다**(§7).

## 4. 성능 (실제 랩 로그, 처음 보는 데이터)

**프로토콜:** 정상 구간을 시간순으로 나눠 앞 70%(149)로 학습, 뒤 30%(65) + 공격 32구간(9종, 공격 전용 IP)으로 평가.
비지도 모델은 공격을 학습에 쓰지 않으므로 모든 공격이 "처음 보는 공격"이다. AE·IF 는 seed 10개 평균.

| 경보 등급 (규칙) | 탐지율 | 정상 오탐 (65구간) | 용도 |
|---|---|---|---|
| **IF\|LOF\|AE** (하나라도) | **0.91 ± 0.04** | 0 / 65 | 분석가 티켓 |
| **LOF** 단독 | 0.88 | 0 / 65 | 단일 모델이 필요할 때 기본값 (결정적, seed 무관) |
| **LOF & AE** (둘 다) | 0.88 | 0 / 65 | **고신뢰** — 조회·태깅 자동화 후보 |
| IF & LOF & AE | 0.32 | 0 / 65 | 너무 보수적, 비권장 |

**공격 종류별 (IF|LOF|AE, seed 평균):**

| 종류 | 구간 | 앙상블 | LOF | IF | 메모 |
|---|---|---|---|---|---|
| bola_slow | 6 | **6.0** | 6.0 | **0.0** | **H5 — IF 가 놓친 느린 공격을 LOF 가 잡음** |
| brute_slow | 5 | 5.0 | 5.0 | 0.0 | H5 |
| bola | 5 | 5.0 | 5.0 | 1.0 | |
| brute_fast | 5 | 4.0 | 4.0 | 4.0 | 놓친 1구간 = 공격 꼬리(요청 적음) |
| scanning · user_enum · bola_fast · harvest | 2 각 | 2.0 | 2.0 | 0~2 | |
| **harvest_slow** | 3 | **1.1** | **0.0** | 0.0 | **알려진 약점** — 빠른 합법 클라이언트와 속도가 같고 한 경로만 봄 |

- **오탐 해석 주의:** 평가 정상 0/65 는 "오탐 0"이 아니라 **95% 신뢰 상한 ≈ 4.6%**(3/n 규칙)다.
  또 경계는 정상 학습분의 95분위로 정했으므로 **설계상 모델당 ~5%**, 합집합은 더 높을 수 있다 — v3.1 을 학습 데이터 자체에 돌리면 합집합 20/214(9%).
  운영 초기엔 **티켓 = 합집합, 자동화 = LOF&AE** 로 나누고, 실제 경보량을 보고 contamination 을 재조정한다.
- **H5(핵심 발견):** IF 는 학습 범위 밖으로 외삽을 못 해 느린 공격을 놓치고(IF 단독 0.32), 밀도 기반 LOF·재구성 기반 AE 가 보완한다.
  합성(`docs/21` §A·B) → 실제(§F·G·L) → 이 카드까지 같은 방향으로 재현.

## 5. 학습·평가 데이터

- **출처:** 랩 Rocky VM 의 OWASP Juice Shop + nginx 액세스 로그(28,249 요청), 2026-10-23~25 수집. Kali 에서 통제 공격, 정상은 12개 IP 의 스크립트 사용자 + 빠른 합법 클라이언트(하드네거티브).
- **라벨:** 공격 러너가 기록한 **출발지(전용 IP)** 기준 사실 라벨. 추측·LLM 라벨 없음(`docs/21` §4).
- **크기의 한계:** 공격 종류당 2~6구간. 통제 공격 하나에 실시간이 드는 본질적 제약이라 지표가 1구간에 크게 흔들린다(`docs/21` "표본이 적은 이유").
- **누수 점검:** 공격 IP 를 무작위 정상 IP 로 바꾼 퍼뮤테이션에서 재현율이 진짜 라벨보다 낮음(`verification/verify.sh` [3]).

## 6. 윤리·운영 고려

- **오탐 비용이 비대칭이다.** 차단은 정상 사용자의 서비스를 끊는다 → 이 모델은 **사람 확인 게이트** 뒤에 둔다. 자동 동작은 조회·태깅까지(`docs/26` §5).
- **출발지 = IP 의 한계:** NAT·프록시 뒤 다수 사용자는 한 키로 섞인다. 실측에서 사용자 키(세션/JWT sub)로 바꾸면 IP 키가 놓친 공격자 3/3 탐지(`docs/25` §5-2). 완전 분산 low-and-slow 는 근본 갭.
- **개인정보:** 원문 경로·쿼리·UA 는 피처로 남기지 않는다. 엣지 배치 시 숫자 벡터만 전송(`edge/`).
- **악용 가능성:** 피처 목록이 공개돼 있어 공격자가 피처 경계 아래로 맞출 수 있다(예: harvest_slow 처럼 합법 속도·한 경로). 다층(룰·DB 계층·호스트 지표)으로 보완.

## 7. 한계와 권장

| 한계 | 영향 | 권장 |
|---|---|---|
| 단일 랩·단일 앱·3일치 정상 | 다른 환경·요일 패턴 미반영 | 운영 전 **최소 1주 정상**으로 재학습, 이 카드의 프로토콜로 재평가 |
| `rel_*` 은 "출발지의 평소"가 필요 | 처음 보는 IP 는 기준선 없음(배수 ≈1) | 신규 출발지는 `--mode peer` 또는 `expanding` |
| collector 는 v2(9피처) | v3.1 은 아직 실시간 경로에 없음 | `rel_*` 온라인 계산 추가 후 승격 (`docs/27` §7) |
| AE 결과가 seed 에 ±0.04 흔들림 | 단일 실행 수치 과신 위험 | AE 수치는 seed 평균으로만 보고 |
| harvest_slow 0/3 (LOF) | 합법 속도의 단일 경로 수집 | 앱 계측(`owned_vs_self_ratio`)·allowlist — `docs/15` §3 |
| RF 는 학습한 종류만 이름 붙임 | 처음 보는 종류는 'normal' 또는 엉뚱한 이름 | 발견은 비지도, RF 는 라벨링 보조로만 |

## 8. 버전 이력 (요약 — 상세 `models/README.md`)

| 버전 | 변경 | 비고 |
|---|---|---|
| **v3.1** (현재) | `web_v1` 10피처(ssh_fail 제외) · **정상 214구간만으로 학습** | 결함 수정 |
| v3 (보관) | 정본 + rel 11피처 | **결함:** `train_export.py` 가 IP형 정답지를 무시해 **공격 32구간을 정상으로 학습**(n_normal 246). 같은 데이터에서 LOF 8/32 → v3.1 28/32. `archive/model_web_v3_canon_rel_trained-with-attacks.joblib` |
| v2 | 합성 데이터 9피처 + AE 추가 | `models/model.joblib` — 현재 collector 기본 |
| v1 | IF + LOF + RF | `archive/` |

## 9. 재현

```bash
pip install -r requirements.txt
zcat datasets/real_web/real_canon_access.log.gz > /tmp/c.log
python ml/features.py --nginx /tmp/c.log --out /tmp/c.csv
python ml/relative_features.py /tmp/c.csv --mode self --cols req_count max_req_1min --out /tmp/c_rel.csv
python ml/train_export.py /tmp/c_rel.csv --answer datasets/real_web/real_canon_answer.csv \
       --feature-set web_v1 --contamination 0.05 --out models/model_web_v3.1.joblib        # 모델
python ml/ablation.py /tmp/c_rel.csv --answer datasets/real_web/real_canon_answer.csv --feature-set web_v1 \
       --groups "rel_req_count rel_max_req_1min" "interval_cv endpoint_entropy"   # §3 소거 · §4 경보 등급·종류별 표 (약 1분)
python ml/predict.py models/model_web_v3.1.joblib /tmp/c_rel.csv                              # 판정
bash verification/verify.sh                                                                   # 전체 검증
```

---

## 부록 — 같은 틀의 다른 모델 (운영급 아님)

| 모델 | 피처셋 | 데이터 | 상태 |
|---|---|---|---|
| `models/db_model.joblib` (v2) | `db_v1` 8 | 합성 MySQL general log | 앙상블 탐지 1.00 이지만 **오탐 0.31**(합성 DB 아크). 실제 MySQL 재검증 전 운영 금지 (`docs/22`, `docs/27` §5) |
| 호스트 지표 (모델 파일 없음) | `host_v1` 12 | 합성 node_exporter | 입구·평가 도구만 확정. **호스트별 LOF** 권장(합성: 25/25 vs 통합 13/25, 오탐 둘 다 4/81). 실측 후 학습 (`docs/27` §3) |
