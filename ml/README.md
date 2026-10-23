# ml/ — 행위 층 이상탐지 (피처 → 모델 비교 → 채점)

> 계획: `docs/10` §3 · 메인 컨셉: `docs/07` §5 행위 층 · 입력 로그: `docs/08` 환경의 alerts.json / archives.json, **또는 Wazuh 없이 nginx access.log 직접**
> 의존성: scikit-learn (numpy 포함). pandas 불필요.

```
alerts / archives / access.log ─▶ features.py ─▶ 피처 CSV ─▶ models.py ─▶ detections CSV ─┬─▶ evaluate.py ─▶ P/R/F1
                                (IP × 5분)          (rule·zscore·iforest·lof·ocsvm)        │   (정답지)
                                                                                           └─▶ explain_llm.py ─▶ 추천·설명
                                                                                               (상위 후보, 숫자 요약만)
```

| 파일 | 역할 |
|---|---|
| `features.py` | 로그 → IP × 구간 피처 표. alerts는 룰 알럿 피처, archives·nginx는 웹 요청 피처. `.gz`도 읽음 |
| `models.py` | 같은 피처 표로 **룰 비교군**(레이트리밋 / Wazuh 레벨 10+) · Z-score(robust) · Isolation Forest · LOF · One-Class SVM 실행, 점수는 모두 "클수록 이상" |
| `evaluate.py` | 정답지로 구간 단위·IP 단위 TP/FP/FN/TN, Precision/Recall/F1, 공격별 탐지 여부 |
| `supervised.py` | **지도(Random Forest) vs 비지도(Isolation Forest)** 비교 — 공격 사건·종류를 하나씩 빼고 학습해 "아는 공격 / 처음 보는 공격" 탐지율과 정상 오탐률 비교 (`docs/12`) |
| `explain_llm.py` | 한 방법의 이상 점수 상위 N개 구간을 **숫자 요약**(피처 값 + 평소 중앙값 + 다른 방법 일치 여부)으로 LLM에 보내 block_30m / observe / ignore 추천과 이유를 받음 |

## 실행 (저장소 루트에서)

```bash
# 샘플: 정상 14 IP + 빠른 브루트포스 + 느린 공격 (tools/make_sample.py가 만든 알럿)
python ml/features.py --alerts samples/sample_alerts_if.json --out data/features_alerts.csv
python ml/models.py data/features_alerts.csv --out data/detections.csv
python ml/evaluate.py data/detections.csv --answer samples/sample_answer_if.csv

# 랩 로그 (docs/08): 정상 수집 기간 끝 시각을 --train-until로
python ml/features.py --archives archives.json --out data/features_archives.csv
python ml/models.py data/features_archives.csv --train-until 2026-11-03T09:00:00Z --out data/det_archives.csv
python ml/evaluate.py data/det_archives.csv --answer data/answer.csv

# LLM 설명 (anthropic 설치 + 자격증명이 있으면 API 호출·요금 발생, 없으면 프롬프트 출력)
python ml/explain_llm.py data/detections.csv data/features_alerts.csv --method lof --top 5 --answer samples/sample_answer_if.csv
python ml/explain_llm.py data/detections.csv data/features_alerts.csv --dry-run   # 프롬프트만

# Wazuh 없이: 웹서버의 nginx 로그를 직접 (로테이션된 .gz 포함, 오래된 것부터)
python ml/features.py --nginx access.log.2.gz --nginx access.log.1 --nginx access.log --out data/features_web.csv
python ml/models.py data/features_web.csv --train-until 2026-11-03T09:00:00Z --out data/det_web.csv
python ml/evaluate.py data/det_web.csv --answer data/answer.csv

# 09 Q12 비교: 같은 기간을 --alerts만으로도 만들어 같은 모델·같은 정답지로
python ml/features.py --alerts alerts.json --out data/features_alerts.csv
```

Windows에서 글자가 깨지면 `$env:PYTHONUTF8=1`(PowerShell) 후 실행. 출력은 `data/`(Git 제외).

## 피처

| 입력 | 피처 | 정의 |
|---|---|---|
| alerts | `alert_count` · `rule_level_max` · `uniq_rules` | 알럿 수 · 최고 룰 레벨 · 서로 다른 룰 수 |
| | `auth_fail` · `uniq_users` | 인증 실패 그룹 알럿 수 · 서로 다른 계정 수 |
| 웹 (archives / nginx) | `req_count` · `uniq_paths` | 요청 수 · 서로 다른 (메서드, 경로 템플릿) 수 |
| | `max_req_1min` | 구간 안 1분 단위 최대 요청 수 — 룰(레이트리밋) 비교군이 쓰는 값 |
| | `uniq_objects` | **소유 자원** 경로(장바구니·장바구니 항목·회원·카드·주소)의 서로 다른 객체 ID 수 — BOLA 징후. 상품 같은 공개 자원은 세지 않는다 (정상 쇼핑객이 상품을 많이 보면 공격자와 구분이 안 되므로). 대상 경로는 `--owned-path`로 교체 |
| | `err_ratio` · `write_ratio` | 4xx·5xx 비율 · POST/PUT/PATCH/DELETE 비율 |
| | `interval_cv` | 요청 간격 표준편차 ÷ 평균 (0에 가까울수록 기계적). 간격 2개 미만이면 1.0(중립) |
| | `endpoint_entropy` | 경로 템플릿 분포 엔트로피 (`detector`의 `shannon` 재사용) |
| archives (sshd) | `ssh_fail` | `Failed password` / `Invalid user` 줄 수 |

- 경로 템플릿: `/rest/basket/3` → `/rest/basket/{id}` (숫자 경로 조각을 `{id}`로)
- nginx 줄의 시각은 **로그 원문 시각**을 쓴다 (Wazuh 수집 시각 아님)
- 분석 주체는 출발지 IP (`docs/10` §2-2 "왜 nginx 로그엔 계정이 없나")

## 룰 비교군 (`--methods rule`)

ML과 같은 채점표에 넣는 "기존 방어" 기준선 (`docs/07` §6 ①). Wazuh가 없어도 룰 vs ML 비교가 유지된다.

| 입력 | 룰 | 임계값 |
|---|---|---|
| 웹 (archives / nginx) | 레이트리밋: 구간 안 어느 1분이라도 요청 N회 이상 | `--rule-rpm`. 없으면 **정상 기간 1분 최대 × 1.5** (운영자가 평소 최대치에 여유를 두고 정하는 방식) |
| alerts | Wazuh 룰 레벨 10 이상 (`docs/03` §3-1) | `--rule-level` |

## ⚠️ 정상만 있어도 ML은 일정 비율을 "이상"으로 표시한다

정상 브라우징만 담은 테스트 로그(8 IP, 3시간)로 확인한 결과 (2026-10-23):

| 방법 | 학습 구간(정상) | 평가 구간(정상) |
|---|---|---|
| rule (1분 11회) | 0 | 0 |
| iforest (contamination 0.1) | 19 / 191 (10%) | 17 / 96 (18%) |

- `contamination=0.1`은 "학습 데이터의 10%를 이상으로 보라"는 **임계값 설정**이다 → 공격이 없어도 그만큼 경보가 난다
- 그래서 **정상 기간만으로 오탐률을 먼저 재고**, 실험 결과에는 "공격 구간 탐지율"과 함께 "정상 구간 오탐률"을 반드시 같이 쓴다
- 운영에 가까이 가려면 contamination을 낮추거나(예: 0.01), 여러 방법이 함께 이상으로 본 구간만 경보로 삼는다(`explain_llm.py`가 보여주는 "이상으로 본 방법")

## 정답지 형식

- 시간 구간형 (`docs/05` §5-2, `docs/08` §4): `attack_id,src,start,end,type` — 겹치는 구간만 양성
- IP형 (`labs/01`과 같음): `ip,label,type` — 그 IP의 모든 구간이 양성 (`samples/sample_answer_if.csv`)

## 샘플 실행 결과 (2026-10-23, scikit-learn 1.9.1, 기본값)

| 방법 | 구간 P / R / F1 | IP P / R / F1 | 빠른 브루트포스 | 느린 공격 |
|---|---|---|---|---|
| zscore | 1.00 / 0.25 / 0.40 | 1.00 / 0.50 / 0.67 | 탐지 | **놓침** |
| iforest | 0.50 / 0.50 / 0.50 | 0.50 / 1.00 / 0.67 | 탐지 | 탐지 |
| lof | 1.00 / 1.00 / 1.00 | 1.00 / 1.00 / 1.00 | 탐지 | 탐지 |
| ocsvm | 0.08 / 0.50 / 0.14 | 0.12 / 1.00 / 0.22 | 탐지 | 탐지 |

읽는 법 (샘플 38행이라 **결론이 아니라 동작 확인용**)
- **zscore가 느린 공격을 놓침**: 피처를 하나씩 보는데, 느린 공격은 5분 구간마다 값이 크지 않다 → 다변량 모델이 필요한 이유
- **ocsvm 오탐 다수**: 38행 중 고유한 행이 10개뿐이라 중복 점이 경계(점수 ≈ −0.0003)에 몰려 미세한 수치 차이로 안/밖이 갈린다. 표본이 작고 중복이 많은 데이터의 한계 — 랩 로그로 다시 볼 것
- lof가 가장 좋게 나왔지만 이 샘플 하나의 결과다. 같은 비교를 랩 로그(정상 기간으로 fit)로 반복해야 의미가 있다

## LLM 단계 설계 (`explain_llm.py`)

- **원문 문자열을 보내지 않는다**: 경로·User-Agent·계정 이름은 공격자가 쓸 수 있는 칸이라 빼고, 피처 숫자만 보낸다 (`labs/01` 4단계에서 원문 전달 시 흔들림을 확인한 이유)
- **IP도 보내지 않는다**: 후보는 `C1`, `C2` 같은 id로만 보내고 IP 매핑은 스크립트 안에서만 한다
- **평소 값 제공**: LLM은 우리 환경의 평소를 모르므로 학습 구간 중앙값을 함께 준다 (`docs/09` Q5)
- **출력 제한**: 구조화 출력으로 `block_30m / observe / ignore` 중 하나만. 최종 조치는 룰·점수가 결정 (`docs/03` §3-6)
- 비결정성: 같은 입력에도 답이 달라질 수 있다 → 비교 실험에선 여러 번 실행해 비율로
- API 호출 경로는 이 PC에 자격증명이 없어 **실제 호출로는 미검증**(2026-10-23, 프롬프트 출력·자격증명 없음 경로만 확인)

## 주의

- `--train-until` 이전 구간에 공격이 섞이면 기준이 오염된다 (`docs/08` §3 "이 기간엔 공격 금지")
- 임계값(contamination·nu·z)은 정상 기간으로 정하고 **채점 결과를 보며 조정하지 않는다**
- 경로·User-Agent 등 원문 값은 피처 계산에만 쓰고, LLM에 넘길 때는 숫자 요약 위주 (`labs/01` 4단계)
