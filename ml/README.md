# ml/ — 행위 층 이상탐지 (피처 → 모델 비교 → 채점)

> 계획: `docs/10` §3 · 메인 컨셉: `docs/07` §5 행위 층 · 입력 로그: `docs/08` 환경의 alerts.json / archives.json
> 의존성: scikit-learn (numpy 포함). pandas 불필요.

```
alerts.json / archives.json ─▶ features.py ─▶ 피처 CSV ─▶ models.py ─▶ detections CSV ─▶ evaluate.py ─▶ P/R/F1
                                (IP × 5분)                (zscore·iforest·lof·ocsvm)          (정답지)
```

| 파일 | 역할 |
|---|---|
| `features.py` | 로그 → IP × 구간 피처 표. alerts는 룰 알럿 피처, archives는 nginx 접근 로그·sshd 실패 피처 |
| `models.py` | 같은 피처 표로 Z-score(robust) · Isolation Forest · LOF · One-Class SVM 실행, 점수는 모두 "클수록 이상" |
| `evaluate.py` | 정답지로 구간 단위·IP 단위 TP/FP/FN/TN, Precision/Recall/F1, 공격별 탐지 여부 |

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

# 09 Q12 비교: 같은 기간을 --alerts만으로도 만들어 같은 모델·같은 정답지로
python ml/features.py --alerts alerts.json --out data/features_alerts.csv
```

Windows에서 글자가 깨지면 `$env:PYTHONUTF8=1`(PowerShell) 후 실행. 출력은 `data/`(Git 제외).

## 피처

| 입력 | 피처 | 정의 |
|---|---|---|
| alerts | `alert_count` · `rule_level_max` · `uniq_rules` | 알럿 수 · 최고 룰 레벨 · 서로 다른 룰 수 |
| | `auth_fail` · `uniq_users` | 인증 실패 그룹 알럿 수 · 서로 다른 계정 수 |
| archives (nginx) | `req_count` · `uniq_paths` | 요청 수 · 서로 다른 (메서드, 경로 템플릿) 수 |
| | `uniq_objects` | 경로 속 숫자 조각(객체 ID)의 서로 다른 수 — BOLA 징후 |
| | `err_ratio` · `write_ratio` | 4xx·5xx 비율 · POST/PUT/PATCH/DELETE 비율 |
| | `interval_cv` | 요청 간격 표준편차 ÷ 평균 (0에 가까울수록 기계적). 간격 2개 미만이면 1.0(중립) |
| | `endpoint_entropy` | 경로 템플릿 분포 엔트로피 (`detector`의 `shannon` 재사용) |
| archives (sshd) | `ssh_fail` | `Failed password` / `Invalid user` 줄 수 |

- 경로 템플릿: `/rest/basket/3` → `/rest/basket/{id}` (숫자 경로 조각을 `{id}`로)
- nginx 줄의 시각은 **로그 원문 시각**을 쓴다 (Wazuh 수집 시각 아님)
- 분석 주체는 출발지 IP (`docs/10` §2-2 "왜 nginx 로그엔 계정이 없나")

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

## 주의

- `--train-until` 이전 구간에 공격이 섞이면 기준이 오염된다 (`docs/08` §3 "이 기간엔 공격 금지")
- 임계값(contamination·nu·z)은 정상 기간으로 정하고 **채점 결과를 보며 조정하지 않는다**
- 경로·User-Agent 등 원문 값은 피처 계산에만 쓰고, LLM에 넘길 때는 숫자 요약 위주 (`labs/01` 4단계)
