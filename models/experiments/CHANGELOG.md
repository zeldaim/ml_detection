# 실험 모델 버전 기록 (플라이휠)

> 최종만 남기지 않고 **설정별·바퀴별로 전부 보존**한다. 각 모델은 재현 가능(같은 데이터·seed).
> 학습 데이터(`data/`)는 gitignore라 저장소엔 없음 — 생성기 seed 로 재생성(`tools/gen_synth_log.py --seed 7`).

## 공통
- 학습 입력: `data/synth_features.csv` (= `gen_synth_log.py --minutes 240 --normal-users 8 --repeat 2 --seed 7`)
- 정답지: `data/synth_answer.csv` · 번들: IsolationForest + LOF + Autoencoder + RandomForest(분류) + 스케일러
- 평가: `supervised.py --group-by type`(처음 보는 공격). 모든 설정에서 **탐지율 1.00 유지**.

## contamination 스윕 (2026-10-25) — 탐지율 1.00 고정, 오탐만 변함

| 버전 파일 | contamination | IF 오탐 | LOF 오탐 | AE 오탐 | IF\|LOF\|AE 오탐 |
|---|---|---|---|---|---|
| `model_synth_c010.joblib` | 0.10 | 0.15 | 0.09 | 0.06 | 0.18 |
| `model_synth_c005.joblib` | 0.05 | 0.06 | 0.03 | 0.05 | 0.10 |
| `model_synth_c003.joblib` | 0.03 | 0.03 | 0.03 | 0.03 | 0.06 |
| **`model_synth_c001.joblib`** | **0.01** | **0.03** | **0.01** | **0.01** | **0.03** |

**해석**: 합성 데이터에선 공격이 잘 분리돼 contamination 을 낮춰도 탐지율 1.00 이 유지되고 **오탐만 급감**.
→ 이 데이터 기준 권장값 **0.01** (LOF·AE 오탐 1%). 단 **합성이라 공격이 "쉽다"** — 탐지율이 전부 1.00 인 것 자체가
실제보다 분리가 과한 신호. **실제 로그에선 더 높은 contamination 이 필요할 수 있음** → 실제 검증에서 재조정.

## 다음 버전 규칙
- 새 바퀴: `model_<데이터셋>_<설정>_v<n>.joblib` 로 저장 + 이 표에 행 추가(설정·지표·해석).
- 실제 데이터 버전은 `model_real_*` 로 구분. 운영 후보는 `models/model.joblib` 로 승격(그때 기존 것 archive).
