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

## 실제 데이터 버전 (2026-10-25)

| 버전 파일 | 데이터 | contamination | 결과 |
|---|---|---|---|
| `model_real_juiceshop_c005.joblib` | 실제 Juice Shop nginx 로그(48구간) | 0.05 | IF 0.43 / LOF 1.00 / AE 1.00, H5 4구간 재현 |

**의미**: 합성에선 IF도 1.00(포화)이었으나 실제에선 **IF 0.43** → 실제 데이터가 포화 안 된 기울기를 줌.
느린 공격을 IF가 놓치고 LOF/AE가 보완(H5)이 **실제 로그에서 재현**. 단 공격 구간 7개로 적어 지표 흔들림.
→ 운영 승격 전 더 많은 실제 변주 수집 필요(다중 IP·여러 종류).

| `model_real_v2_c010.joblib` | 실제 2수집 합본(70구간·9종) | 0.10 | LOF 1.00/0.06 · IF 0.71 · **AE 1.00/0.88(분포 shift)** |

**실제 2바퀴 결론**: 합성은 전부 1.00 포화였으나 실제선 **LOF>IF, AE 취약**으로 갈림.
AE 오탐 0.88 = 두 수집분 정상이 다른 분포(train≠eval normal, 편향 사례). 운영 후보 = **LOF**.
H5(IF 놓침·LOF 보완) 실제 5구간 재현.

## DB 모델 (2026-10-25)

| 버전 파일 | 데이터 | contamination | 결과 |
|---|---|---|---|
| `model_db_arc_c005.joblib` | 합성 DB 아크(92구간: scrape·bola·sqli + 하드네거티브) | 0.05 | LOF 1.00/0.14 · IF 0.67 · AE 1.00/0.33 |

DB 아크(docs/22): 하드네거티브는 **파생 피처 '반복도(q_count/uniq_templates)'**로 scrape 0/8→8/8.
UEBA는 웹 §K 코드 전이. 출발지 귀속만 실제 필요. 운영후보 LOF.

## ★ 현재 최선 모델 (운영 후보, 2026-10-25)

**`models/model_web_v3.1.joblib`** — 웹 정본 정상 214구간 + 피처셋 **`web_v1`**(10피처, ssh_fail 제외). 카드: `models/MODEL_CARD.md`.
- 성능(처음 보는 데이터, seed 10개): **IF|LOF|AE 0.91±0.04 · LOF 0.88 · 평가 정상 오탐 0/65**(c0.05).
- ⚠ 이전 v3(`model_web_v3_canon_rel.joblib`, 0.97 로 기록)은 **정정**: 0.97 은 AE seed 하나의 값, 번들은 `train_export.py` 버그로
  **공격 32구간을 정상으로 학습**(n_normal 246) → `archive/model_web_v3_canon_rel_trained-with-attacks.joblib` 로 보관. 상세 `docs/27` §4.
- 재현: `datasets/real_web/` + `relative_features.py` → `train_export.py --feature-set web_v1`(`docs/27` §6).
- experiments/ 의 이전 모델들은 실험 기록용. **배포 후보는 이 v3.1.**

## 다음 버전 규칙
- 새 바퀴: `model_<데이터셋>_<설정>_v<n>.joblib` 로 저장 + 이 표에 행 추가(설정·지표·해석).
- 실제 데이터 버전은 `model_real_*` 로 구분. 운영 후보는 `models/model.joblib` 로 승격(그때 기존 것 archive).
