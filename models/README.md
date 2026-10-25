# models/ — 학습된 모델 + 버전 기록

`.joblib`은 바이너리라 파일 안에 주석을 못 넣는다. **버전 변경 설명은 이 파일에 남긴다.**
이전 버전은 지우지 않고 `models/archive/`에 보존한다.

## 현재 (최신)

| 파일 | 대상 | 버전 | 담긴 모델 |
|---|---|---|---|
| `model.joblib` | 웹(nginx) | **v2** | IsolationForest + LOF + **Autoencoder** + RandomForest(분류) + 스케일러 |
| `db_model.joblib` | DB(MySQL) | **v2** | 위와 동일 구조 (DB 피처) |
| **`model_web_v3.1.joblib`** | 웹(nginx, 실제 정본) | **v3.1 · 운영 후보** | 위 구조 + 피처셋 `web_v1`(UEBA `rel_*` 포함 10개). **[모델 카드](MODEL_CARD.md)** |

> `model.joblib`(v2)는 collector 기본값으로 남긴다 — v3.1 은 `rel_*` 온라인 계산이 붙으면 승격(`docs/27` §7).

번들 안에는 모델 외에 `features`(피처 순서), `feature_set`(v3.1~, `ml/feature_spec.py` 이름), `contamination`, `scaler`, `ae_threshold`(재구성 오차 경계), `classes`, `trained_at`, `trained_on`, `sklearn` 버전이 함께 들어 있다.

## 버전 기록 (changelog)

### v3.1 — 2026-10-25 · 피처셋 확정(`web_v1`) + 학습 결함 수정
- **무엇:** 실제 정본(`datasets/real_web/real_canon_*`)으로 학습, 피처 10개(`ssh_fail` 제외 — nginx 소스에서 분산 0).
- **결함 수정:** `train_export.py` 가 IP형 정답지(`ip,label,type`)를 무시해 v3 는 **공격 32구간을 정상으로 학습**했다(n_normal 246).
  같은 데이터 in-sample 에서 LOF 8/32 → v3.1 28/32. 이제 `supervised.label_windows` 공유 + 매칭 0건이면 학습 중단.
- **성능:** IF|LOF|AE 0.91±0.04 · LOF 0.88 · 평가 정상 오탐 0/65 (seed 10개). 상세 [MODEL_CARD.md](MODEL_CARD.md), 근거 `docs/27`.
- 이전: `archive/model_web_v3_canon_rel_trained-with-attacks.joblib` (v3, 결함 그대로 보존)

### v2 — 2026-10-24 · Autoencoder 추가
- **무엇:** 비지도 층에 Autoencoder(sklearn MLPRegressor로 구현) 추가. 정상을 압축→복원 학습, 재구성 오차 > 경계면 이상.
- **왜:** IsolationForest는 "학습 때 본 값의 범위 밖"으로 외삽을 못 해 느린·새 공격을 놓친다(docs/16 §0, 우리 H5). AE는 모든 피처를 복원하므로 그 약점을 보완한다.
- **결과(합성):** 웹 E2에서 AE 탐지율 1.00 / 오탐 0.00 (LOF와 동급, IF 0.43 대비↑). 느린 BOLA(.214)를 IF는 놓치고 LOF·AE가 잡음.
- **호환:** predict.py·collector.py는 번들에 `autoencoder`가 없으면(구버전) AE를 건너뛰도록 방어 처리 → v1도 그대로 로드 가능.
- 이전 버전: `archive/model_v1_IF-LOF-RF.joblib`, `archive/db_model_v1_IF-LOF-RF.joblib`

### v1 — 2026-10-23 · 최초
- IsolationForest + LOF + RandomForest(분류) + 스케일러.
- 웹·DB 각각 랩 합성 데이터로 학습. docs/13 결과의 기반.
- 보존 위치: `archive/model_v1_IF-LOF-RF.joblib`, `archive/db_model_v1_IF-LOF-RF.joblib`

## 재현(재학습) 방법

```bash
# 웹 v2
python ml/train_export.py data/features_combined.csv --answer data/answer.csv --contamination 0.05 --out models/model.joblib
# 웹 v3.1 (실제 정본) — 전체 명령은 MODEL_CARD.md §9
python ml/train_export.py /tmp/c_rel.csv --answer datasets/real_web/real_canon_answer.csv --feature-set web_v1 --contamination 0.05 --out models/model_web_v3.1.joblib
# DB v2
python ml/train_export.py data/features_db.csv --answer data/answer_db.csv --contamination 0.05 --out models/db_model.joblib
```

> 다음 버전을 만들 때도: ① 현재 파일을 `archive/model_vN_설명.joblib`로 복사 → ② 재학습 → ③ 이 README에 변경 설명 추가.
> 학습 데이터(`data/`)는 .gitignore라 저장소엔 없음. 모델만 커밋한다.
