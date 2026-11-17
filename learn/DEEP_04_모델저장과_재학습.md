# 깊이 이해 04 — 모델 저장(.joblib)과 재학습·재현

> 원저작 설명 + 우리 저장소 실물. 앞: `DEEP_02_분류와평가지표.md`. 용어: `GLOSSARY.md`.
> 2026-10-25 질문에서 출발: "어차피 .py로 모델링하는데 .joblib은 왜 따로 있나? 플라이휠 돌릴 때 모델이 메모리에 없으면?"

## 0. 누가 무엇을 하나
| 누가 | 하는 일 |
|---|---|
| **Claude** | AI 모델(두뇌). 코드를 *쓰고*, 터미널 출력(텍스트)을 *읽는다*. ML 모델을 머릿속에 들고 있지 않다 |
| **Claude Code** | Claude 가 파일을 쓰고 명령을 치게 해주는 프로그램. `python ml/train_export.py ...` 를 *대신 타이핑* |
| **Python** | 코드를 실제로 실행. `model = IsolationForest()` 줄에서 **RAM 에 객체를 만들고** `fit()` 으로 채운다 |
| **Windows** | python.exe 에 메모리를 빌려주고, 끝나면 회수 |

→ 같은 명령을 내가 cmd 에 쳐도 결과는 완전히 같다. "메모리에 띄운다"는 특별한 작업이 아니라 **파이썬 코드가 실행되는 것 자체**.

## 1. .py = 레시피, .joblib = 완성된 요리
```
ml/train_export.py (학습 과정)            models/model_web_v3.1.joblib (학습 결과)
 - 데이터 읽기                               - 피처 순서, 설정값
 - 스케일링                    ──fit()──▶    - 학습된 숫자들 (트리 분기점, LOF 이웃, AE 가중치)
 - 모델 종류·설정 선택                       - 학습 메타정보
```
- **.py 안에는 학습 결과가 없다.** "어떻게 학습할지"만 있다.
- **.joblib 안에는 코드가 없다.** 학습으로 찾아낸 **숫자(데이터)** 가 있다. 수천~수만 개라 코드로 못 쓰니 바이너리로 저장.
- 진화가 아니다: 레시피가 요리로 *변하는* 게 아니라, 레시피대로 *만든 결과물*.

**왜 따로 저장?** 학습은 느리다(분~일). 저장해 두면 판정 때 `load` 만 하면 된다 → `ml/predict.py`, `consumer/consumer.py`.

## 2. 우리 .joblib 안에 정확히 뭐가 있나
`train_export.py` 가 `joblib.dump(bundle, ...)` 로 저장하는 **사전(dict)** 하나:

| 키 | 종류 | 예 (v3.1) |
|---|---|---|
| `features` · `feature_set` | 피처 순서 · 확정셋 이름 | 10개 · `web_v1` |
| `contamination` | 설정(사람이 정함) | 0.05 |
| `scaler` | 학습 결과 — 정상의 평균·표준편차 | StandardScaler |
| `iforest` · `lof` · `autoencoder` · `rf` | **학습 결과 — 용량 대부분** | 트리 300개 / 이웃 / MLP 가중치 / 트리 300개 |
| `ae_threshold` | 학습 결과 — 정상 재구성오차 95분위 | 0.3173 |
| `trained_on` · `trained_at` · `n_normal` · `sklearn` | 영수증(메타정보) | `c_rel.csv` · UTC 시각 · 214 · 1.9.1 |

- 모델 객체는 **클래스 경로 + 속성값**으로 저장된다. 클래스 *코드*는 없어서 **scikit-learn 이 설치돼 있어야** 열린다(버전 다르면 경고).
- 속성 중 이름이 `_` 로 끝나는 것(`estimators_`, `classes_`)이 학습으로 생긴 값.
- 직접 열어보기:
```python
import joblib
b = joblib.load("models/model_web_v3.1.joblib")
print(b.keys()); print(b["features"]); print(b["n_normal"], b["trained_at"])
print(b["iforest"].get_params())      # 하이퍼파라미터
```

## 3. 비교: PyTorch .pt
- `.pt` 는 **zip** 파일: 안에 `data.pkl`(목차) + `data/0, 1, …`(텐서 숫자 원본).
- 보통 `state_dict`(이름→가중치 텐서)만 저장 → **모델 구조(클래스 코드)는 .py 에 있어야** 불러올 수 있다.
- 정리: sklearn .joblib = "구조 정보 + 숫자", PyTorch state_dict = "숫자만". 어느 쪽이든 **판정은 파일만, 재학습은 코드+데이터**.

## 4. 메모리(RAM) vs 디스크
```
python ml/train_export.py ... 실행
  → RAM 에서 학습 (모델이 메모리에 있는 건 이 몇 초~몇 분뿐)
  → joblib.dump() ── 디스크에 저장 ◀ 여기서 남는다
  → 프로그램 종료 → RAM 회수 (파일은 그대로)
```
- 학습과 판정을 **한 번의 실행 안에서** 하면 파일 없이도 동작한다(예: `ml/models.py`, `supervised.py` 는 매번 fit 하고 버린다). 끝나면 사라지는 건 *파일이 지워진* 게 아니라 **처음부터 파일이 아니었던** 것.
- Claude Code 가 `python - <<EOF ... EOF` 처럼 **파일 없이 코드를 흘려 넣어** 실행하는 경우도 있다 → 코드도 디스크에 안 남는다. 남기고 싶으면 "코드는 ○○.py, 모델은 ○○.joblib 로 저장해줘"라고 요청.

## 5. 재학습과 플라이휠 — 모델을 "고치는" 게 아니라 "새로 만든다"
```
1바퀴  데이터 A        → train_export → model_v1.joblib
2바퀴  데이터 A+B      → train_export → model_v2.joblib
3바퀴  데이터 A+B+C    → train_export → model_v3.joblib
        ↑ 재료는 '누적 데이터'        ↑ 이전 모델은 재료가 아님 (비교 기준일 뿐)
```
- IsolationForest · LOF · RandomForest 는 기존 모델에 새 데이터를 **조금씩 더 배우는 기능(partial_fit)이 없다** → 매 바퀴 **전체 데이터로 처음부터** 학습.
- 그래서 플라이휠에 꼭 필요한 건 **① 학습 코드 ② 누적 데이터**. 모델 파일은 결과물·비교 기준.
- 우리 경로: `scripts/flywheel_turn.sh`(피처→누적 `data/dataset_web.csv`→검증) → `train_export.py`(새 버전 저장) — `docs/24`.

| 하려는 일 | .joblib 만으로? |
|---|---|
| 저장 모델로 새 로그 판정 | ✅ `predict.py` |
| 새 데이터 반영(플라이휠) | ❌ 코드+누적 데이터로 재학습 |
| contamination 등 설정 바꿔 실험 | ❌ 재학습 |

## 6. 재현 — "그 모델을 똑같이 다시 만들 수 있나?"
**왜 필요?** v4 가 v3.1 보다 나은지 공정하게 비교하려면 v3.1 이 *정확히* 어떤 데이터·설정에서 나왔는지 알아야 한다.

- `models/retrain_2026-10-25.sh` — 10-25 에 만든 모델 10개를 같은 입력·설정으로 다시 학습 → `tools/compare_bundles.py` 로 원본 대조. **10/10 일치**.
- 명령을 복원한 방법: 각 .joblib 의 **영수증 키**(`trained_on`, `contamination`, `n_normal`)를 읽었다 → §2 의 메타정보가 이래서 중요.
- 같은 결과가 나오는 이유: `random_state=0` 고정 → 같은 데이터면 같은 모델(결정적).

**실제로 겪은 함정 — 데이터가 바뀌면 모델 파일만으로는 재현 안 된다:**
`model_db_arc_c005` 는 07:07 에 학습(92구간). 그런데 08:54 에 생성기 버그를 고쳐 `data/db_arc_features.csv` 가 **96구간으로 덮어써졌다**
→ 지금 데이터로 학습하면 다른 모델. 학습 당시 커밋(`5b53e5f`)의 생성기로 로그를 다시 만들어야 재현됐다.
> **교훈: 데이터도 코드처럼 버전 관리해야 한다.** 그래서 `data/` 를 git 에 올렸다(2026-10-25, 커밋 `56640e4`). 이전엔 이 PC 에만 있어서 고장 나면 실제 랩 로그를 잃을 수 있었다.

## 7. 보안 주의 — .joblib/.pkl 은 "실행되는" 파일
- joblib/pickle 은 "이 클래스로 객체를 만들고 값을 채워라"는 **복원 지시문**이다. 악의적 파일은 load 순간 임의 코드를 실행할 수 있다.
- **출처 모르는 .joblib/.pkl 은 load 금지.** PyTorch 는 2.6부터 `torch.load(weights_only=True)` 기본(텐서만), Hugging Face 는 `.safetensors` 권장.
- 우리 모델은 우리가 만든 것이라 괜찮지만, 공개 저장소에서 남의 모델을 받을 땐 이 점을 기억.

## 8. 직접 해보기
```bash
# 번들 열어보기 (§2)
python -c "import joblib; b=joblib.load('models/model_web_v3.1.joblib'); print({k:b[k] for k in ('features','contamination','n_normal','trained_on','trained_at')})"
# 저장 모델로 판정만 (재학습 없음) — 입력 CSV 에 번들의 features 10개가 다 있어야 한다
python ml/predict.py models/model_web_v3.1.joblib data/real_canon_rel.csv
#   rel_* 없는 datasets/real_web/real_canon_features.csv 를 주면 "피처 CSV에 없는 열" 에러 → §2 의 '피처 순서' 가 그래서 번들에 있다
# 오늘 모델 10개 재현 + 원본 대조 (약 2~3분)
bash models/retrain_2026-10-25.sh
# PyTorch .pt 가 zip 인지 확인 (torch 설치 시)
python -c "import torch,zipfile; torch.save({'w':torch.ones(2)},'t.pt'); print(zipfile.ZipFile('t.pt').namelist())"
```

## 한 문장 정리
> **.py 는 레시피, .joblib 은 레시피대로 만든 요리(학습된 숫자). 판정은 요리만 있으면 되지만, 플라이휠은 매번 *누적 데이터*로 새 요리를 만든다.
> 그래서 지켜야 할 건 코드와 데이터이고, 모델 파일 속 영수증(`trained_on`·`n_normal`)이 "어떻게 만들었나"를 증명한다.**
