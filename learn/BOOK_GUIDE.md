# Hands-On ML (3rd ed, 영어 원서) 읽기 가이드 — 우리 프로젝트에 대입

> 영어 원서를 무료로 볼 때 **막히는 영어 ML 용어 + 챕터별 우리 프로젝트 연결**.
> 공식 무료 코드: github.com/ageron/handson-ml3 (실행 가능 노트북). 용어는 `GLOSSARY.md`, 개념은 `ML_WALKTHROUGH.md`.
> **1부(Ch 1~9)만** 보면 우리가 쓴 건 다 나온다. 2부(신경망/TF)는 나중.

## 읽는 법 (영어 부담 줄이기)
1. 각 챕터 **"우리 프로젝트" 줄 먼저** 보고 → 뭘 찾을지 알고 영어를 읽는다.
2. 아래 **영어→한글 핵심 용어**로 막히는 단어 해결.
3. 수식/증명은 건너뛰고 **"왜 쓰나 + 언제 쓰나"**에 집중(우리 목적).

---

## Ch 1. The Machine Learning Landscape
- 우리: 전체 그림. supervised/unsupervised/anomaly 가 뭔지.
| EN | KO |
|---|---|
| training set / test set | 학습셋 / 시험셋 |
| instance, sample | 샘플(한 행) |
| feature, attribute | 피처 |
| label, target | 라벨(정답) |
| overfitting / underfitting | 과적합 / 과소적합 |
| generalization | 일반화 |

## Ch 2. End-to-End ML Project ★ (전처리의 핵심)
- 우리: **전처리 판단**(`ML_WALKTHROUGH.md` C). 스케일링·데이터 분리·파이프라인.
| EN | KO |
|---|---|
| data pipeline | 데이터 파이프라인 |
| stratified sampling | 층화 추출 |
| feature scaling / standardization | 스케일링 / 표준화(StandardScaler) |
| data leakage | 라벨 누수 |
| cross-validation | 교차검증 |

## Ch 3. Classification ★
- 우리: `supervised.py`, RF 분류, 평가지표.
| EN | KO |
|---|---|
| precision / recall | 정밀도 / 재현율 |
| confusion matrix | 혼동행렬 |
| F1 score | F1 점수 |
| false positive / false negative | 오탐 / 미탐 |
| decision threshold | 판정 임계값 (우리 contamination 과 같은 역할) |

## Ch 4. Training Models
- 우리: 모델이 "학습"한다는 게 뭔지(가중치 맞추기). 깊이 필요할 때만.
| EN | KO |
|---|---|
| gradient descent | 경사하강법 |
| regularization | 규제(과적합 억제) |
| bias / variance tradeoff | 편향/분산 트레이드오프 (`docs/19` §6-1) |

## Ch 5. SVM
- 우리: One-Class SVM 비교군(`models.py`). 가볍게.
| EN | KO |
|---|---|
| margin | 마진(경계 여유) |
| kernel | 커널 |

## Ch 6. Decision Trees
- 우리: RandomForest 의 부품. 트리가 어떻게 분기하나.
| EN | KO |
|---|---|
| split, node, leaf | 분기 / 노드 / 잎 |
| Gini impurity | 지니 불순도 |
| feature importance | 피처 중요도 (우리 RF 출력) |

## Ch 7. Ensemble Learning & Random Forests ★
- 우리: **RandomForest**(`classify_type.py`, E2 결과). 여러 모델 조합(우리 IF|LOF|AE 앙상블과 통함).
| EN | KO |
|---|---|
| ensemble | 앙상블(여러 모델 합치기) |
| bagging | 배깅(샘플 랜덤 재추출) |
| voting (hard/soft) | 투표(다수결/확률평균) |
| out-of-bag | OOB(안 쓴 샘플로 평가) |

## Ch 8. Dimensionality Reduction
- 우리: 지금은 안 씀(피처 9개로 적음). 참고만.
| EN | KO |
|---|---|
| PCA | 주성분분석 |
| curse of dimensionality | 차원의 저주 |

## Ch 9. Unsupervised Learning ★★ (우리 핵심)
- 우리: **이상탐지**(IF/LOF), 비지도. H5(IF vs LOF)가 여기 개념.
| EN | KO |
|---|---|
| clustering | 군집화 |
| anomaly / novelty detection | 이상탐지 / 새로움탐지 |
| Isolation Forest | 아이솔레이션 포레스트 (`docs/02`) |
| density estimation | 밀도 추정 (LOF 가 쓰는 개념) |
| contamination | 오염 비율(이상으로 볼 %) — 우리가 스윕한 그것 |

> **Autoencoder** 는 2부 Ch 17(신경망)인데, 우리 AE 이해는 `ML_WALKTHROUGH.md` A3 로 충분. 책은 깊이 필요할 때.

---

## 우선순위 (시간 아끼기)
1. **Ch 9**(비지도·이상탐지) ← 우리 프로젝트 심장
2. **Ch 7**(앙상블/RF) + **Ch 3**(분류·평가지표)
3. **Ch 2**(전처리·파이프라인) ← 전처리 실력
4. 나머지는 필요할 때 사전처럼.

> 읽다 막히면: "이 장(예: Ch 7)이 우리 프로젝트 어디?" 물어보면 바로 코드·실험으로 연결해 줌.
