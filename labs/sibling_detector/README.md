# labs/sibling_detector — 형제-detector 프레임 (실험 버전)

> ⚠️ **실험/대안 버전.** 메인 파이프라인(`ml/`·`edge/`)을 대체하지 않는다. 밑바닥부터
> 다시 짠 자기완결 패키지라, **상당 부분이 기존 코드와 겹치고 일부는 이미 기각된 것**을
> 포함한다. 아래 "기존 코드와의 관계"를 반드시 먼저 읽을 것.

## 무엇인가

BOLA 탐지를 **형제 detector 구조**로 구현한 실험물. 공통 파이프라인에서 윈도우를 한 번
자르고, 각 detector(현재 BOLA + Exfil 템플릿)가 그 위에서 돌아, 윈도우마다 **모든 detector
점수 + 통합점수 + 귀속(어느 detector가 터졌나)**을 동시에 산출한다.

```
AccessLog ─▶ DetectorRegistry (window 1회, ownership enrich 1회)
                   ├─ BolaDetector  (live)
                   └─ ExfilDetector (template)
             per-window: {bola_z, exfil_z} + combined + top_detector
```

## 기존 코드와의 관계 (정직한 중복·충돌 표)

| 이 폴더 | 메인 리포에 이미 있음 | 판정 |
|---|---|---|
| `sequential_id_ratio` | `ml/features.py` 주석의 **seq_id_score — 이미 실험 후 기각** (uniq_objects와 중복, IF 오탐↑; `docs/21 §D`) | ❌ **기각된 피처.** 참고용으로만 둠 |
| `central_features.deviation_from_baseline` | `ml/relative_features.py` (UEBA rel_*, self/expanding/peer) | ⚠️ 중복 — 메인 쪽이 더 정교 |
| `edge_features.distinct_object_ids` | 웹 `uniq_objects` / DB `distinct_where_ids` | ⚠️ 중복 |
| 단일 IsolationForest | `ml/models.py`의 IF+LOF+OCSVM+AE 다모델 | ❌ **핵심 발견과 배치** (IF 단독은 느린 공격 놓침) |

## 유일하게 비중복인 기여

**`owner_mismatch` 축** — 게이트웨이 인증 ID ↔ DB owner 직접 비교.

- 메인 웹 파이프라인은 **출발지 IP 기준**이다(nginx 로그에 계정 없음, `docs/10 §2-2`).
- 이 축은 요청마다 **인증된 user_id**가 있어야 성립 → 게이트웨이 로그(로그인 정보 보존)에서만
  나온다. 지금 메인 리포엔 미구현.
- `ownership.OwnershipSource`로 추상화 → 실제 DB 모델을 `resolve()` 하나만 구현해 꽂으면 됨.
- **시점 정합성 주의**: 소유권이 바뀌면 "요청 당시 owner"로 조인해야 이관 직후 오탐이 안 난다.

→ 이 폴더에서 **살려서 메인에 이식할 가치가 있는 건 이 축 하나**다. 나머지는 재발명.

## 구조

```
bola_detection/
  schema.py            AccessLog(엣지 emit) + OwnershipRecord
  ownership.py         OwnershipSource ABC + 인메모리 + [실제 DB 어댑터 스텁]
  edge_features.py     엣지 로컬 피처 (seq_id 포함 — 기각된 것 주의)
  central_features.py  소유권 조인 + per-user baseline
  model.py             AnomalyModel: StandardScaler + IsolationForest
  pipeline.py          enrich / window 헬퍼
  registry.py          DetectorRegistry: 형제 detector 실행·통합·귀속
  detectors/           base / bola / exfil(템플릿)
tools/synthetic_logs.py  정상 + BOLA 공격 합성
demo.py / tests/         실행·테스트 (6개 통과)
```

## 실행

```bash
cd labs/sibling_detector
python tests/test_features.py
python demo.py
```
