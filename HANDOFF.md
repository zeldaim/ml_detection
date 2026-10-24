# 이어가기 (HANDOFF) — 현재 상태와 다음 할 일

> 다음에 작업을 이어갈 때 **여기부터 읽는다.** 마지막 업데이트: 2026-10-25.
> 빠른 복귀: `pip install -r requirements.txt` → `bash run_demo.sh` → 아래 "다음 할 일".

## 0. 플라이휠 1차 (2026-10-25 진행 — 실제 로그 검증)

> 전체 서사·수치: `docs/21`. 원리/편향분산/LLM한계: `docs/19`. API 데이터셋 설계: `docs/20`. DB는 별도 phase: `docs/22`. 초보 용어: `learn/GLOSSARY.md`.

- **실제 로그로 H5 재현**: 실제 Juice Shop nginx 로그에서 IF 느린공격 놓침·LOF/AE 보완 재현(`docs/21` §F·G).
- **합성 vs 실제**: 합성은 전부 1.00 포화(모델 건강은 퍼뮤테이션으로 확인) → 실제선 **LOF 우수, IF 느린공격 취약, AE 분포 민감**으로 갈림.
- **AE 분포 shift**: 서로 다른 정상 분포 합치면 AE 오탐 폭증(편향 실례). 정상 보강으로 완화(`docs/21` §G·H).
- **정상 생성기 속도 교훈**: 너무 빠른 정상은 harvest 공격과 인위적 겹침 → **현실적 간격 필수**(§I). 운영 후보 현재 **LOF**(실제 1.00/0.06~0.15).
- **플라이휠 누적셋** `data/dataset_web.csv` ≈569행(gitignore), 출처 6종(합성 2+실제 4). 장치 `ml/accumulate.py`.
- **버전 모델 전부 보존** `models/experiments/` + `CHANGELOG.md`(contamination 스윕 4종 + 실제 2종).
- **생성기**: 합성 로그 `tools/gen_synth_log.py`(10종), 실제 트래픽 `collect_kit/target_side/`(타겟서 IP별칭, 다중출발지).
- **진행 중**: #2 = `fastclient.sh`(하드 네거티브, 빠른 합법 클라이언트)로 `endpoint_entropy`가 harvest와 가르는지.

## 1. 지금 어디까지 왔나 (완료)

- **웹 계층 탐지**: nginx 로그 → IP×5분 피처 → IF·LOF·AE(발견) + RF(분류). 느린 BOLA를 IF는 놓치고 LOF·AE가 잡음(H5). → `docs/13` §3
- **DB 계층 탐지**: MySQL 쿼리 로그 → DB 피처(BOLA=`distinct_where_ids`, SQLi=`sqli_token_hits`). 웹과 같은 결론 재현. → `docs/13` §4
- **모델 저장/판정**: `models/model.joblib`(웹), `models/db_model.joblib`(DB) = **v2(IF+LOF+AE+RF)**. v1은 `models/archive/`. 체인지로그 `models/README.md`
- **자동화**: `consumer/`(단순), `edge/`(피처 벡터만 전송 + 중앙 collector + DB 출발지 귀속 `correlate.py`)
- **공개 데이터 교차검증**: CSIC 2010(내용 공격) → lof·AE F1 0.98. → `docs/13` §4-1
- **기록**: README(현관), `docs/01~18`, 디버깅 로그 `docs/17`, draw.io 토폴로지 `docs/18`, 재현 데모 `run_demo`
- **노션**: 종합 결과 페이지 + "ML 파트 일지" DB (「새싹 최종 프로젝트」 아래)

## 2. 다음 할 일 (우선순위)

1. **실제 MySQL 로그로 DB 모델 재검증** — 지금은 합성. PHP+MySQL 티어 세우고 general log로. 런북: `docs/14`. 파싱 점검 `db_features.py --check`, 출발지 귀속 `correlate.py`(옵션 C→A).
2. **CSIC contamination 0.05 비교** — 오탐↓ 트레이드오프 눈으로 확인 (`--contamination 0.05`).
3. **설명가능성(XAI)** — RF 피처 중요도 + "왜 이상인가" 정리 (X-WAD 참고, `docs/16`).
4. **앱 계측 피처** — BOLA `owned_vs_self_ratio` 등 로그 밖 피처 (`docs/15` §3 갭 분석).
5. **pfSense 경계 삽입 데모** — "경계 통과 → 내부 ML 탐지" 실증 (`docs/13` §8, `docs/18` 그림2).
6. **SOAR** — 탐지 후 대응 자동화 (`docs/04`).

## 3. 열린 질문 / 결정 대기

- **DB 출발지 귀속**: 실제 환경에서 A(웹-DB 시간상관) / B(앱 계측) / C(DB 티어 단위) 중 택 → `docs/14` §4, `edge/correlate.py`.
- **모니터링 지표**(syscollector·Prometheus) 추가 여부 → "로그만 vs 로그+지표" 비교 (`docs/03`).
- **contamination 최종값**: 현재 0.05 고정. 데이터 늘면 재조정.

## 4. 환경 메모 (재현용)

- **취약 서버**: Rocky VM `10.16.1.10` — Juice Shop(127.0.0.1:3000) + nginx(80). [MySQL 티어 예정]
  - 정상 트래픽 보조 IP `10.16.1.101~106`, 공격 보조 IP `10.16.1.211~214`
- **공격**: Kali VM. **ML 분석**: 호스트 PC(Windows) `10.16.1.1`. 네트워크: VMnet8 NAT `10.16.1.0/24`(GW·DNS `10.16.1.2`)
- **Python**: 로컬 3.15 + scikit-learn 1.9.1 + pandas 3.1 (검증 환경: 3.12/1.9.1)
- **데이터**: `data/`는 .gitignore(저장소에 없음) → 생성기(`tools/`)로 재생성하거나 scp로 가져옴. 공개 CSIC은 `docs/16`에서 수동 다운로드.

## 5. 재현·이어가기 명령

```bash
pip install -r requirements.txt
bash run_demo.sh                      # 외부 데이터 없이 핵심 결과 재생성 (H5 포함)

# 실제 로그로 갈 때 (다음 할 일 1번)
#   docs/14 런북 따라 MySQL 세우고 → db_features.py --check → correlate.py → train_export → supervised
```

## 6. 기록 위치 한눈에

- **코드·문서**: GitHub `zeldaim/ml_detection` (README = 현관, `docs/` = 상세, `models/README.md` = 모델 버전)
- **노션**: 종합 결과 페이지 + ML 파트 일지 DB (일지는 작업마다 행 추가하며 이어감)
- **이 파일(HANDOFF.md)**: 다음 복귀 지점. 작업 끝낼 때마다 "완료/다음 할 일"을 여기 갱신.
