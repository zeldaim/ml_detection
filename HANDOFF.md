# 이어가기 (HANDOFF) — 현재 상태와 다음 할 일

> 다음에 작업을 이어갈 때 **여기부터 읽는다.** 마지막 업데이트: 2026-10-26.
> 빠른 복귀: `pip install -r requirements.txt` → `bash run_demo.sh` → 아래 "다음 할 일".

## 0000000. 피처 선택 원칙 정리 (2026-10-26)

- **`docs/32`**: 피처는 공격별이 아니라 **행위 축별 공통 한 세트**(web_v1). 개발=반복, 확정=동결, 운영=고정(바꾸면 web_v2 로 재검증)
- 적으면 그 축의 공격을 못 봄(uniq_objects 빼면 0.91→0.78), 많으면 오탐(같은 축 중복·무관 피처·데이터 부족). 넓게 보려면 출처별 모델(웹/DB/호스트)
- 엣지 에이전트는 **DB 에만**(쿼리 원문 반출 금지), 웹은 원문 수집. 단 **탐지를 DB 로만 하면 안 됨** — DB 는 app@웹VM 하나만 보고, DB 에 안 닿는 공격이 있음

## 000000. API Gateway 를 둘 때 원래 IP 보존 (2026-10-26)

- **`docs/29` §7**: 게이트웨이는 리버스 프록시 → 뒤쪽 로그엔 게이트웨이 IP 하나만 → `features.py`(첫 칸 IP = 출발지)가 모든 사용자를 한 출발지로 합침
- 결정: **게이트웨이 access log 를 ML 주 입력으로 수집**(첫 L7 지점), 뒤쪽 nginx 는 `real_ip`(게이트웨이 IP 만 신뢰)로 원래 IP 복원해 교차 확인·WAF 용
- `X-Forwarded-For` 위조 주의, 뒤쪽은 게이트웨이에서 온 연결만 허용. 게이트웨이는 BOLA 소유권 검사를 못 함(앱 몫). **설계만, 랩 미도입**

## 00000. WAF 층 설계 (2026-10-26)

- **`docs/31`**: 웹 VM nginx 에 ModSecurity + OWASP CRS. `DetectionOnly` → 오탐 예외 → 차단 순서. FortiGate=경계, ModSecurity=HTTP 내용 검사
- 인젝션(SQLi·XSS·LFI·RCE)은 WAF, BOLA·흐름 남용은 앱 권한 검사 + ML. WAF 결과는 ML 피처로 안 넣고 비교용
- ML 데이터 규칙: WAF 모드·CRS 버전·예외 파일을 실험 메타에 기록, 바꾸면 재학습. 이번 실측 바퀴는 `DetectionOnly` 권장
- `docs/28` §0·§1·§4-3-1·§4-7, `docs/26` §1·§2 에 자리 반영. **랩 미설치**(버전은 `docs/31` §9 에 설치 때 기록)

## 0000. 저장 모델로 처음 보는 공격 탐지 정리 (2026-10-26)

- **`docs/30`**: "joblib + 로그만 있으면 되나?" → 아니다. 피처 추출·구간 길이·피처셋·rel 계산·같은 sklearn이 함께 필요. 실행 경로는 `ingest.py`(권장)·수동·consumer
- `consumer.py`: AE 누락(IF·LOF만) → IF|LOF|AE, v3.1의 rel_*를 0으로 채우던 것 → 멈추고 안내
- `predict.py --block-file`: 이상 출발지를 `ML_ANOMALY srcip=` 형식으로 기록 (Active Response는 아직 미연결)
- 남은 것: 새 IP의 rel_* 기준선(self는 공격만 하는 새 IP에서 배수≈1) — `docs/27` §7·`MODEL_CARD` §7

## 000. 외부 로그 투입구 (2026-10-25)

- **`inbox/<이름>/` 에 로그를 넣고 `python ml/ingest.py inbox/<이름> [--retrain]`** — 사용법·흐름 `inbox/README.md`. 기존 스크립트를 순서대로 부르고 돌린 명령을 `out/REPORT.md` 에 남김.
- 같이 고친 것: `db_features.py` `.gz` 미지원(0행 생성), `predict.py` 빈 CSV 크래시, 다른 드라이브 폴더 경로 오류. `verify.sh` [6] 추가(11항목 PASS).
- **실시간 수집 결정(`docs/29`)**: ML PC 에 **Logstash 수신기** → `inbox/live/<출처>/<로그종류>/` (랩 VM=Filebeat, 원격 Wazuh=Fluent Bit 로 archives 복사본, 상호 TLS). 설정 `deploy/collect/`. 인증서 스크립트·mTLS 는 로컬 검증, Logstash/Filebeat/Fluent Bit 실행은 구축 때.

## 00. 피처셋 확정 + 모델 카드 + node_exporter 입구 (2026-10-25, 최신)

> 상세: `docs/27`. 모델: `models/MODEL_CARD.md`. 검증: `bash verification/verify.sh`(10항목 PASS) + 독립 코드 리뷰 14건 반영(호스트 속도 부풀림 HIGH 포함, `docs/27` §4).

- **피처셋 확정** `ml/feature_spec.py`: `web_v1`(10, 실제 정본 소거 실험으로 확정) · `db_v1`(8, 재검증 대기) · `host_v1`(12, 가설). `ssh_fail` 제외(nginx 서 분산 0).
- **운영 후보 = `models/model_web_v3.1.joblib`**: IF|LOF|AE **0.91±0.04** · LOF 0.88 · 평가 정상 오탐 0/65 (seed 10개). 모델 카드에 용도·경보 등급·한계.
- **정정 2건:** ① 기록된 0.97 은 AE seed 하나의 값 → seed 평균 0.91. ② `train_export.py` 가 IP형 정답지를 무시해 v3 번들이 **공격까지 정상으로 학습**(LOF in-sample 8/32 → 수정 후 28/32). 수정·회귀검사 추가, v3 는 archive 보관.
- **node_exporter 입구** `edge/host_metrics.py`: Prometheus API / 저장 query_range JSON / `/metrics` 스냅샷(`--collect`, Prometheus 없이) → 같은 코드로 호스트×5분 피처. 두 경로 출력 바이트 동일 확인.
- **설계 결정(합성 근거): 호스트별 기준선 LOF** — 통합 모델은 느린 유출 0/12, 호스트별 12/12(전체 25/25 vs 13/25, LOF 오탐 둘 다 4/81). 학습 기간은 계절성 1주기 이상.
- **다음:** ⓪ **`apps/shopapi/` 작성**(PHP 쇼핑몰 API, 사양 `docs/28` §4-3) + **쇼핑객 정상 트래픽 생성기** → ① Rocky VM 에 node_exporter → 24h 수집 + 통제 공격(stress-ng·scp·hping3) → host_v1 역할 확정(`docs/27` §3-5). ② 로그+지표 결합 실험(`docs/03`). ③ collector 에 `rel_*` 온라인 계산 → v3.1 승격.

## 0. 플라이휠 1차 — 완료 요약 (2026-10-25)

> 전체 서사·수치: `docs/21`(실험 A~L). 원리/편향분산/LLM한계: `docs/19`. API 설계: `docs/20`. DB phase: `docs/22`.
> 식별자/귀속 한계: `docs/25`. 개념도: `docs/23`. 운영 런북: `docs/24`. 학습: `learn/GLOSSARY.md`·`learn/ML_WALKTHROUGH.md`.

**웹 (실험 A~L):**
- **실제 로그로 H5 재현**: IF 느린공격 놓침·LOF/AE 보완(`docs/21` §F·G·L). 정본 검증 **IF|LOF|AE 0.91/오탐0.02**(§L).
- **합성 vs 실제**: 합성 1.00 포화(모델 건강=퍼뮤테이션 확인) → 실제선 **LOF 우수·IF 느린공격 취약·AE 분포민감**.
- **두꺼운 정상이 오탐 붕괴**: AE 오탐 0.88→0.00(§L). "정상이 병목+대표성이 편향 깎음" 확정. 생성기 속도 왜곡 주의(§I).
- **겹침 두 축**: 속도겹침→상대속도(UEBA `ml/relative_features.py`, §K) / 내용겹침→`endpoint_entropy`(§J). 둘 다 데이터로 채택(§E seq_id_score는 거부).
- **식별자/귀속**(`docs/25`): IP는 그룹핑키(피처 아님). NAT서 깨짐 → **실측으로 사용자키가 IP키 못잡는 공격자 3/3 탐지**(§5-2). 완전분산 low-slow만 근본갭.

**DB (`docs/22`, 착수):** 합성 바퀴서 H5 재현. 공격별 신호(BOLA=distinct_where_ids·SQLi=sqli_token_hits·scrape=q_count). 하드네거티브는 **파생 '반복도'**로 scrape 0/8→8/8. UEBA 전이. 누적 `dataset_db.csv`. 실제는 MySQL 티어 후.

**자산:** 누적 `data/dataset_web.csv`(~668행·출처 다수)·`dataset_db.csv`. 모델 버전 전부 `models/experiments/`+CHANGELOG. 자동화 `scripts/flywheel_turn.sh`(web/db). 생성기 `tools/gen_synth_log.py`·`gen_db_arc.py`·`collect_kit/target_side/`.

**다음(막힘/미래):** 실제 다환경 검증·DB 실제 MySQL·사용자키 운영 적용 = **팀 인프라 후**. 같은 랩 추가 축적은 수확체감(멈춤 권장). 재개는 `flywheel_turn.sh` 한 명령.

## 1. 지금 어디까지 왔나 (완료)

- **웹 계층 탐지**: nginx 로그 → IP×5분 피처 → IF·LOF·AE(발견) + RF(분류). 느린 BOLA를 IF는 놓치고 LOF·AE가 잡음(H5). → `docs/13` §3
- **DB 계층 탐지**: MySQL 쿼리 로그 → DB 피처(BOLA=`distinct_where_ids`, SQLi=`sqli_token_hits`). 웹과 같은 결론 재현. → `docs/13` §4
- **모델 저장/판정**: `models/model.joblib`(웹), `models/db_model.joblib`(DB) = **v2(IF+LOF+AE+RF)**. v1은 `models/archive/`. 체인지로그 `models/README.md`
- **자동화**: `consumer/`(단순), `edge/`(피처 벡터만 전송 + 중앙 collector + DB 출발지 귀속 `correlate.py`)
- **공개 데이터 교차검증**: CSIC 2010(내용 공격) → lof·AE F1 0.98. → `docs/13` §4-1
- **기록**: README(현관), `docs/01~18`, 디버깅 로그 `docs/17`, draw.io 토폴로지 `docs/18`, 재현 데모 `run_demo`
- **노션**: 종합 결과 페이지 + "ML 파트 일지" DB (「새싹 최종 프로젝트」 아래)

## 2. 다음 할 일 (우선순위)

1. **실제 MySQL 로그로 DB 모델 재검증** — 지금은 합성. 인프라 확정: **`docs/28`**(별도 DB VM 10.16.1.20 + 직접 만든 쇼핑몰 API `shopapi` + Prometheus(분석 PC) + Wazuh manager 전용). 절차: `docs/14`. 파싱 점검 `db_features.py --check`, 출발지 귀속 `correlate.py`(옵션 C→A).
2. **CSIC contamination 0.05 비교** — 오탐↓ 트레이드오프 눈으로 확인 (`--contamination 0.05`).
3. **설명가능성(XAI)** — RF 피처 중요도 + "왜 이상인가" 정리 (X-WAD 참고, `docs/16`).
4. **앱 계측 피처** — BOLA `owned_vs_self_ratio` 등 로그 밖 피처 (`docs/15` §3 갭 분석).
5. **pfSense 경계 삽입 데모** — "경계 통과 → 내부 ML 탐지" 실증 (`docs/13` §8, `docs/18` 그림2).
6. **SOAR** — 탐지 후 대응 자동화 (`docs/04`).

## 3. 열린 질문 / 결정 대기

- **DB 출발지 귀속**: 실제 환경에서 A(웹-DB 시간상관) / B(앱 계측) / C(DB 티어 단위) 중 택 → `docs/14` §4, `edge/correlate.py`.
- **모니터링 지표**: 입구 구현 완료(`edge/host_metrics.py`, `docs/27` §3). 남은 것 = 실측 + "로그만 vs 로그+지표" 결합 비교 (`docs/03`).
- **contamination 최종값**: 현재 0.05 고정. 데이터 늘면 재조정.

## 4. 환경 메모 (재현용)

- **취약 서버**: Rocky VM `10.16.1.10` — Juice Shop(127.0.0.1:3000) + nginx(80). [MySQL 티어 예정]
  - 정상 트래픽 보조 IP `10.16.1.101~106`, 공격 보조 IP `10.16.1.211~214`
- **확장 예정(`docs/28`)**: DB VM `10.16.1.20`(MySQL 8) · 웹 VM `:8080` shopapi · node_exporter 두 VM · Prometheus 분석 PC `:9090` · Wazuh manager 전용(2GB)
- **공격**: Kali VM. **ML 분석**: 호스트 PC(Windows) `10.16.1.1`. 네트워크: VMnet8 NAT `10.16.1.0/24`(GW·DNS `10.16.1.2`)
- **Python**: 로컬 3.15 + scikit-learn 1.9.1 + pandas 3.1 (검증 환경: 3.12/1.9.1)
- **데이터**: `data/`는 저장소에 포함(2026-10-25부터, 공개 CSIC `data/csic/` 포함). 생성기(`tools/`)로 재생성도 가능.

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
