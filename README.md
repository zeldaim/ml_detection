# ml_detection — Wazuh 로그 위 ML 이상탐지

> Wazuh(룰 기반 SIEM)가 모은 로그를 재료로, **비지도 ML(Isolation Forest)** 로 "평소와 다른" 공격 주체를 찾는 실습 저장소.
> 다음 단계로 **룰 · ML · LLM · ML+LLM 조합**의 탐지 성능 비교 실험을 계획 중.

## 구조

```
Kali 공격 ──► Wazuh 매니저 ──► alerts.json ──► detector/wazuh_ml_detect.py ──► 🚨 이상 IP
                                                 (IP별 피처 → Isolation Forest)
```

## 처음이라면

**Wazuh 없이 노트북에서 바로** 해볼 수 있는 실습부터: [`labs/01_공개데이터_SSH_랩/`](labs/01_공개데이터_SSH_랩/README.md) — 공개 SSH 로그에 우리 사건을 섞고, 룰·ML·LLM이 각각 무엇을 잡고 놓치는지 확인한다.

## 빠른 실행

```bash
pip install -r requirements.txt

# 1) 소규모 샘플(IP 5개 → 표본 부족으로 룰 폴백 동작)
python detector/wazuh_ml_detect.py --alerts samples/sample_alerts.json --window 0

# 2) Isolation Forest 경로 확인(IP 16개: 정상 14 + 빠른 브루트포스 + 느린 공격)
python detector/wazuh_ml_detect.py --alerts samples/sample_alerts_if.json --window 0

# 3) 실제 Wazuh 매니저에서 실시간(15초마다, 최근 15분)
python3 detector/wazuh_ml_detect.py --alerts /var/ossec/logs/alerts/alerts.json --window 15 --watch 15
```

2)의 기대 결과: `10.10.99.10`(빠른 브루트포스)과 `10.10.77.7`(40초 간격 느린 공격)이 🚨 이상, 나머지 정상.
(2026-10-22 로컬 실행 확인: Python 3.12, scikit-learn 1.9.1)

## 파일

| 경로 | 내용 |
|---|---|
| `detector/wazuh_ml_detect.py` | 탐지 엔진 — alerts.json → IP별 피처 → Isolation Forest (IP 8개 미만이면 룰 폴백) |
| `samples/sample_alerts.json` | 소규모 검증 샘플 |
| `samples/sample_alerts_if.json` | Isolation Forest 경로 검증용 합성 샘플 |
| `tools/make_sample.py` | 위 합성 샘플 생성기 (`python tools/make_sample.py samples/sample_alerts_if.json`) |
| `tools/gen_normal_traffic.py` | Juice Shop 정상 트래픽 생성기 — 가상 사용자별 출발지 IP로 nginx 정상 로그를 쌓고 정상 기간 끝(UTC) 출력 (`docs/08` §8-5) |
| `tools/gen_attack_traffic.py` | Juice Shop 공격 트래픽 재현기(랩 전용) — 빠른 대입 2건·BOLA 2건을 사건별 출발지 IP로 실행하고 `answer.csv`(정답지) 자동 생성 (`docs/12` §5-3) |
| `docs/01_Wazuh_ML_실습_런북.md` | 랩 구축 런북 (Wazuh 경량화, 공격 재현, 로그 확장, 자동 차단) |
| `docs/02_Isolation_Forest_개념정리.md` | 쉬운 개념 설명, 오해 정리, 지표 추가 규칙, ML vs LLM |
| `docs/03_ML_vs_LLM_비교실험_계획.md` | 후속 실험 계획 — 룰·ML·LLM·조합 비교, 모니터링 지표·클라우드 분석, 자동 대응 LLM 도입 |
| `docs/04_SOAR_구현계획.md` | SOAR 구현 계획 — 수집·보강·판단·조치·기록 자동화, 플레이북, LLM 안전장치 |
| `docs/05_데이터전략_시나리오_팀분담.md` | 공개 데이터 + 우리 공격 데이터 결합 전략, 추천 시나리오 4개, 1인 1서버 분담·공통 형식 |
| `docs/06_기존자산_연계계획.md` | 기존 Home SOC Lab·커스텀 룰·Slack Alert Bot·엔트로피 연구를 프로젝트에 잇는 계획, 수정된 진행 순서 |
| `docs/07_쇼핑몰API_공공데이터_계획.md` | **현재 메인 컨셉** — 쇼핑몰 API 이상행위 탐지(CSIC 2010 + 직접 생성 BOLA), 2층 탐지, 항공사 챗봇 확장, 3주 일정 |
| `docs/08_테스트환경_구축순서.md` | 쇼핑몰(Juice Shop) 타겟 + Wazuh(alerts·archives) + ML 입력까지 구축 순서·체크리스트, §8 Wazuh 없이 nginx 단독 구축 |
| `docs/09_설계논의_히스토리.md` | 2026-10-22 방향 결정 Q&A 기록 (지도/비지도/LLM, 왜 ML, 전체 로그 vs Wazuh 로그 등) |
| `docs/10_7-8주차_데이터파이프라인_ML이상탐지.md` | 7~8주차 실행 계획 (`07`·`08` 기준) — alerts·archives → MySQL 정규화·인덱스/EXPLAIN·자동 적재·리포트, Z-score·IF/LOF/OCSVM·시계열, Kibana 시각화, P/R/F1 |
| `docs/11_추가조사.md` | 추가 조사 — API 보안 솔루션 종류, 룰 밖 이상행위 탐지 방법, 수집(미러링) vs 탐지 단계 구분, 추가 검토 항목 |
| `docs/12_모델선정_지도vs비지도.md` | 모델 선정 논의 — Random Forest(지도) vs 비지도(Isolation Forest + LOF) 차이, 함께 쓰는 구조, LOF가 IF의 국소 이상치 약점을 보완하는 근거(H5·H6), 타당성 입증 실험(E1~E3)·예비 결과 |
| `docs/_이전버전/` | 수정 전 문서 보관 |
| `labs/01_공개데이터_SSH_랩/` | **Wazuh 없이** 공개 SSH 로그(Loghub)로 룰·ML·LLM을 직접 비교하는 1~2시간 실습 |
| `ml/` | 행위 층 이상탐지 — Wazuh 로그 또는 nginx access.log → IP×5분 피처 → 룰·Z-score·IF·LOF·OCSVM 비교 → P/R/F1 채점 → LLM 설명 (`ml/README.md`) |

## 사용 피처

`alerts` · `rule_level_max` · `uniq_rules` · `auth_fail` · `uniq_users` · `uniq_agents` · `burst_entropy`(요청 간격 엔트로피, 낮을수록 기계적) · `dns_qcount` · `dns_name_ent`(도메인 문자 엔트로피) · `sslvpn_fail`

## 자동 수집·판정 (수동으로 로그 주지 않고)

| 방식 | 디렉토리 | 설명 |
|---|---|---|
| 단순 소비자 | `consumer/` | 한 호스트가 원본 로그를 읽어 저장모델로 반복 판정 |
| **엣지 + DB** | `edge/` | 각 호스트가 피처 벡터만 중앙 collector로 전송(원본 로그 안 나감). MySQL general log → BOLA·SQLi DB 피처 포함 |

```bash
python consumer/consumer.py --nginx <로그> --model models/model.joblib --interval 60      # 단순
python edge/collector.py --model models/model.joblib --port 8000                           # 엣지(중앙)
python edge/edge_agent.py --kind db --log <mysql log> --collector http://<중앙>:8000        # 엣지(DB 호스트)
```

## 다음 단계

- Prometheus + node_exporter로 **모니터링 지표**를 추가해 "로그만 vs 로그+지표" 비교
- 룰 · ML · LLM · ML+LLM 4방식 비교 실험 (`docs/03`)
- SOAR로 탐지 이후 대응 자동화 (`docs/04`)
- 공개 데이터로 배경 채우기 + 1인 1서버 분담 (`docs/05`)
- 7~8주차: 08 환경 로그 → MySQL 파이프라인 + 베이스라인·비지도 모델 비교·시계열과 성능 평가 (`docs/10`)
- (선택) 클라우드 환경 재현

## 주의

- 공격 재현은 **직접 통제하는 랩 환경에서만** 수행.
- 자동 차단(`--block-file`)은 오탐 시 정상 IP를 끊을 수 있음 — 랩에서만.

## 관련

- 원 프로젝트: [zeldaim/finance_secure](https://github.com/zeldaim/finance_secure) (금융권 보안사고 분석·제안서)
