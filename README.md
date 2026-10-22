# ml_detection — Wazuh 로그 위 ML 이상탐지

> Wazuh(룰 기반 SIEM)가 모은 로그를 재료로, **비지도 ML(Isolation Forest)** 로 "평소와 다른" 공격 주체를 찾는 실습 저장소.
> 다음 단계로 **룰 · ML · LLM · ML+LLM 조합**의 탐지 성능 비교 실험을 계획 중.

## 구조

```
Kali 공격 ──► Wazuh 매니저 ──► alerts.json ──► detector/wazuh_ml_detect.py ──► 🚨 이상 IP
                                                 (IP별 피처 → Isolation Forest)
```

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
| `docs/01_Wazuh_ML_실습_런북.md` | 랩 구축 런북 (Wazuh 경량화, 공격 재현, 로그 확장, 자동 차단) |
| `docs/02_Isolation_Forest_개념정리.md` | 쉬운 개념 설명, 오해 정리, 지표 추가 규칙, ML vs LLM |
| `docs/03_ML_vs_LLM_비교실험_계획.md` | 후속 실험 계획 — 모니터링 지표 추가·클라우드 확장 분석 포함 |

## 사용 피처

`alerts` · `rule_level_max` · `uniq_rules` · `auth_fail` · `uniq_users` · `uniq_agents` · `burst_entropy`(요청 간격 엔트로피, 낮을수록 기계적) · `dns_qcount` · `dns_name_ent`(도메인 문자 엔트로피) · `sslvpn_fail`

## 다음 단계

- Prometheus + node_exporter로 **모니터링 지표**를 추가해 "로그만 vs 로그+지표" 비교
- 룰 · ML · LLM · ML+LLM 4방식 비교 실험 (`docs/03`)
- (선택) 클라우드 환경 재현

## 주의

- 공격 재현은 **직접 통제하는 랩 환경에서만** 수행.
- 자동 차단(`--block-file`)은 오탐 시 정상 IP를 끊을 수 있음 — 랩에서만.

## 관련

- 원 프로젝트: [zeldaim/finance_secure](https://github.com/zeldaim/finance_secure) (금융권 보안사고 분석·제안서)
