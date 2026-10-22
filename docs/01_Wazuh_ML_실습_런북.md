# ML 이상탐지 실습 — Wazuh 로그 위에 머신러닝 한 겹

> 작성일: 2026-10-21 · 상태: 구축 가이드(실습용)
> 출처: `zeldaim/finance_secure` 저장소 `런북/ML이상탐지_실습/README.md`에서 옮김. 아래 명령의 스크립트·샘플은 이 저장소의 `detector/`, `samples/`에 있음.
> 목표: Wazuh(룰 기반 SIEM)가 모은 로그를 재료로, **비지도 ML(Isolation Forest)로
> '평소와 다른' 공격 IP를 탐지**하는 랩을 하루 안에 구축한다.
> 성격: 런북(따라 하면 재현됨) + 오늘 논의·결정 정리.

관련 제안서: `05_옆문공격`(외부 접점 탐지)·`04_통합방어`(탐지 계층). 선행 런북:
`런북/Wazuh_설치.md`(에이전트 배포), `런북/API대입공격_실습`(코드 내장 scorer).

---

## 0. 한눈에 — 오늘의 결정

| 질문 | 결정 | 이유 |
|---|---|---|
| Wazuh에서 ML이 도나? | **아니오.** Wazuh는 룰 기반. ML은 `alerts.json`을 읽어 **위에 얹음** | 역할 분리가 명확·가벼움 |
| 무거워서 걱정 | 데모엔 **manager만** 켠다(indexer·dashboard 끔) | 무거운 범인은 indexer(OpenSearch, RAM 3~4GB). ML은 파일만 읽음 |
| FortiGate 연동 | **오늘 제외**(Phase 2로) | 본 목표(ML)와 무관. 노트북 VM만으로 데모 완성 |
| FortiGate 연결에 IPsec? | **쓰지 마라** | syslog 한 줄에 사이트-투-사이트 터널은 과함 |
| DNS 로그(Sysmon) | 오늘 설치(Phase 2) | 윈도 에이전트에 Sysmon 미설치 상태 |
| LLM vs 전통 ML | **탐지는 전통 ML**, LLM은 주변(점검·문서) | 전통 ML이 빠르고 싸고 설명 가능 |

**오늘의 진짜 성공 기준**: _브루트포스 → Wazuh 탐지(이미 할 줄 앎) → 그 위에서
`wazuh_ml_detect.py`가 공격 IP를 🚨 이상치로 뽑는 스크린샷._
여기에 "체이닝 룰은 침묵, ML은 탐지"(slow 공격) 장면을 더하면 발표 분량 끝.

---

## 1. 구조

```
 Kali/Metasploit ──브루트포스/slow 공격──► Wazuh 매니저(에이전트가 로그 수집)
                                              │  /var/ossec/logs/alerts/alerts.json
                                              ▼
                              wazuh_ml_detect.py (Isolation Forest, 비지도)
                                              │  이상 IP + 피처
                                              ▼
                       (Phase 3) Active Response → iptables 자동 차단
```

- Wazuh = **보안용으로 세팅된 ELK**. manager가 로그 분석·룰 적용 후 `alerts.json` 생성.
- ML 스크립트는 그 파일을 읽어 **출발지 IP별 행동 피처 벡터**를 만들고,
  Isolation Forest로 "고립되기 쉬운(=평소와 동떨어진)" IP를 이상치로 판정.

### 피처(환경에 있는 것만 자동 사용)
`alerts`(알람수) · `rule_level_max` · `uniq_rules` · `auth_fail`(인증실패) ·
`uniq_users`(계정열거) · `uniq_agents`(다수 호스트=횡적) · `burst_entropy`(시간간격이
기계적일수록 낮음) · `dns_qcount` · `dns_name_ent`(도메인 문자 엔트로피=DGA/터널링) ·
`sslvpn_fail`(FortiGate SSL-VPN 실패).

---

## 2. Phase 1 — 코어 (오늘 반드시)

### 2-1. 가볍게: 무거운 둘 끄기
```bash
sudo systemctl stop wazuh-dashboard
sudo systemctl stop wazuh-indexer
sudo systemctl status wazuh-manager          # active (running) 확인
sudo tail -f /var/ossec/logs/alerts/alerts.json   # 로그 생성 확인
# 발표 대시보드 스크린샷 필요할 때만 다시:
# sudo systemctl start wazuh-indexer wazuh-dashboard
```
RAM: 올인원 풀가동 6~8GB → **manager만 2~3GB**.

### 2-2. 스크립트 준비 (매니저에서 한 번)
```bash
# 내장 파이썬 또는 시스템 파이썬
sudo /var/ossec/framework/python/bin/pip3 install scikit-learn || pip3 install scikit-learn
# wazuh_ml_detect.py, sample_alerts.json 을 매니저 임의 폴더로 복사(scp)
```

### 2-3. 샘플로 피처 검증 (공격 없이)
```bash
python3 wazuh_ml_detect.py --alerts sample_alerts.json --window 0
```
기대: `10.10.99.10`이 **🚨 이상**(authfail=6, users=5, hosts=2, dnsH 높음),
나머지는 정상. (샘플은 IP 5개 < 8 → **룰 폴백**으로 동작 = 정상.)

### 2-4. 진짜 공격 → 실시간 탐지
```bash
# Kali: 매니저 VM SSH를 브루트포스(타깃 VM 따로 불필요)
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<wazuh-manager-ip>

# 매니저: 실시간 ML (15초마다, 최근 15분)
python3 wazuh_ml_detect.py --alerts /var/ossec/logs/alerts/alerts.json \
    --window 15 --watch 15
```
기대: Kali IP가 🚨로, `authfail` 급상승. **IP가 8개 이상이면 자동으로
Isolation Forest 전환**(미만이면 룰 폴백).

---

## 3. Phase 2 — 로그 확장 (쌓기, 선택)

### 3-1. DNS 로그 (Sysmon, 윈도 에이전트) — "DNS 재미 지점"
```powershell
# 윈도 에이전트에서(관리자)
# 1) Sysmon 설치 + DNS 포함 설정(SwiftOnSecurity config 권장)
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```
```xml
<!-- Wazuh 윈도 에이전트 ossec.conf: Sysmon 채널 수집 -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
→ EventID 22(DnsQuery)가 `data.win.eventdata.queryName`으로 들어오고,
ML의 `dns_name_ent`(도메인 엔트로피)가 활성. Metasploit DNS 터널/C2 흔적 탐지.

### 3-2. FortiGate syslog — "SSL 재미 지점" (오늘은 보류 권장)
전제: FortiGate가 **Wazuh IP로 UDP 514 도달 가능**해야 함. **IPsec 불필요.**
- 도달성: ① FortiGate PC→Wazuh `ping` 되면 끝 ② 안 되면 같은 공유기/스위치 또는
  **랜선 직결 + 같은 /24 고정 IP** ③ 대역만 맞추는 건 L2 경로 있을 때만 유효.
```
# FortiGate CLI
config log syslogd setting
    set status enable
    set server <wazuh-ip>
    set port 514
    set format default
end
```
```xml
<!-- Wazuh 매니저 ossec.conf: syslog 수신 -->
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips><fortigate-ip>/32</allowed-ips>
</remote>
```
→ SSL-VPN/로그인 실패가 `sslvpn_fail` 피처로. (SGI 건라 사고 진입점이 SSL-VPN.)

---

## 4. Phase 3 — 자동 차단 (시간 남으면)

ML이 이상 IP를 `--block-file`에 적고, Wazuh가 그 파일을 읽어 Active Response로 차단.
```bash
python3 wazuh_ml_detect.py --alerts /var/ossec/logs/alerts/alerts.json \
    --window 15 --watch 15 --block-file /var/ossec/logs/ml_block.log
```
연계(개요): `ml_block.log` → `<localfile>`로 읽기 → 커스텀 디코더/룰(srcip 추출) →
`<active-response>`가 `firewall-drop`으로 iptables 차단. (상세는 추후 작성.)

> 주의: 자동 차단은 **오탐 시 정상 IP를 끊을 수 있음.** 랩에서만. 데모는
> "탐지까지"로 끝내도 충분하고, 차단은 스트레치 목표.

---

## 5. 발표 핵심 — 체이닝 룰 vs ML

| | 체이닝 룰 | ML(Isolation Forest) |
|---|---|---|
| 방식 | "10초 5실패→에스컬레이트"(임계치를 사람이 씀) | 임계치 없이 조합으로 판정(데이터가 학습) |
| 놓치는 것 | 임계치 밑으로 기는 slow/분산 공격 | (표본·설명 필요) |
| 메시지 | — | **"룰은 침묵, ML은 탐지"** = 신한 사고(넓게 훑는 자동화) |

데모 2컷: ① slow 공격에 체이닝 룰 무반응 ② 같은 IP를 ML이 🚨(burst_entropy 낮음 +
auth_fail 누적). 이게 이 랩의 셀링포인트.

---

## 6. 파일

| 파일 | 역할 |
|---|---|
| `wazuh_ml_detect.py` | ML 탐지 엔진(alerts.json → Isolation Forest/룰 폴백) |
| `sample_alerts.json` | 공격 없이 피처 추출 검증용 샘플 |
| `README.md` | 이 문서(계획·결정·절차) |
| `ML_vs_LLM_비교실험_계획.md` | 후속: 룰·ML·LLM·조합 탐지 비교 실험 계획 (모니터링 지표·클라우드 확장 분석 포함) |
| `active-response/` | (Phase 3) 자동 차단 스크립트 자리 |

---

## 부록 A — 개념 메모 (오늘 정리한 것)

- **Isolation Forest 원리**: 데이터를 랜덤 분할해 한 점을 '고립'시키는 데 걸리는 분할
  횟수(경로 길이). 이상치는 외딴곳이라 몇 번이면 고립(얕음)=이상 점수↑. **섀넌
  엔트로피 기반이 아님**. 거리/밀도 개념도 아님 — **"몇 번 잘라야 혼자 남나"(경로 길이)** 개념(거리 기반은 kNN·LOF). 분할도 랜덤이라 엔트로피로 최적점을 안 찾음. 쉬운 설명은 `02_Isolation_Forest_개념정리.md`.
- **엔트로피는 피처로** 들어감: 도메인 문자 엔트로피(DGA/터널링), 시간 간격 엔트로피
  (자동화일수록 낮음). Isolation Forest의 **입력 한 칸**이지 알고리즘 자체는 아님.
- **지도 vs 비지도**: 지도=정답 라벨로 학습(아는 공격만), 비지도=라벨 없이 '평소와
  다름'(신종도). 보안 탐지는 라벨이 없어 **비지도가 현실적**. 랩은 모드를 직접 만드니
  라벨도 가질 수 있어 지도(RandomForest)도 선택 가능.
- **LLM vs 전통 ML**: LLM도 ML의 한 갈래(딥러닝). 실시간 로그 탐지는 **전통 ML**이
  빠르고 싸고 설명 가능 → 탐지 심장은 전통 ML, LLM은 점검·요약 등 주변.
- **공격은 LLM, 방어 탐지는 전통 ML** — 신한 사고(ARTEX AI 멀티에이전트)의 구도.
