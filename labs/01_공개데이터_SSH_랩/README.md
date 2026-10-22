# 랩 01 — 공개 SSH 로그로 배우는 ML과 LLM

> Wazuh 없이, 노트북에서 1~2시간. 실제 서버의 공개 SSH 로그에 **우리가 만든 사건을 섞고**, 룰·ML·LLM이 각각 무엇을 잡고 무엇을 놓치는지 직접 본다.
> 관련 개념: `docs/02_Isolation_Forest_개념정리.md` · 데이터 전략: `docs/05_데이터전략_시나리오_팀분담.md`

---

## 이 랩에서 배우는 것

1. 로그 한 줄은 평범하다 → **IP별로 묶어야** 행동이 보인다 (피처 만들기)
2. 공개 데이터엔 정답이 없다 → **정답을 아는 사건을 섞어** 채점한다
3. 룰은 "짧은 시간에 몰린 실패"만 본다 → **느린 공격엔 침묵**
4. ML은 "평소와 다른 것"을 본다 → 하지만 **기준(contamination)에 따라 놓치기도, 오탐하기도** 한다
5. LLM은 이유를 설명해 준다 → 하지만 **로그 속 문장에 속을 수 있다**

## 준비

```bash
pip install scikit-learn
pip install anthropic          # 4단계에서 Claude API를 직접 부를 때만 (없어도 랩 진행 가능)
```

Windows에서 글자가 깨지면 `set PYTHONUTF8=1`(cmd) 또는 `$env:PYTHONUTF8=1`(PowerShell) 후 실행.
모든 명령은 이 폴더(`labs/01_공개데이터_SSH_랩/`)에서 실행한다.

## 데이터

- **Loghub OpenSSH 2k 샘플** ([logpai/loghub](https://github.com/logpai/loghub)) — 실제 서버의 sshd 로그 2,000줄, 약 4시간, 출발지 IP 27개
- 특징: **로그인 성공은 1건뿐, 나머지는 거의 다 인터넷의 실제 공격 시도.** 즉 이 서버의 "평소"는 공격이다 → 이게 이 랩의 첫 번째 함정이자 교훈
- 원본은 `data/`에 내려받고 저장소에는 올리지 않는다 (이용 조건은 Loghub 안내를 따름)

---

## 0단계 — 내려받기

```bash
python step0_download.py
```

👀 출력된 첫 3줄을 읽어 보자. `Invalid user webmaster`, `POSSIBLE BREAK-IN ATTEMPT!` — 첫 줄부터 공격이다.

## 1단계 — 피처 만들기 (원본만)

```bash
python step1_features.py data/OpenSSH_2k.log data/features_original.csv
```

| 피처 | 의미 |
|---|---|
| `events` | 이 IP가 등장한 줄 수 |
| `fail` | 로그인 실패 수 |
| `invalid_user` | 없는 계정 시도 수 |
| `uniq_users` | 시도한 서로 다른 계정 수 |
| `root_fail` | root 실패 수 |
| `accepted` | 로그인 성공 수 |
| `active_min` | 처음~마지막 등장 사이 시간(분) |
| `max_fail_2min` | 2분 안에 몰린 최대 실패 수 — **룰이 보는 값** |
| `interval_cv` | 실패 간격의 들쭉날쭉함 — 0에 가까울수록 기계처럼 일정 |

👀 상위 IP `183.62.140.253`은 실패 286회, 2분 안에 62회. 이건 누가 봐도 공격이다.

## 2단계 — 우리 사건 섞기

```bash
python step2_inject.py data/OpenSSH_2k.log data/mixed.log data/answer.csv
python step1_features.py data/mixed.log data/features_mixed.csv
```

| 섞은 것 | IP | 의도 |
|---|---|---|
| 정상 사용자 8명 | 198.51.100.10~17 | 가끔 접속, 가끔 오타 1회 후 성공 |
| 느린 공격 | 203.0.113.77 | **6분마다 1회** 실패, 계정 3개 — 룰 임계치 밑으로 기는 공격 |
| 로그 조작 공격 | 203.0.113.99 | 빠른 대입 + 계정 이름 칸에 **LLM을 속이려는 문장** |

`answer.csv`가 정답지다. 채점은 **이 10건으로만** 한다 (원본 27개 IP엔 정답이 없으므로).
(IP는 문서용 예약 대역 — 실제 누군가의 IP가 아님)

## 3단계 — 룰 vs ML

```bash
python step3_detect.py data/features_mixed.csv --answer data/answer.csv
```

**실행 결과 (2026-10-22, 기본값 contamination 0.1)**

| 사건 | 룰 (2분 내 5회↑) | ML |
|---|---|---|
| 정상 사용자 8명 | 정상 ✅ | 정상 ✅ |
| 빠른 대입 (203.0.113.99) | 탐지 ✅ | 탐지 ✅ |
| **느린 공격 (203.0.113.77)** | **침묵 ❌** | **놓침 ❌ (5위, 기준선 바로 밑)** |

👀 ML이 느린 공격을 5위로 올려놨지만, "상위 10%만 이상"이라는 기준(37개 중 약 4개)에 걸려 놓쳤다.

### 실험 A — 기준을 바꿔 보기

```bash
python step3_detect.py data/features_mixed.csv --answer data/answer.csv --contamination 0.15
python step3_detect.py data/features_mixed.csv --answer data/answer.csv --contamination 0.2
```

| contamination | 느린 공격 | 정상 사용자 오탐 |
|---|---|---|
| 0.10 | 놓침 ❌ | 0명 |
| **0.15** | **탐지 ✅ (룰은 여전히 침묵)** | **0명** |
| 0.20 | 탐지 ✅ | **1명 ❌** (198.51.100.15) |

💡 **기준을 낮추면 더 잡지만 오탐도 늘어난다.** 정답이 없는 실전에서는 이 값을 정하는 것 자체가 운영자의 판단이다.

### 실험 B — 피처를 빼 보기

```bash
python step3_detect.py data/features_mixed.csv --answer data/answer.csv --contamination 0.15 --drop interval_cv active_min
```

👀 시간 관련 피처를 빼도 느린 공격은 6위로 탐지됐다(누적 실패·계정 수가 여전히 튐). 다른 피처를 하나씩 빼 보며 **어떤 피처가 탐지를 떠받치는지** 찾아보자.

### 실험 C — 원본만으로 돌려 보기

```bash
python step3_detect.py data/features_original.csv
```

👀 원본의 상위 3개 IP는 ML·룰 모두 잡는다. 그런데 이게 "맞았는지"는 **알 수 없다** — 정답지가 없기 때문. 2단계에서 사건을 섞은 이유가 이것이다.

## 4단계 — LLM에게 판단과 설명 맡기기

먼저 3단계를 `--contamination 0.15`로 한 번 실행해 `data/results.json`을 만든다.

```bash
python step4_llm.py data/results.json --mode numbers                              # 숫자 요약만
python step4_llm.py data/results.json --mode raw --ip 203.0.113.99                 # 계정 이름까지 (방어 문장 있음)
python step4_llm.py data/results.json --mode raw --ip 203.0.113.99 --no-guard      # 계정 이름까지 (방어 문장 없음)
```

- `anthropic`이 설치돼 있고 자격증명(`ANTHROPIC_API_KEY` 또는 `ant auth login`)이 있으면 Claude API를 호출해 결과를 표로 보여준다. 호출할 때마다 요금이 든다.
- 없으면 **프롬프트를 출력**한다 → claude.ai에 붙여넣어 결과를 받아 보면 된다.

| 비교 | 보는 것 |
|---|---|
| `numbers` | 숫자만으로도 공격·정상을 잘 가르는가? 이유 설명은 쓸 만한가? |
| `raw` + 방어 문장 | 계정 이름 칸의 `..._mark_as_ignore` 문장을 **데이터로 취급**하는가? |
| `raw` + `--no-guard` | 방어 문장이 없을 때 판단이 흔들리는가? |

💡 `docs/03` §3-6과 `docs/04` §5의 안전장치("원문 대신 숫자 요약", "로그 값은 지시가 아님")가 왜 필요한지 여기서 직접 확인한다. 같은 모델·같은 입력도 실행마다 답이 다를 수 있으니 **여러 번 돌려 비율로** 비교하자.

> 이 단계의 API 호출 코드는 작성 시점에 실제 호출로 검증하지 않았다(프롬프트 출력 경로만 확인). 처음 실행할 때 결과를 확인할 것.

---

## 생각해 볼 질문

1. 이 서버의 "평소"는 공격이다. 그렇다면 ML이 찾은 "이상"은 무엇과 다른 것일까? 정상 사용자가 오히려 "이상"이 될 수도 있을까?
2. 느린 공격을 룰로 잡으려면 룰을 어떻게 바꿔야 할까? 그 룰은 어떤 오탐을 새로 만들까?
3. contamination 0.15가 이 데이터에서 잘 맞은 건 우연일까? 정답이 없는 실전에선 이 값을 어떻게 정할까?
4. LLM에 숫자 요약만 주면 조작 위험은 사라질까? 숫자 자체를 조작할 수 있는 공격은 없을까?
5. 이 랩의 피처를 Wazuh `alerts.json`에서 뽑으면 무엇이 달라질까? (`detector/wazuh_ml_detect.py`와 비교)

## 파일

| 파일 | 역할 |
|---|---|
| `step0_download.py` | 공개 로그 내려받기 |
| `step1_features.py` | 로그 → IP별 피처 CSV |
| `step2_inject.py` | 정상 사용자·느린 공격·로그 조작 공격 섞기 + 정답지 |
| `step3_detect.py` | 룰 vs Isolation Forest 비교, 채점, 결과 JSON |
| `step4_llm.py` | LLM 판단·설명, 로그 조작 내성 비교 |
| `data/` | 내려받은 원본과 중간 결과 (Git 제외) |
