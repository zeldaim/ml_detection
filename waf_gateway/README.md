# waf_gateway/ — WAF 로그 + API Gateway 로그로 "사용자 키 + IP 키" 함께 쓰기

> 작성 2026-10-27. 기존 `ml/features.py`는 **출발지 IP 하나**로만 묶는다. 이 디렉토리는 WAF 로그와 Gateway 로그를
> `request_id`로 짝지어 **사용자 ID 표와 IP 표를 따로** 만든다. 기존 파이프라인과 입력이 완전히 달라서 디렉토리를 나눴다.
> 관련: `docs/25`(식별자 한계), `docs/29` §7(Gateway 앞에 둘 때 IP 보존), `docs/31`(WAF DetectionOnly)

## 0. 정리 — 왜 이걸 만들었나

### 0-1. 지금 모델은 무엇으로 묶나
- `ml/features.py:137` `windows[(m["ip"], int(ts // win_sec * win_sec))]`. 키는 **(출발지 IP, 5분 구간)**이다.
- `ts // win_sec * win_sec`는 시각을 300초 단위로 내림한다. 13:03:27은 13:00 구간에 들어간다. 구간이 겹치지 않으므로 **텀블링 윈도우**다.
- alerts(`:155`)와 SSH(`:182`)도 같은 키를 쓴다. 웹 모델에서 IP가 아닌 키는 없다(`edge/`의 DB·호스트 표만 host 키).
- 쉬운 말: **"IP별 5분 행동 요약"**. 이 한 줄이 모델이 판단하는 샘플 1건(분석 단위)이다.

### 0-2. WAF 로그만으로는 IP가 부정확하다
- WAF는 L7 프록시다. 앞에 LB나 프록시가 있거나 FortiGate가 SNAT을 하면, 로그 첫 칸에 **중간 장비 IP 하나**만 찍힌다. 그러면 모든 요청이 한 묶음이 되어 "5분 전체 트래픽" 하나만 보게 된다.
- 해결책은 둘이다. ① 신뢰하는 프록시가 붙인 `X-Forwarded-For`로 원래 IP를 복원한다(`--trusted-proxy`). ② FortiGate SNAT을 끈다.
- WAF는 `DetectionOnly`(탐지만, 차단 안 함)로 둔다. 차단하면 공격 요청이 로그에서 사라지거나 403으로 바뀌어 "평소" 학습이 깨진다(`docs/31` §0).

### 0-3. Gateway는 "누구인지"를 안다 — 그래서 사용자로 묶을 수 있다
- API Gateway는 토큰(JWT)을 검증해 인증하고 인가한다. 그래서 요청마다 **사용자 ID**를 로그에 남길 수 있다.
- 사용자 키는 NAT 뒤 여러 사용자, IP를 바꾸는 공격자에게 강하다. 실측으로 사용자키 3/3 탐지, 오탐 0을 확인했다(`docs/25` §5-2).

### 0-4. 그런데 사용자 키만으로는 안 된다 — ID가 없는 요청

| 요청 | 사용자 ID | 들어가는 표 |
|---|---|---|
| 로그인 후 API 호출 | 있음 | 사용자 표 + IP 표 |
| 로그인 시도 자체, 401 거부, 공개 페이지 | **없음** | IP 표만 |

무차별 대입, 크리덴셜 스터핑, 스캐너는 대부분 **인증 전**에 일어난다. 그래서 **두 표를 모두** 만든다.

| 공격 | IP 표 | 사용자 표 |
|---|---|---|
| 느린 BOLA (남의 객체 열람) | NAT이면 공유 IP 전체가 걸림(누구인지 모름, 차단 시 정상 사용자까지 피해) | **정확히 그 사용자** |
| 탈취 토큰 사용 | IP가 바뀌면 흩어짐 | 그 사용자의 평소와 비교 |
| 크리덴셜 스터핑, 로그인 대입 | **잡힘** (+ `uniq_users`) | ID가 없어 **안 보임** |
| 스캐너, 로그인 전 공격 | **잡힘** | 안 보임 |

## 1. 토폴로지 가정

```
클라이언트 ─▶ FortiGate(SNAT 끔) ─▶ [LB/프록시: XFF 덧붙임] ─▶ WAF(nginx+ModSecurity, DetectionOnly) ─▶ API Gateway(토큰 검증) ─▶ 앱
                                                                 │                                        │
                                                          waf_access.log                           gw_access.jsonl
                                                          (IP·요청줄·request_id)                   (request_id·user_id·status)
```
WAF와 Gateway의 순서가 반대여도 된다. 짝짓기는 `request_id`로만 한다.

## 2. 파일

| 파일 | 역할 |
|---|---|
| `hybrid_features.py` | WAF + Gateway → `--out-user`(사용자 키) / `--out-ip`(IP 키 + `uniq_users`). 출력 형식은 `ml/features.py`와 같다 → `ml/models.py`·`evaluate.py`·`train_export.py`를 그대로 쓴다 |
| `gen_sample.py` | 합성 로그: NAT 뒤 정상 4명 + mallory(느린 BOLA), 개인 IP 사용자, 익명 구경꾼, 스터핑 IP(XFF 위조 시도). 정답지 2개 포함 |

- 피처 계산(`Window`, `add_request`, 경로 템플릿, `uniq_objects`)은 `ml/features.py`를 **import해서 재사용**한다. 피처 정의를 바꾸면 양쪽에 같이 반영된다.
- 사용자 표의 첫 열 이름은 기존 도구 호환을 위해 `ip` 그대로 두었다. **값은 사용자 ID**다.
- 사용자 ID 원문은 **키로만** 쓰고 피처에 넣지 않는다(`docs/20`, 누수 방지).

## 3. 로그 형식

### 3-1. WAF (nginx + ModSecurity) — combined 뒤에 두 칸 추가
```nginx
log_format waf '$remote_addr - - [$time_local] "$request" $status $body_bytes_sent '
               '"$http_referer" "$http_user_agent" "$http_x_forwarded_for" $request_id';
proxy_set_header X-Request-ID $request_id;   # Gateway 로 같은 id 를 넘김 → 짝짓기 키
```
- 두 칸이 없는 순수 combined도 읽는다. 다만 짝짓기가 안 되어 IP 표만 나온다.
- 앞단에서 이미 `X-Request-ID`를 붙인다면 `$request_id` 대신 `$http_x_request_id`를 쓴다.

### 3-1-1. WAF가 Apache(+ModSecurity)일 때 — 같은 칸 순서
Apache combined는 nginx combined와 칸 순서가 같다. 끝에 XFF와 요청 ID 두 칸만 덧붙이면 `hybrid_features.py`가 그대로 읽는다.

```apache
# 요청 ID: mod_unique_id 가 요청마다 UNIQUE_ID 를 만든다
LoadModule unique_id_module modules/mod_unique_id.so
RequestHeader set X-Request-ID "%{UNIQUE_ID}e"     # Gateway 로 같은 id 를 넘김 (mod_headers) → 짝짓기 키

# 방법 A (추천): mod_remoteip 가 원래 IP 를 복원 → %a 가 이미 클라이언트 IP. 이때 --trusted-proxy 는 주지 않는다
RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxy 10.16.1.2                     # 앞단 LB/프록시 IP 만 (대역 전체 금지)
LogFormat "%a - - %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"%{X-Forwarded-For}i\" %{UNIQUE_ID}e" waf
CustomLog /var/log/httpd/waf_access.log waf
HostnameLookups Off
```

```apache
# 방법 B: Apache 는 받은 그대로 기록하고, 복원은 스크립트(--trusted-proxy 10.16.1.2)가 한다
LogFormat "%{c}a - - %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" \"%{X-Forwarded-For}i\" %{UNIQUE_ID}e" waf
```

- `%t`는 `[27/Oct/2026:09:00:00 +0900]` 형식으로, nginx `$time_local`과 같다. `%b`는 0바이트일 때 `-`로 찍혀도 괜찮다.
- `%{c}a`는 직접 연결한 상대(프록시) IP, `%a`는 mod_remoteip를 적용한 뒤의 IP다. 방법 A에서 `%{c}a`를 쓰면 복원이 안 된다.
- `HostnameLookups On`이면 첫 칸에 호스트명이 찍혀 파서가 그 줄을 버린다. 그래서 반드시 Off로 둔다. Apache는 지시어 뒤에 주석을 달 수 없으니 주석은 별도 줄에 쓴다.
- Apache가 WAF가 아니라 **Gateway 역할**이라면 `docs/29` §7-3처럼 3번째 칸에 `%{X-User-Id}o`(앱 응답 헤더)를 넣는다. 그때는 그 로그 하나만으로 기존 `ml/features.py --nginx`에 넣을 수 있다.
- 확인: `curl -H 'X-Forwarded-For: 8.8.8.8' http://<서버>/` → 로그 첫 칸(방법 A) 또는 IP 표(방법 B)에 8.8.8.8이 나오지 않아야 한다.

### 3-2. Gateway — JSON lines
기본 필드는 `request_id`, `user_id`, `status`다. 이름이 다르면 `--gw-field`로 바꾼다(중첩은 점으로 표시).
```bash
# Kong (file-log / http-log 플러그인)
--gw-field request_id=request.headers.x-request-id --gw-field user_id=consumer.username --gw-field status=response.status
```
- `user_id`가 비었거나 `-`이거나 상태가 401/403이면 **미인증**으로 본다. 그 요청은 사용자 표에 넣지 않는다.
- 토큰 원문(`Authorization`)은 로그에 남기지 않는다. 사용자 ID만 남긴다(`docs/29` §7-3).

## 4. 실행

```bash
python waf_gateway/gen_sample.py --out data/waf_gw_demo
python waf_gateway/hybrid_features.py --waf data/waf_gw_demo/waf_access.log --gw data/waf_gw_demo/gw_access.jsonl \
    --trusted-proxy 10.16.1.2 --out-user data/waf_gw_demo/feat_user.csv --out-ip data/waf_gw_demo/feat_ip.csv
cd data/waf_gw_demo
for k in user ip; do
  python ../../ml/models.py feat_$k.csv --train-until 2026-10-27T03:00:00Z --methods iforest lof autoencoder \
      --contamination 0.05 --drop ssh_fail --out det_$k.csv
  python ../../ml/evaluate.py det_$k.csv --answer answer_$k.csv
done
```

## 5. 합성 데이터 결과 (2026-10-27, seed 7, scikit-learn 1.9.1)

| 표 | 정답 공격 | IF · LOF · AE | 구간 단위 F1 (IF / LOF / AE) |
|---|---|---|---|
| 사용자 | mallory (bola_slow) | 탐지 · 탐지 · 탐지 | 0.69 / 0.86 / 0.86 |
| IP | 203.0.113.10 (NAT, bola_slow) | 탐지 · 탐지 · 탐지 | 0.97 / 0.85 / 0.95 (두 공격 합산) |
| IP | 198.51.100.66 (cred_stuffing) | 탐지 · 탐지 · 탐지 | ↑ |

- **스터핑은 IP 표에서만 보인다.** 사용자 표에는 그 요청이 아예 없다(인증 전이라 ID가 없음).
- **BOLA는 두 표 모두에서 잡힌다.** 단 IP 표가 가리키는 것은 "NAT IP 전체(5명)"이고, 사용자 표가 가리키는 것은 "mallory"다. 차단·대응 단위가 다르다. 합성 데이터에서는 `uniq_objects`가 집합이라 NAT으로 합쳐도 신호가 남는다. 사용자 수가 늘면 희석된다(`docs/25` §5-2와 같은 뉘앙스).
- `--trusted-proxy`를 빼면 출발지 IP가 **1개(LB)**로 뭉치고 경고가 뜬다. 이때도 **사용자 표는 그대로**다. IP 문제의 영향을 받지 않는 것이 사용자 키의 장점이다.
- XFF 왼쪽에 위조한 `8.8.x.x`는 무시되고 진짜 IP가 복원된다(오른쪽부터 신뢰 목록 밖 첫 주소).
- 합성·소규모라 수치는 "틀 확인"용이다. 사용자 표 IP 단위 오탐 3~4/8은 정상 사용자 수가 적어서다. 실제 로그로 재검증해야 한다.

## 6. 운영 때 확인

```
[ ] WAF 로그와 Gateway 로그에 같은 request_id 가 찍힘 (실행 결과 "짝짓기 실패"가 0 근처)
[ ] IP 표의 출발지 수 ≈ 실제 접속 PC 수 (1개면 SNAT·--trusted-proxy 확인)
[ ] 위조 시험: curl -H 'X-Forwarded-For: 8.8.8.8' … → IP 표에 8.8.8.8 이 안 나옴
[ ] Gateway user_id 가 로그인 후 요청에 실제로 찍힘 (사용자 표가 비면 필드 경로 확인)
[ ] 두 표는 따로 학습·저장 (train_export.py 를 표마다) — 인증 사용자와 익명의 "평소"는 다르다
```

## 7. mitmproxy로 정답지 만들기 (랩 전용)

접근 로그는 "남의 id를 요청했다"까지만 안다. mitmproxy는 **응답 본문**까지 보므로 "실제로 남의 데이터를 받아갔다"를 확인할 수 있다. 이걸 `hybrid_features.py` 표를 채점하는 정답지로 쓴다.

| 파일 | 역할 |
|---|---|
| `mitm_label.py` | mitmproxy 애드온. 요청마다 `bola` / `own` / `auth_fail` / `normal` 라벨을 JSONL로 남긴다 |
| `mitm_answer.py` | 라벨 → `answer_user.csv`(bola, 사용자 기준) · `answer_ip.csv`(bola + 로그인 공격, IP 기준). `ml/evaluate.py` 시간 구간형 |

### 7-1. 실행
```bash
pip install mitmproxy
# 앱 앞에 리버스 프록시로. 공격·정상 트래픽은 :8081 로 보낸다
mitmdump -p 8081 --mode reverse:http://10.16.1.10:3000 -s waf_gateway/mitm_label.py --set label_out=data/mitm_labels.jsonl
python waf_gateway/mitm_answer.py data/mitm_labels.jsonl --out data/mitm_answer
python ml/evaluate.py <det_user.csv> --answer data/mitm_answer/answer_user.csv
```

### 7-2. 판정 규칙과 앱별 설정 (`--set 이름=값`)

| 라벨 | 조건 | 관련 옵션 (기본 = Juice Shop) |
|---|---|---|
| `bola` | 소유 자원 경로(`ml/features.py` `OWNED_PREFIXES`) 2xx이고, 응답 주인 ≠ 요청자 | `owner_field=data.UserId`, `user_claim=data.id`(JWT payload) |
| `own` | 같은 경로, 주인 = 요청자 | ↑ |
| `auth_fail` | 로그인 경로 401. 시도한 계정명도 남김 | `login_path=/rest/user/login`, `login_field=email` |

- `mitm_answer.py`는 같은 (출발지, 종류) 요청이 `--gap`(10분) 안에 이어지면 한 회차로 묶는다. 로그인 실패는 `--min-fails`(5) 이상만 공격으로 치고, 시도 계정이 `--stuffing-accounts`(3)개 이상이면 `cred_stuffing`, 아니면 `brute_force`로 분류한다.
- "소유 자원 판정 0건" 경고가 뜨면 `owner_field`와 `user_claim`이 앱의 응답·토큰 구조와 맞지 않는 것이다.
- 403처럼 **막힌 시도는 `bola`가 아니다**(데이터를 못 가져감). 시도 자체를 잡고 싶으면 별도 라벨이 필요하다.

### 7-3. 주의
- **랩 전용.** TLS를 복호화하는 중간자이므로 운영 경로에 끼우지 않는다(지연, 인증서 신뢰, 개인정보).
- JWT 서명은 검증하지 않는다(라벨링 목적). 위조 토큰 공격을 실험할 때는 앱 응답(401)으로 판단한다.
- 라벨 파일에는 사용자 ID와 시도 계정명이 들어간다. 커밋하지 않는다.
- 판정 로직(`label_request`)은 mitmproxy 없이 테스트할 수 있다. 가짜 flow로 own/bola/스터핑/대입/오타/깨진 JWT/403을 확인했다(2026-10-27).

## 8. 아직 안 한 것

- 로그인 실패를 **시도한 계정명**으로 묶는 세 번째 키(한 계정에 여러 IP가 대입하는 분산 공격용). Gateway가 로그인 요청의 계정명을 남겨야 한다.
- `consumer/` 실시간 판정 연결. 지금은 배치(파일 → CSV)만 된다.
- `verification/verify.sh` 회귀 검사 추가.
