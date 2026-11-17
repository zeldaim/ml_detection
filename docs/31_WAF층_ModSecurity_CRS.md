# 31. WAF 층 — nginx + ModSecurity(OWASP CRS)

> 작성일: 2026-10-26 · 상태: **설계·구축 절차 확정, 랩 미설치**(설치 때 버전·결과를 이 문서에 기록)
> 배경: API 보안을 다루면서 L7 웹 방어(WAF)가 없으면 구성이 성립하지 않는다. 아는 공격(인젝션)은 WAF가 싸고 빠르게 막고, ML은 **WAF를 통과한 정상 모양 요청**에서 행위 이상을 찾는다.
> 관련: `docs/26`(층 구조·결정 로직), `docs/28`(랩 구축 — §4-3-1에서 여기로), `docs/29`(로그 수집), `docs/15`(API 공격·피처), `docs/16` §6(내용 공격 ≠ 행위 공격)

---

## 0. 결정 요약

| 무엇 | 결정 | 이유 |
|---|---|---|
| WAF | **웹 VM nginx 안에 ModSecurity v3(libmodsecurity) + nginx 커넥터 + OWASP CRS v4** | nginx가 TLS를 푼 뒤라 **HTTPS 안쪽도 평문으로** 본다 · 무료·규칙 수정 가능 · 요청 단위 감사 로그(걸린 규칙 ID까지) |
| FortiGate와 관계 | **역할 분담, 대체 아님** (§3) | FortiGate = 경계(정책·IPS·VPN). HTTP 내용 검사는 SSL deep inspection·라이선스가 전제라 랩에선 ModSecurity가 담당 |
| 적용 범위 | shopapi(:8080)·Juice Shop(:80) server 블록 둘 다 | 두 앱 모두 같은 층 구성으로 실험 |
| 시작 모드 | **`DetectionOnly`(탐지만, 차단 안 함)** → 오탐 정리 → `On`(차단) | CRS 기본값도 정상 API를 막는 오탐이 흔함. 바로 차단하면 정상 수집이 깨짐 |
| Paranoia Level | **PL1**(기본) | PL2 이상은 오탐이 급증. 올리려면 별도 바퀴로 |
| ML 데이터 | **WAF 모드·CRS 버전을 실험 메타에 기록, 바꾸면 재학습** (§6) | 차단 모드는 nginx 로그(403)·앱·DB 로그를 바꾼다 |
| WAF 결과를 ML 피처로? | **지금은 안 넣음** (§6-3) | 룰 결과를 피처로 넣으면 ML이 룰을 다시 배움 → 비교 실험이 무의미 |

## 1. WAF는 API에서 무엇을 잡고 무엇을 못 잡나

WAF는 **요청 하나의 모양**(문자열 패턴·형식·크기·빈도)을 본다. 페이로드에 흔적이 남는 공격은 잡고, **정상 요청과 모양이 같은 공격은 못 잡는다.**

### 1-1. 잘 잡는 것 (CRS 규칙 파일)

| 공격 | 예 | CRS |
|---|---|---|
| SQL Injection | `' OR 1=1--`, `UNION SELECT` | `REQUEST-942-*` (libinjection) |
| XSS | `<script>`, `onerror=` | `REQUEST-941-*` |
| 경로 조작·LFI | `../../etc/passwd` | `REQUEST-930-*` |
| 원격 명령 실행 | `; cat /etc/passwd`, `$(...)` | `REQUEST-932-*` |
| PHP 인젝션 | `php://`, 위험 함수 | `REQUEST-933-*` (shopapi가 PHP라 해당) |
| 프로토콜 위반 | 깨진 헤더, 이상한 메서드, 과대 요청 | `REQUEST-920-*`·`921-*` |

### 1-2. OWASP API Top 10 (2023) 기준

| 항목 | WAF | 누가 막나 |
|---|---|---|
| API1 **BOLA** | ❌ 요청 모양이 정상과 같음, 주인은 앱만 앎 | **앱 권한 검사**(예방) + **ML 행위 탐지**(우리) |
| API2 인증 결함 | △ 로그인 경로 빈도 제한 | 앱·게이트웨이 + ML(UEBA) |
| API3 객체 속성 권한 | △ 금지 필드(`isAdmin`) 직접 규칙 | 앱(허용 필드 목록) |
| API4 자원 소비 | △ 크기·빈도 제한 | 게이트웨이 rate limit + Prometheus 임계 |
| API5 기능 권한 | △ `/admin` 경로 IP 제한 | 앱(역할 검사) |
| API6 비즈니스 흐름 남용 | ❌ 요청마다 정상 | **ML 행위 탐지** |
| API7 SSRF | △ 내부 주소 패턴(우회 쉬움) | 앱(외부 요청 허용 목록) |
| API8 설정 오류 | △ 위험 메서드·에러 노출 일부 | 설정 점검 |
| API9 자산 관리 | △ 허용 경로 목록이 있으면 | 인벤토리·Shadow API 탐지 |
| API10 외부 API 사용 | ❌ 나가는 트래픽 | 앱 |

> **인젝션 = WAF, 권한·로직 = 앱 + ML.** 이게 이 프로젝트 층 구조의 근거다.

## 2. 층 구조

```
[인터넷/공격자]
      │
      ▼
 FortiGate ............ 경계: 정책·IPS·SSL-VPN·(차단 IP 그룹)            ← 네트워크 층
      │
      ▼
 nginx + ModSecurity(CRS) ... 요청 단위: 인젝션·프로토콜 위반 차단       ← WAF 층 (이 문서)
      │  └─ modsec_audit.log (걸린 규칙·점수)
      │  └─ access_log (통과·403 모두) ──────────────┐
      ▼                                                │
 shopapi(PHP-FPM) / Juice Shop ... 소유자 검사(BOLA 예방)  ← 앱 층
      │                                                │
      ▼                                                ▼
 MySQL(DB VM) ── db_features.py ───────────▶  ML 행위 탐지 (IF·LOF·AE + RF)   ← 행위 층
                                              BOLA·느린 수집·대입·흐름 남용
                                                       │
                                                       ▼
                                              (나중) SOAR — 고신뢰만 자동 (docs/26 §5)
```

- **WAF가 막은 요청은 앱·DB에 닿지 않는다** → nginx 접근 로그에는 403으로 남고, 앱·DB 로그에는 없다
- ML은 계속 **nginx 접근 로그**(통과 + 차단 모두)와 DB 피처를 본다. 입구는 그대로(`features.py`·`ingest.py`)

## 3. FortiGate와 역할 분담

| | FortiGate | ModSecurity |
|---|---|---|
| 위치 | 네트워크 경계 | 웹서버 바로 앞 |
| HTTPS 안쪽 | SSL deep inspection(서버 인증서 탑재·복호화 부담) 전제 | nginx가 TLS 종료 → 항상 평문 |
| HTTP 내용 검사 | IPS 시그니처·(모델·FortiOS에 따라) WAF 프로필 — FortiGuard 구독 | CRS 무료·직접 수정 |
| 로그 | 세션 단위 위주, syslog 전송 | 요청 단위, 규칙 ID·이상 점수까지 |
| 이 랩에서 맡을 것 | 경계 정책, 포트 스캔·IPS 이벤트, SSL-VPN 실패, (나중) 차단 IP 그룹 | **L7 인젝션 탐지·차단** |

- 우리 FortiGate의 모델·FortiOS 버전·라이선스로 WAF 프로필·SSL inspection이 되는지는 **장비에서 확인 필요**(미확인). 되더라도 랩에선 ModSecurity를 주 WAF로 두고 FortiGate는 경계 역할로 둔다 — 로그가 요청 단위로 남아 ML·발표에 쓰기 쉽다
- FortiGate가 SNAT를 하면 nginx에 FortiGate IP 하나만 찍힌다 → 출발지 귀속 깨짐(`docs/25`). VIP(DNAT)면 보통 원래 IP 유지. **구축 때 nginx 로그의 `$remote_addr`가 실제 클라이언트인지 먼저 확인**

## 4. 구축 (웹 VM 10.16.1.10, Rocky 9)

> 아래는 절차 초안이다. 패키지 유무·버전은 설치 시점에 확인하고 **실제 쓴 버전을 §9 기록표에 남긴다**(`docs/28`과 같은 규칙).

### 4-1. libmodsecurity + nginx 커넥터 모듈

```bash
dnf -y install epel-release
dnf -y install libmodsecurity libmodsecurity-devel   # EPEL에 없으면 ModSecurity v3 소스 빌드
nginx -v                                             # 예: nginx/1.20.1 → 아래 NGX 에 같은 버전

# 커넥터는 "지금 설치된 nginx와 같은 버전 소스"로 동적 모듈만 빌드한다
dnf -y install gcc make pcre-devel zlib-devel openssl-devel git
NGX=1.20.1
curl -LO https://nginx.org/download/nginx-$NGX.tar.gz && tar xzf nginx-$NGX.tar.gz
git clone --depth 1 https://github.com/owasp-modsecurity/ModSecurity-nginx.git
cd nginx-$NGX && ./configure --with-compat --add-dynamic-module=../ModSecurity-nginx && make modules
cp objs/ngx_http_modsecurity_module.so /usr/lib64/nginx/modules/
```
`/etc/nginx/nginx.conf` 맨 위(events 블록 밖):
```nginx
load_module modules/ngx_http_modsecurity_module.so;
```

### 4-2. 기본 설정 + CRS

```bash
mkdir -p /etc/nginx/modsec && cd /etc/nginx/modsec
# ModSecurity 권장 설정·유니코드 매핑 (ModSecurity v3 저장소의 파일)
curl -L -o modsecurity.conf https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/modsecurity.conf-recommended
curl -L -O https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/unicode.mapping
# OWASP CRS v4 — 릴리스 태그로 고정(설치 시점 최신 v4.x를 §9에 기록)
CRS=4.x.y
curl -LO https://github.com/coreruleset/coreruleset/archive/refs/tags/v$CRS.tar.gz
tar xzf v$CRS.tar.gz && mv coreruleset-$CRS crs && cp crs/crs-setup.conf.example crs/crs-setup.conf
```
`/etc/nginx/modsec/modsecurity.conf`에서 바꿀 것:
```apache
SecRuleEngine DetectionOnly          # 1단계: 탐지만 (§5에서 On으로)
SecRequestBodyAccess On              # POST/JSON 본문 검사 (API 필수)
SecAuditEngine RelevantOnly          # 규칙에 걸린 요청만 감사 로그
SecAuditLogFormat JSON
SecAuditLogType Serial
SecAuditLog /var/log/nginx/modsec_audit.log
```
- 권장 설정에는 `Content-Type: application/json`이면 JSON 본문 처리기를 켜는 규칙이 들어 있다 → **지우지 않는다**(지우면 JSON 본문 안의 SQLi를 못 봄)

`/etc/nginx/modsec/main.conf`:
```apache
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/nginx/modsec/crs/crs-setup.conf
Include /etc/nginx/modsec/local-exclusions-before.conf   # §5 예외(규칙 앞)
Include /etc/nginx/modsec/crs/rules/*.conf
Include /etc/nginx/modsec/local-exclusions-after.conf    # §5 예외(규칙 뒤)
```
```bash
touch /etc/nginx/modsec/local-exclusions-before.conf /etc/nginx/modsec/local-exclusions-after.conf
```

### 4-3. server 블록에 켜기

`docs/28` §4-3의 shopapi server와 Juice Shop server 둘 다:
```nginx
server {
    listen 8080;
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;
    # ... 기존 root·access_log·location 그대로 (docs/28 §4-3)
}
```
```bash
nginx -t && systemctl reload nginx
# 동작 확인: SQLi 흉내 → DetectionOnly 라 200 이지만 감사 로그에 942 규칙이 찍혀야 함
curl -s -o /dev/null -w "%{http_code}\n" "http://10.16.1.10:8080/api/search?q=1'%20OR%201=1--"   # docs/28 §4-3 의 의도된 SQLi 지점
grep -o '"ruleId":"942[0-9]*"' /var/log/nginx/modsec_audit.log | sort | uniq -c
```
- SELinux: 감사 로그 파일 쓰기가 막히면 `ausearch -m avc -ts recent`로 확인하고 nginx 로그 디렉터리(`/var/log/nginx/`) 안에 둔다(위 경로가 그 이유)
- 메모리: 웹 VM 예산 2~2.5GB(`docs/28` §2). CRS 적재 후 nginx 워커 메모리를 `ps -o rss -C nginx`로 기록. 부족하면 웹 VM을 2.5GB로

## 5. 운영 단계 — 탐지 → 예외 → 차단

| 단계 | 모드 | 기간 | 하는 일 | 완료 기준 |
|---|---|---|---|---|
| A | `DetectionOnly` | 정상 수집 기간 내내 (`docs/24`, 1~3일+) | 정상 트래픽만 흘리고 감사 로그 수집 | 정상 요청에서 걸린 규칙 목록 확보 |
| B | `DetectionOnly` | 반나절 | 오탐 규칙을 **경로·파라미터 단위**로 예외 처리 | 정상 트래픽 재생 시 이상 점수 ≥ 5 요청 0건 |
| C | `On` | 실험 바퀴 | 차단 모드에서 공격 시나리오 실행 | 인젝션 403, 정상 200 |

예외는 **규칙을 통째로 끄지 말고 좁게**:
```apache
# local-exclusions-before.conf — 형식 예시: <경로>의 <파라미터>에서만 <규칙ID> 제외 (실제 값은 §5 A의 오탐 목록에서)
SecRule REQUEST_URI "@beginsWith /api/<오탐난 경로>" \
    "id:1001,phase:1,pass,nolog,ctl:ruleRemoveTargetById=<규칙ID>;ARGS:<파라미터>"
```
- **의도된 SQLi 지점 `/api/search`의 `q`는 예외 처리하지 않는다** — 그게 "WAF가 막는 것" 데모다(§7)
- 예외마다 **이유·근거 요청**을 §9 표에 적는다 (나중에 "WAF를 일부러 약하게 했나?"라는 질문에 답하려고)
- Juice Shop은 Angular 프론트 정적 파일·JSON이 많아 오탐이 shopapi보다 많을 수 있다 — 앱별로 따로 정리

## 6. ML 데이터에 미치는 영향 (중요)

### 6-1. 모드별로 로그가 달라진다

| 모드 | nginx 접근 로그 | 앱·DB 로그 | ML 피처 |
|---|---|---|---|
| WAF 없음 / `DetectionOnly` | 공격 요청도 원래 상태 코드 | 공격이 앱·DB까지 감 | **기존 데이터·모델과 같은 조건** |
| `On`(차단) | 막힌 요청은 **403** | 막힌 요청은 **없음** | `err_ratio`↑, `distinct_where_ids`·`sqli_token_hits`↓ 등 분포가 바뀜 |

### 6-2. 규칙
- **정상 수집·공격 실험·평가는 같은 WAF 모드·같은 CRS 버전·같은 예외 파일로.** 하나라도 바꾸면 그 바퀴는 별도 데이터셋이고 **재학습**한다
- 실험 메타(`inbox/<이름>/meta.json` 또는 수집 기록)에 남긴다: `waf_mode`(none/detect/block) · `crs_version` · `paranoia` · 예외 파일 해시
- **이번 실측 바퀴 권장 = `DetectionOnly`**: ML 입력이 WAF 없음과 같아서 v3.1·기존 결과와 그대로 비교할 수 있고, 동시에 "WAF가 무엇을 탐지했나" 기록이 쌓인다. 차단 모드 바퀴는 그다음에 따로

### 6-3. WAF 결과를 ML 피처로 넣지 않는 이유
- 감사 로그로 `waf_hits`(IP×구간 규칙 적중 수)를 만들 수는 있다. 하지만 넣으면 ML이 **CRS가 이미 아는 것**을 다시 배운다 → "룰이 놓친 것을 ML이 잡나"(`docs/26` §0 원칙 3)를 측정할 수 없게 된다
- 대신 **비교용 열**로 쓴다: 각 공격 구간에 대해 "WAF 탐지 여부 / ML 탐지 여부"를 나란히 놓는다 (§7). 피처화는 비교가 끝난 뒤 별도 실험으로(미구현)

### 6-4. 감사 로그 수집
- ML 입력은 아니지만 비교표와 발표에 필요하다 → Filebeat에 입력 하나 추가(`deploy/collect/filebeat/filebeat-lab-web.yml`, `log_type: modsec`) → `inbox/live/lab/modsec/` (`docs/29` §3 구조)
- `ml/ingest.py`는 이 형식을 모른다 → "⚠ 안 씀"으로 표시되는 게 정상. 비교표는 감사 로그에서 `ruleId`·`client_ip`·시각만 뽑아 만든다(스크립트 미작성)
- 감사 로그에는 **요청 본문 원문**이 들어간다(비밀번호·개인정보 가능). 저장소에 커밋하지 않고(`inbox/`는 git 제외), 실험 후 정리한다

## 7. 발표 데모 — "WAF가 막는 것 / 통과하는 것"

같은 시간대에 섞어서 실행하고 표로 보여 준다. **아래 '기대'는 설계상 예상이며 실측 전이다.**

| 시나리오 | 예 | 기대: WAF | 기대: ML | 메시지 |
|---|---|---|---|---|
| SQLi | `/api/search?q=1' UNION SELECT ...` | **탐지/차단**(942) | 피처상 약함(웹 행위 피처는 내용을 안 봄) | 아는 패턴은 WAF가 싸고 빠름 |
| XSS·LFI | `<script>`, `../` | 탐지/차단(941·930) | — | 같음 |
| **BOLA (빠름)** | `/api/orders/{1..200}` 순회 | **통과** | 탐지(`uniq_objects`·`err_ratio`) | WAF 사각지대 |
| **BOLA (느림)** | 40초 간격 순회 | **통과** | LOF·AE 탐지, IF 놓침(H5) | 행위 ML이 필요한 이유 |
| 대량 수집 | 정상 경로 반복 조회 | 통과(빈도 규칙 없으면) | 탐지 | 비즈니스 흐름 남용(API6) |

- 정답지는 지금처럼 통제 공격의 **사실**(출발지·시각)로 만든다(`docs/26` §3). WAF 결과는 감사 로그에서 따로 채운다
- 앱 권한 검사를 완벽히 넣으면 BOLA가 403으로 끝나 데모가 안 된다 → shopapi 사양(`docs/28` §4-3)에서 이미 `GET /api/orders/{id}`·`/api/addresses/{id}`·`/api/users/{id}`는 **소유자 확인 없음(의도적, 랩 전용)**, `/api/search`는 의도된 SQLi로 정해 두었다
- 차단 모드(`On`)에선 `/api/search` SQLi가 WAF에서 끝나 DB의 `sqli_token_hits`가 사라진다 → "WAF 있음/없음"에서 DB 피처가 어떻게 달라지는지도 비교 대상(§6-1)

## 8. 구축 체크리스트

```
[ ] nginx -V 로 버전 확인 → 같은 버전 소스로 커넥터 빌드, load_module 후 nginx -t 통과
[ ] modsecurity on: shopapi(:8080)·Juice Shop(:80) server 블록 둘 다
[ ] SecRuleEngine DetectionOnly · SecRequestBodyAccess On · 감사 로그 JSON
[ ] SQLi 흉내 curl → 감사 로그에 942xxx 적중 (DetectionOnly라 응답은 200)
[ ] JSON 본문 SQLi(POST) → 감사 로그 적중 (JSON 처리기 동작 확인)
[ ] nginx 접근 로그의 $remote_addr = 실제 클라이언트 IP (FortiGate SNAT 여부)
[ ] 정상 트래픽 생성기 1시간 → 정상 요청의 오탐 규칙 목록 정리(§5 B)
[ ] 웹 VM 메모리: nginx RSS 기록, 여유 확인
[ ] 실험 메타에 waf_mode·crs_version·paranoia 기록
```

## 9. 기록 (설치 때 채움)

| 항목 | 값 |
|---|---|
| nginx 버전 | (미설치) |
| libmodsecurity 버전 | |
| ModSecurity-nginx 커밋 | |
| CRS 버전 | |
| Paranoia Level | 1 |
| 예외 규칙 (ID·대상·이유) | |
| 웹 VM nginx RSS (WAF 전/후) | |
