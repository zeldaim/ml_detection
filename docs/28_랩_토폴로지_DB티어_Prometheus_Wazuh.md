# 28. 랩 확장 런북 — DB 티어 VM + Prometheus + Wazuh(manager 전용)

> 작성 2026-10-25. **다음 실측 바퀴의 인프라 기준 문서.** 웹/DB 로그 · 호스트 지표 · Wazuh 경보를 한 번에 수집하고,
> 나중에 Shuffle(SOAR)을 붙일 자리까지 잡아 둔다.
> 관련: `docs/14`(DB 재검증 절차), `docs/27` §3(호스트 지표 입구), `docs/26`(신호별 결정 로직), `docs/08`(기존 랩).

## 0. 결정 요약

| 무엇 | 결정 | 이유 |
|---|---|---|
| PHP 앱 | **직접 만든 작은 쇼핑몰 API `shopapi`**(DVWA 아님, §4-3) | 시나리오("PHP/MySQL 쇼핑몰 API") 그대로 · 소유 자원 경로/테이블이 기존 피처(`uniq_objects`·`distinct_where_ids`)와 맞음 · 쇼핑객 정상 흐름을 생성기로 재현 가능 |
| MySQL | **별도 DB VM `10.16.1.20`** | 웹·DB 호스트 지표가 따로 나와야 호스트별 모델(`docs/27` §3-4)이 성립. 실제 티어 분리와 같은 귀속 문제도 재현 |
| Prometheus | **분석 PC(Windows 호스트 `10.16.1.1`)에 직접 설치** | 공격 대상 밖(VM 과부하에도 기록 생존) · ML 과 같은 자리 · VM 추가 메모리 0 |
| Wazuh | **기존 VM 을 manager 전용으로**(indexer·dashboard 끔), RAM 2GB | Shuffle 연동은 manager 의 `wazuh-integratord` 가 직접 한다(인덱서 불필요). ML 은 `archives.json` 파일을 읽음 |
| MySQL general log | **Wazuh 로 보내지 않음.** DB VM 안에서 `db_features.py` 로 숫자만 | 쿼리 원문 = 개인정보(`edge/` 원칙) · 여러 줄 쿼리 쪼개짐 · 양 |
| Shuffle | **이번 바퀴엔 안 띄움.** 연동 지점만 정해 둠(§6) | 자체 OpenSearch 로 무거움. 메모리 예산 밖 |
| WAF | **웹 VM nginx 에 ModSecurity + OWASP CRS, `DetectionOnly` 로 시작**(§4-3-1, `docs/31`) | API 보안 구성에 L7 방어 층 필요 · 인젝션은 WAF, BOLA·흐름 남용은 앱+ML · 탐지 전용이면 ML 입력이 기존과 같음 |

## 1. 토폴로지

```
                    (VMnet8 NAT 10.16.1.0/24, GW·DNS 10.16.1.2)

[Kali]  공격자 ──── HTTP ────▶ [웹 VM 10.16.1.10]  Rocky 9
                                 nginx :80   → Juice Shop (127.0.0.1:3000)
                                 nginx :8080 → shopapi (PHP-FPM, 직접 만든 쇼핑몰 API)
                                 └ 두 server 모두 ModSecurity(CRS) — WAF 층 (docs/31)
                                 node_exporter :9100 · Wazuh 에이전트
                                        │ 3306 (웹 VM 에서만 허용)
                                        ▼
                               [DB VM 10.16.1.20]  Rocky 9 최소
                                 MySQL 8 (general log: 실험 기간만)
                                 db_features.py (원문은 VM 밖으로 안 나감)
                                 node_exporter :9100 · Wazuh 에이전트

[Wazuh VM]  manager 전용 — 1514/1515 수신 → alerts.json · archives.json
                         └─(나중) integratord ─▶ Shuffle 웹훅

[분석 PC 10.16.1.1]  Prometheus :9090 ── 15초마다 10.16.1.10/20:9100 수집
                     ML: features.py · db_features 결과 · host_metrics.py → 학습/판정
                     └─(나중) Alertmanager · collector ─▶ Shuffle 웹훅
```

| 머신 | IP | 보조 IP (트래픽 연출) |
|---|---|---|
| 웹 VM | 10.16.1.10 | — |
| DB VM | **10.16.1.20** (새로) | — (합성 생성기의 db01 과 같은 주소 → 합성/실측 비교 쉬움) |
| 정상 트래픽 | 웹 VM 보조 IP 10.16.1.101~106 | 기존(`docs/08` §8) |
| 공격 | Kali 보조 IP 10.16.1.211~228 | 기존 |
| Wazuh VM | 기존 주소(아래 `<WAZUH_IP>`) | — |

## 2. 메모리 예산 (호스트 16GB)

| 머신 | 할당 | 비고 |
|---|---|---|
| Windows 호스트 | ~4GB | OS + Prometheus(수백 MB) + 파이썬 ML |
| 웹 VM | 2~2.5GB | nginx·Juice Shop·PHP-FPM(shopapi)·에이전트 |
| DB VM | 1.5GB | MySQL 8 은 `innodb_buffer_pool_size=256M` 로 줄여 둔다 |
| Wazuh VM | **2GB** (기존 6GB+ → 축소) | manager 만 |
| Kali | 2GB | |
| **합계** | **~12GB** | 여유 ~4GB. Shuffle 은 이 여유로 부족(§6) |

> 이전 장애(인덱서 메모리 부족으로 Wazuh 포트 전부 닫힘, `docs/08` §8)의 원인을 구조적으로 없앤다.

## 3. 데이터 흐름 — 무엇이 어디로

| 신호 | 출처 | 수송 | 받는 곳 | 쓰임 |
|---|---|---|---|---|
| nginx 액세스 로그(Juice Shop·shopapi) | 웹 VM | Wazuh 에이전트 → manager | `archives.json` | `ml/features.py --archives` (또는 `--nginx` 로 파일 직접) |
| MySQL general log | DB VM | **수송 안 함** | DB VM 안 `db_features.py` | DB 피처 CSV 만 가져옴(숫자) |
| MySQL error log·인증 실패 | DB VM | Wazuh 에이전트 | manager 룰 | 룰 경보 → (나중) Shuffle |
| sshd·시스템 로그 | 두 VM | Wazuh 에이전트 | manager | `ssh_fail`(archives) · 룰 |
| 호스트 지표 | 두 VM node_exporter | Prometheus 수집(pull) | 분석 PC | `edge/host_metrics.py --prom` |

## 4. 구축 순서

### 4-1. Wazuh VM → manager 전용 (기존 Docker 4.9.0 single-node)
```bash
cd ~/wazuh-docker/single-node                 # 기존 compose 디렉터리
docker compose stop wazuh.dashboard wazuh.indexer
docker compose up -d wazuh.manager            # manager 만
docker compose ps                              # manager Up 확인
ss -lntp | grep -E '1514|1515'                 # 에이전트 수신 포트 열림 확인
```
- manager 컨테이너 안 filebeat 가 인덱서 접속 실패 로그를 남기지만 **수집·룰·archives 에는 영향 없음**(정상).
- 전체 로그 저장 켜기(`docs/08` §2-4): manager `ossec.conf` 의 `<global>` 에 `<logall_json>yes</logall_json>` → 재시작.
- VMware 에서 이 VM 의 메모리를 **2GB** 로 줄인다(끈 상태에서 설정).
- 대시보드가 필요할 때(발표)만 `docker compose start wazuh.indexer wazuh.dashboard` — 그때는 Kali 등을 끄고 메모리 확보.

### 4-2. DB VM 만들기 (10.16.1.20)
```bash
# Rocky 9 최소 설치, vCPU 1~2, RAM 1.5GB, 디스크 20GB
nmcli con mod ens160 ipv4.method manual ipv4.addresses 10.16.1.20/24 ipv4.gateway 10.16.1.2 ipv4.dns 10.16.1.2
nmcli con up ens160
dnf -y install mysql-server
cat >> /etc/my.cnf.d/mysql-server.cnf <<'EOF'
innodb_buffer_pool_size = 256M
bind-address = 10.16.1.20
EOF
systemctl enable --now mysqld

mysql -uroot <<'EOF'
CREATE DATABASE shop;
CREATE USER 'app'@'10.16.1.10' IDENTIFIED BY 'labpass';
GRANT SELECT, INSERT, UPDATE, DELETE ON shop.* TO 'app'@'10.16.1.10';
EOF

# 3306 은 웹 VM 에서만 (Kali 직접 접속 차단 = "웹을 거쳐 DB" 시나리오 유지)
firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=10.16.1.10 port port=3306 protocol=tcp accept'
firewall-cmd --reload
```
- 확인: 웹 VM 에서 `mysql -h 10.16.1.20 -uapp -p` 성공, **Kali 에서는 실패해야 정상**.

### 4-3. 웹 VM 에 쇼핑몰 API `shopapi` (직접 제작) — DB 는 DB VM 으로

> **상태: 사양 확정, 코드 미작성**(다음 작업). 코드는 저장소 `apps/shopapi/`(PHP 파일 몇 개 + `schema.sql` + `seed.sql`)에 둔다.
> 왜 DVWA 가 아닌가: DVWA 는 취약점 연습 페이지 모음이라 주문·장바구니·REST API 가 없어 BOLA 피처가 맞지 않고, 현실적 정상 흐름이 없다.

**스키마** — 테이블 이름을 `edge/db_features.py` 의 `OWNED_TABLES` 와 맞춘다(소유 자원만 `distinct_where_ids` 로 셈):

| 테이블 | 소유? | 주요 열 |
|---|---|---|
| `users` | 소유 | id, email, password_hash, name, role(`customer`/`admin`) |
| `products` · `reviews` | **공개** | id, name, price, category, stock / id, product_id, user_id, body |
| `orders` | 소유 | id, user_id, total, status, created_at |
| `addresses` | 소유 | id, user_id, line1, city |
| `baskets` | 소유 | id, user_id, product_id, qty |
| `payments` | 소유 | id, order_id, card_last4 |
| `sessions` | — | token, user_id, expires_at |

시드: 사용자 200명·상품 300개·주문 2,000건(사용자당 0~20) — 열거 공격이 "남의 것"을 충분히 밟도록.

**엔드포인트**(JSON, `Authorization: Bearer <token>`) — 취약점은 **의도적으로, 표시된 곳에만**:

| 메서드·경로 | 정상 역할 | 의도한 취약점 → 공격 클래스 | 기대 신호 |
|---|---|---|---|
| `POST /api/login` | 로그인 | 시도 제한 없음 → 대입·크리덴셜 스터핑(API2) | `err_ratio`·`max_req_1min`, DB 인증 쿼리 수 |
| `GET /api/products?page=` · `/api/products/{id}` · `/{id}/reviews` | 상품 탐색(공개) | — (정상 트래픽의 몸통) | 공개라 `uniq_objects` 에 안 셈 |
| `GET /api/search?q=` | 검색 | `q` 를 문자열로 이어붙인 `LIKE` → **SQLi** | `sqli_token_hits` |
| `GET /api/products?limit=` | 목록 | 상한 없음 → 과다 노출·대량 수집(API3) | `q_count`·`req_count` |
| `GET /api/orders` · `POST /api/orders` | 내 주문·결제 | — | `write_ratio` |
| **`GET /api/orders/{id}`** | 주문 상세 | **소유자 확인 없음 → BOLA(API1)** | `uniq_objects`·`distinct_where_ids` |
| **`GET /api/addresses/{id}`** · **`/api/users/{id}`** | 내 정보 | 소유자 확인 없음 → BOLA·사용자 열거 | 같음 |
| `GET/POST/DELETE /api/basket/items` | 장바구니 | — | |
| **`GET /api/admin/users`** · **`DELETE /api/admin/users/{id}`** | 관리자 | **역할 확인 없음 → BFLA(API5)** | `write_ratio`(DELETE). 관리 경로 전용 피처는 아직 없음 → **현재 피처로 잡히는지가 측정 대상**(정본엔 BFLA 가 없어 `write_ratio` 가 '커버리지', `docs/27` §2) |

구현 규칙:
- DB 접근은 PDO, **SQLi 지점(`/api/search`)만 문자열 연결**, 나머지는 바인딩. PDO 기본(에뮬레이트 prepare)이면 general log 에 값이 들어간 `Query` 줄로 남는다(`db_features.py` 가 읽는 형태, `Execute` 도 처리됨).
- 응답 헤더 `X-User-Id: <id>` 를 붙인다 → nginx 가 **combined 의 `remote_user` 칸**에 기록 → `ml/features.py` 정규식 그대로 + 사용자 키 실험(`docs/25` §5-2) 가능.
- 귀속 옵션 B(`docs/14` §4)용 스위치: 환경변수 `SHOP_SQL_COMMENT_UID=1` 이면 모든 쿼리 앞에 `/* uid=<id> */`. 기본은 끔(실제 앱 조건 재현).
- `--owned-path` 로 웹 피처의 소유 경로를 이 앱에 맞춘다:
  `--owned-path /api/orders/{id} --owned-path /api/addresses/{id} --owned-path /api/users/{id}`
  ⚠ 분석 PC 의 **Git Bash** 는 `/api/...` 인자를 `C:/Program Files/Git/api/...` 로 바꿔 `uniq_objects` 가 0 이 된다 → `MSYS_NO_PATHCONV=1 python ml/features.py …` 또는 PowerShell 에서 실행(`features.py` 가 이 경우 오류로 멈춤).
  로그 형식 호환은 확인함: 2번째 칸에 사용자 id(비로그인은 `-`)가 있는 줄을 기존 파서가 그대로 읽고, `/api/orders/{id}` 열거가 `uniq_objects` 로 세어짐.

**배포**(Docker 없이 PHP-FPM — 웹 VM 메모리 절약):
```bash
dnf -y install php-fpm php-mysqlnd php-json
mkdir -p /var/www/shopapi && cp -r apps/shopapi/* /var/www/shopapi/
# DB 연결 정보는 /etc/php-fpm.d/www.conf 의 env 로
cat >> /etc/php-fpm.d/www.conf <<'EOF'
env[SHOP_DB_HOST] = 10.16.1.20
env[SHOP_DB_NAME] = shop
env[SHOP_DB_USER] = app
env[SHOP_DB_PASS] = labpass
EOF
systemctl enable --now php-fpm
mysql -h 10.16.1.20 -uroot -p shop < apps/shopapi/schema.sql     # DB VM 에서 실행해도 됨
mysql -h 10.16.1.20 -uroot -p shop < apps/shopapi/seed.sql
```
```nginx
# /etc/nginx/conf.d/shopapi.conf
log_format shop '$remote_addr - $upstream_http_x_user_id [$time_local] "$request" '
                '$status $body_bytes_sent "$http_referer" "$http_user_agent"';
server {
    listen 8080;
    root /var/www/shopapi/public;
    access_log /var/log/nginx/shopapi_access.log shop;
    location / { try_files $uri /index.php$is_args$args; }
    location = /index.php {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root/index.php;
        fastcgi_pass unix:/run/php-fpm/www.sock;
    }
}
```
```bash
setsebool -P httpd_can_network_connect_db 1   # SELinux: PHP-FPM → 원격 MySQL 허용
firewall-cmd --permanent --add-port=8080/tcp && firewall-cmd --reload
nginx -t && systemctl reload nginx
curl -s http://10.16.1.10:8080/api/products | head -c 200    # 확인
```

### 4-3-1. WAF — nginx + ModSecurity(OWASP CRS)

절차·설정·운영 단계는 **`docs/31`** (§4 구축, §5 탐지→예외→차단, §8 체크리스트). 이 런북에서 지킬 것만:
- shopapi·Juice Shop server 블록 **둘 다** `modsecurity on`. 처음엔 **`SecRuleEngine DetectionOnly`**
- 정상 수집·공격 실험·평가 동안 **WAF 모드·CRS 버전·예외 파일을 바꾸지 않는다**(바꾸면 재학습, `docs/31` §6)
- 의도된 SQLi 지점 `/api/search?q=` 는 예외 처리하지 않는다 (WAF가 막는 것 데모)
- 웹 VM 메모리: CRS 적재 후 nginx RSS 기록, 부족하면 2.5GB

### 4-4. node_exporter — 웹 VM·DB VM 둘 다
```bash
VER=1.8.2   # 설치 시점의 릴리스로 고정하고 이 문서에 기록
curl -LO https://github.com/prometheus/node_exporter/releases/download/v$VER/node_exporter-$VER.linux-amd64.tar.gz
tar xzf node_exporter-$VER.linux-amd64.tar.gz && cp node_exporter-$VER.linux-amd64/node_exporter /usr/local/bin/
useradd -rs /sbin/nologin node_exporter
cat > /etc/systemd/system/node_exporter.service <<'EOF'
[Unit]
Description=node_exporter
After=network-online.target
[Service]
User=node_exporter
ExecStart=/usr/local/bin/node_exporter
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now node_exporter
# 9100 은 분석 PC 에서만
firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=10.16.1.1 port port=9100 protocol=tcp accept'
firewall-cmd --reload
```
- 확인(분석 PC, PowerShell): `curl.exe -s http://10.16.1.10:9100/metrics | findstr node_cpu_seconds_total` (`curl` 만 쓰면 PowerShell 별칭이 잡힘).

### 4-5. Wazuh 에이전트 — 두 VM
```bash
# 매니저 버전(4.9.0)과 같은 에이전트
WAZUH_MANAGER='<WAZUH_IP>' WAZUH_AGENT_NAME='web01' dnf -y install https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.0-1.x86_64.rpm   # DB VM 은 db01
systemctl enable --now wazuh-agent
```
`/var/ossec/etc/ossec.conf` 수집 대상:
```xml
<!-- 웹 VM -->
<localfile><log_format>syslog</log_format><location>/var/log/nginx/juiceshop_access.log</location></localfile>
<localfile><log_format>syslog</log_format><location>/var/log/nginx/shopapi_access.log</location></localfile>
<!-- DB VM: error log 만. general log 는 넣지 않는다(§3) -->
<localfile><log_format>syslog</log_format><location>/var/log/mysql/mysqld.log</location></localfile>
```
- 확인: manager 의 `archives.json` 에 `/api/` 요청 줄이 들어오는지 `grep -c '/api/' archives.json`.

### 4-6. Prometheus — 분석 PC(Windows)
```
1) prometheus-<버전>.windows-amd64.zip 을 C:\prometheus 에 풀기 (버전 기록)
2) C:\prometheus\prometheus.yml:
```
```yaml
global:
  scrape_interval: 15s            # host_metrics.py --step 15s 와 같게 (다르면 --step 을 맞출 것)
scrape_configs:
  - job_name: node
    static_configs:
      - targets: ['10.16.1.10:9100', '10.16.1.20:9100']
```
```powershell
cd C:\prometheus
.\prometheus.exe --config.file=prometheus.yml --storage.tsdb.retention.time=15d
# 확인: http://localhost:9090/targets  → 두 대 모두 UP
```
- 데이터 디렉터리(`C:\prometheus\data`)는 저장소 밖. 실험 끝나면 필요한 구간만 `host_metrics.py --prom` 으로 CSV 화.

### 4-7. 구축 체크리스트
```
[ ] Wazuh: manager 만 Up, 1514/1515 열림, logall_json=yes, VM 2GB
[ ] DB VM: mysqld 동작, 웹 VM→3306 성공 / Kali→3306 실패
[ ] shopapi: schema·seed 적재, /api/products 응답, 로그인 후 shopapi_access.log 의 2번째 칸에 사용자 id 기록
[ ] WAF: 두 server modsecurity on(DetectionOnly), /api/search SQLi 흉내 → modsec_audit.log 에 942xxx (docs/31 §8)
[ ] node_exporter: 두 VM, 분석 PC 에서 :9100/metrics 응답 / 다른 곳에선 차단
[ ] Wazuh 에이전트: 두 VM Active, archives.json 에 nginx 줄 유입
[ ] Prometheus: targets 2개 UP
[ ] 시계: 모든 VM chrony 동기화(정답지 시각·5분 구간 정렬의 전제) — `chronyc tracking`
```

## 5. 실측 바퀴 진행

1. **정상 24시간 이상**(계절성 한 주기, `docs/27` §3-4): Juice Shop 정상 생성기(`tools/gen_normal_traffic.py`) + shopapi 쇼핑객 생성기.
   ⚠ shopapi 용 정상 생성기는 아직 없음 — 시드 사용자로 로그인 → 상품 탐색·검색 → 장바구니 → 결제 → **자기** 주문·주소 조회 흐름(다음 작업).
2. **MySQL general log 는 실험 기간만 ON**(`docs/14` §2). 디스크 확인.
3. **통제 공격 + 정답지**(`attack_id,src,start,end,type`, UTC):

| 계층 | 공격 | 하는 곳 | 기대 신호 |
|---|---|---|---|
| 웹/DB | SQLi (`/api/search?q=`) | Kali(.21x) | `sqli_token_hits`↑ |
| 웹/DB | BOLA: `/api/orders/{id}` 열거(빠름·느림 둘 다) | Kali | `uniq_objects`·`distinct_where_ids`↑ |
| 웹/DB | 대입: `/api/login` 연속 실패 | Kali | `err_ratio`·`max_req_1min`↑ |
| 웹/DB | 대량 수집: `/api/products?limit=99999` | Kali | `q_count`·`req_count`↑ |
| 웹/DB | BFLA: 일반 계정으로 `/api/admin/users` 조회·삭제 | Kali | 현재 피처로 잡히나 측정 |
| 호스트 | 채굴 흉내 `stress-ng --cpu 2 --timeout 40m` | **대상 VM 안**(감염 상황) | `cpu_busy_sustain`=1 |
| 호스트 | 유출 `scp` 대용량 → Kali | **DB VM 에서 밖으로** | `net_tx_Bps`·`tx_rx_ratio`↑ |
| 호스트 | 연결 폭주 `hping3 -S -p 80 --flood` 짧게 | Kali → 웹 VM | `tcp_estab_max`·`net_rx_Bps`↑ |

> 연결 폭주는 **랩 안에서만, 짧게**. 호스트 PC 전체가 느려질 수 있다.

4. 추출·평가:
```bash
python ml/features.py --nginx shopapi_access.log --out data/web_real2.csv \n       --owned-path /api/orders/{id} --owned-path /api/addresses/{id} --owned-path /api/users/{id}   # 또는 --archives
python edge/db_features.py --log /var/lib/mysql/<host>.log --check                          # DB VM 안에서
python edge/db_features.py --log /var/lib/mysql/<host>.log --out db_features.csv            # DB VM 안 → CSV 만 가져옴
python edge/host_metrics.py --prom http://localhost:9090 --start <UTC> --end <UTC> --out data/host_real.csv --per-host-dir data/host_by_host
python ml/per_key_eval.py data/host_real.csv --answer data/host_answer.csv
```

## 6. 나중에 Shuffle 붙일 자리 (지금은 설정 안 함)

| 입구 | 어디서 | 설정 |
|---|---|---|
| Wazuh 룰 경보 | manager `ossec.conf` | `<integration><name>shuffle</name><hook_url>http://<SHUFFLE>/api/v1/hooks/<id></hook_url><level>7</level><alert_format>json</alert_format></integration>` |
| 지표 임계 | Prometheus → Alertmanager | `receivers.webhook_configs.url: http://<SHUFFLE>/api/v1/hooks/<id>` (뻔한 자원 임계, `docs/26` §3) |
| ML 경보 | `edge/collector.py` | 판정 결과를 웹훅으로 POST — **미구현**. 고신뢰(LOF&AE)만 자동 조회·태깅, 나머지 티켓(`MODEL_CARD` §4) |

- Shuffle 자체는 Docker + 자체 OpenSearch 로 수 GB. 이 예산(§2)엔 안 들어감 → 그 단계에서 **Kali 등 실험 VM 을 끄고** 띄우거나, 팀원 PC/클라우드에 두고 웹훅만 연결.
- 자동 차단은 사람 확인 게이트 뒤(`docs/26` §5).

## 7. 안전
- 모든 취약 앱(Juice Shop·shopapi)은 **VMnet8 NAT 안에서만**. 브리지/포트포워딩 금지.
- shopapi·MySQL 비밀번호(`labpass`)는 랩 전용. 다른 곳에 재사용 금지.
- general log 는 실험 후 OFF + 로그 파일 정리(쿼리 원문 보관 최소화).
