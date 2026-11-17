# 15. API 취약점 공격 분석 + 탐지 피처 (소스별 획득법)

> 작성일: 2026-10-24 · 목적: OWASP API Security Top 10 + 관련 공격별로 "행위 시그니처 → 추천 피처 → 피처를 어디서 어떻게 구하나"를 정리. 피처 설계는 사람(보안지식)의 몫이므로(`docs/12`·피처 엔지니어링), 이 문서를 팀 피처 후보 카탈로그로 쓴다.

## 0. 먼저 — 피처 소스는 로그만이 아니다

같은 "피처"라도 여러 곳에서 구할 수 있고, 소스마다 보이는 게 다르다.

| 소스 | 보이는 것 | 구하는 법 |
|---|---|---|
| **웹 접근 로그** (nginx/apache) | HTTP 요청 패턴(경로·상태·크기·시각·IP) | 파일 파싱 (현재 `ml/features.py`) |
| **DB 쿼리 로그/감사** (MySQL general·audit) | 실제 쿼리·접근 레코드·에러 | general log 또는 audit 플러그인 (`edge/db_features.py`) |
| **앱 계측** (코드가 직접 기록) | 사용자 id·세션·권한·인증결과 등 **의미 있는 필드** | 앱에 로깅 추가(`/* uid=5 */` 주석, 구조화 로그) |
| **API 게이트웨이/WAF 로그** | 라우팅·인증·레이트·차단 이벤트 | 게이트웨이 설정에서 로그 활성화 |
| **인증/IdP 로그** | 로그인 성공·실패·토큰 발급·MFA | 인증 서버(Keycloak 등) 이벤트 |
| **네트워크 미러링/패킷** | 요청 본문·응답 본문(페이로드) | 포트 미러링/TAP, Zeek·Suricata (`docs/11` §3) |
| **메트릭** (Prometheus·node_exporter) | CPU·메모리·연결수·송신 바이트 | exporter 설치 → 시계열 수집 |
| **자산 인벤토리** (syscollector·API 스펙) | 열린 포트·엔드포인트 목록(섀도우 API) | syscollector / OpenAPI 스펙 diff |

> 원칙: **먼저 "어떤 신호가 이 공격을 드러내나"를 정하고, 그 신호가 가장 잘 보이는 소스를 고른다.** 한 공격을 여러 소스로 교차 확인하면 탐지가 강해진다(예: BOLA를 웹 `uniq_objects` + DB `distinct_where_ids` 둘로).

---

## 1. 공격별 분석 — OWASP API Security Top 10 (2023) + 관련 공격

각 항목: 정체 → 행위 시그니처(문법 아닌 패턴) → 추천 피처 → 피처 소스. ✅=현재 프로젝트에 있음.

### API1:2023 — BOLA (객체 수준 권한 미흡) ★ 우리 메인

- **정체:** 번호(주문·회원·장바구니 id)만 바꾸면 남의 자원이 보임. 요청 하나하나는 정상(200).
- **행위 시그니처:** 한 주체가 **소유 자원의 서로 다른 id를 다수** 접근.

| 피처 | 의미 | 소스 |
|---|---|---|
| `uniq_objects` ✅ | URL의 소유자원 id 종류 수 | 웹 로그 |
| `distinct_where_ids` ✅ | DB WHERE의 소유테이블 id 종류 수 | DB 로그 |
| `id_access_entropy` | 접근 id의 분포(순차/무작위일수록 의심) | 웹/DB |
| `owned_vs_self_ratio` | 자기 id 외 접근 비율 | **앱 계측**(세션 uid 필요) |
| `403_on_object_ratio` | 객체 접근 중 거부 비율 | 웹/앱 로그 |

### API2:2023 — 인증 취약 (크리덴셜 스터핑·브루트포스)

- **정체:** 유출 계정/비번을 대량 대입, 토큰 탈취·재사용.
- **행위 시그니처:** 로그인 실패 급증, 많은 계정 시도, 비정상 토큰 사용.

| 피처 | 의미 | 소스 |
|---|---|---|
| `auth_fail` ✅ | 인증 실패 수 | 웹/인증 로그 |
| `max_req_1min` ✅ | 분당 최대 요청 | 웹 로그 |
| `uniq_users` ✅ / `distinct_accounts_tried` | 시도한 계정 종류 수 | 인증 로그/앱 계측 |
| `login_fail_ratio` | 로그인 중 실패 비율 | 인증 로그 |
| `new_ip_for_account` | 계정별 처음 보는 IP | **인증/IdP 로그** |
| `token_reuse_count` | 같은 토큰의 다중 IP 사용 | **앱 계측**(토큰↔IP) |

### API3:2023 — 객체 속성 수준 권한 미흡 (과잉 노출·Mass Assignment)

- **정체:** 응답에 민감 필드 과잉 포함(excessive data exposure), 또는 요청에 허용 안 된 필드 주입(mass assignment, 예: `isAdmin=true`).
- **행위 시그니처:** 큰 응답 본문, 쓰기 요청에 예상 밖 필드.

| 피처 | 의미 | 소스 |
|---|---|---|
| `resp_bytes_p95` | 응답 크기 분포(과잉 노출) | 웹 로그(`$body_bytes_sent`) |
| `write_field_count` | 쓰기 요청의 필드 수 | **네트워크/앱**(본문 필요) |
| `unexpected_field_hits` | 스키마 밖 필드 포함 수 | **앱 계측/스펙 대조** |

### API4:2023 — 자원 소비 제한 없음 (DoS·대량 수집)

- **정체:** 레이트리밋·페이지네이션 없이 자원 고갈/대량 긁기.
- **행위 시그니처:** 요청 폭증, 큰 페이지 크기, 반복 목록 호출.

| 피처 | 의미 | 소스 |
|---|---|---|
| `req_count` ✅ / `max_req_1min` ✅ | 요청량 | 웹 로그 |
| `rows_returned_sum` | 반환 행 수 합(대량 수집) | **DB 로그/앱** |
| `page_size_max` | 요청한 페이지 크기 | 웹 로그(쿼리스트링) |
| `cpu_or_conn_spike` | CPU·동시연결 급증 | **메트릭**(Prometheus) |
| `bytes_out_rate` | 송신 바이트율(유출) | **메트릭/네트워크** |

### API5:2023 — 기능 수준 권한 미흡 (BFLA)

- **정체:** 일반 사용자가 관리자 기능(API) 호출(예: `DELETE /api/users/{id}`).
- **행위 시그니처:** 비권한 주체가 관리/쓰기 엔드포인트 접근.

| 피처 | 의미 | 소스 |
|---|---|---|
| `admin_path_hits` | 관리/민감 엔드포인트 호출 수 | 웹 로그(경로 패턴) |
| `write_ratio` ✅ | 쓰기(POST/PUT/DELETE) 비율 | 웹 로그 |
| `priv_endpoint_by_role` | 권한 대비 호출한 기능 | **앱 계측**(role 필요) |
| `405_403_ratio` | 메서드/권한 거부 비율 | 웹 로그 |

### API6:2023 — 민감 비즈니스 흐름 무제한 (자동화 남용)

- **정체:** 결제·예약·쿠폰 등 비즈니스 흐름을 봇/AI가 자동 반복(선착순 매크로, 재고 싹쓸이).
- **행위 시그니처:** 사람보다 빠르고 규칙적, 흐름 완주 패턴 반복.

| 피처 | 의미 | 소스 |
|---|---|---|
| `interval_cv` ✅ | 요청 간격 규칙성(낮을수록 기계) | 웹/DB 로그 |
| `flow_completion_rate` | 장바구니→결제 완주 빈도 | **앱 계측**(흐름 추적) |
| `ua_entropy` / `headless_ua` | User-Agent 다양성·봇 UA | 웹 로그 |
| `night_activity_ratio` | 사람 안 쓰는 시간대 활동 | 웹 로그(시각) |

### API7:2023 — SSRF (서버측 요청 위조)

- **정체:** 서버가 공격자가 준 URL로 요청하게 유도(내부망·메타데이터 접근).
- **행위 시그니처:** 입력에 URL/내부 IP, 서버발 아웃바운드 이상.

| 피처 | 의미 | 소스 |
|---|---|---|
| `url_param_hits` | 파라미터에 URL/IP 포함 | **네트워크/앱**(본문) |
| `internal_ip_in_input` | 169.254·10.·127. 등 | **네트워크/앱** |
| `server_outbound_new_dst` | 서버발 새 목적지 | **네트워크/방화벽 로그** |

### API8:2023 — 보안 설정 오류

- **정체:** 디버그 노출, 과한 CORS, 기본 자격증명, 미패치.
- **행위 시그니처:** 에러·디버그 경로 접근, 비정상 메서드.

| 피처 | 의미 | 소스 |
|---|---|---|
| `err_ratio` ✅ | 4xx·5xx 비율 | 웹 로그 |
| `debug_path_hits` | `/debug`·`/actuator` 등 | 웹 로그 |
| `options_trace_hits` | 비정상 메서드 | 웹 로그 |
| `config_drift` | 설정 변경 | **자산 인벤토리/FIM** |

### API9:2023 — 부적절한 자산 관리 (섀도우/좀비 API) ★ 우리 테마

- **정체:** 문서·관리에 없는 API(shadow), 폐기됐는데 살아있는 API(zombie). WAF 보호 밖.
- **행위 시그니처:** 스펙에 없는 엔드포인트가 호출됨, 구버전 경로 접근.

| 피처 | 의미 | 소스 |
|---|---|---|
| `uniq_paths` ✅ / `endpoint_entropy` ✅ | 경로 다양성 | 웹 로그 |
| `undocumented_endpoint_hits` | **스펙에 없는** 경로 호출 | **웹 로그 ↔ OpenAPI 스펙 대조** |
| `old_version_path_hits` | `/v1` 등 구버전 호출 | 웹 로그 |
| `listening_ports_delta` | 새로 열린 포트 | **syscollector** |

> 섀도우 API 발견은 "포트"가 아니라 "경로" 문제 → 웹 로그의 경로를 **API 스펙과 대조**하는 게 핵심. syscollector(포트)로는 부족(`docs/14`·이전 논의).

### API10:2023 — 안전하지 않은 API 소비

- **정체:** 서드파티 API 응답을 검증 없이 신뢰 → 그 경로로 침투.
- **행위 시그니처:** 외부 연동 응답 후 내부 이상.

| 피처 | 의미 | 소스 |
|---|---|---|
| `thirdparty_err_ratio` | 외부 API 오류율 | **앱/연동 로그** |
| `post_integration_anomaly` | 연동 직후 내부 이상 | 상관분석(웹+내부) |

### (관련) 인젝션 — SQLi ★ PHP/MySQL

- **정체:** 입력으로 쿼리 조작(데이터 탈취·우회). WAF 우회형(블라인드)은 룰이 놓침.
- **행위 시그니처:** 비정상 쿼리 구조, 에러 기반 탐침, 참/거짓 반복.

| 피처 | 의미 | 소스 |
|---|---|---|
| `sqli_token_hits` ✅ | UNION·sleep·information_schema 등 | DB 로그 |
| `sql_error_ratio` | 쿼리 에러율(에러 기반 SQLi) | **DB 에러 로그** |
| `uniq_query_templates` ✅ | 쿼리 템플릿 다양성 | DB 로그 |
| `boolean_probe_pattern` | 참/거짓 반복(블라인드) | DB 로그(시계열) |
| `payload_sqli_tokens` | 요청 본문의 SQLi 토큰 | **네트워크/WAF** |

---

## 2. 피처를 "어떻게" 구하나 — 소스별 실전

### A. 웹 접근 로그 (이미 함)
- nginx `log_format`에 `$body_bytes_sent`(응답크기), `$request_time`, 쿼리스트링 포함.
- 파싱: `ml/features.py`의 정규식·`Window`. 경로 템플릿화(`/basket/3`→`/basket/{id}`)로 id 추출.

### B. DB 로그 (이미 함)
- general log(랩) 또는 **audit 플러그인**(운영). `edge/db_features.py`가 쿼리→피처.
- **에러율**은 general log엔 없음 → MySQL **에러 로그**나 앱이 잡은 예외에서.

### C. 앱 계측 (권장 — 가장 의미 있는 피처)
- 코드가 **구조화 로그**(JSON)로 `user_id, session, role, auth_result, flow_step`를 남긴다.
- 또는 쿼리에 주석 `/* uid=5 role=user */` → DB 로그에서 귀속(`docs/14` 옵션 B).
- 이걸로만 얻는 피처: `owned_vs_self_ratio`, `token_reuse`, `priv_endpoint_by_role`, `flow_completion`.

### D. 네트워크 미러링 (페이로드가 필요할 때)
- 포트 미러링/TAP → **Zeek**(연결·HTTP 메타) 또는 **Suricata**(시그니처+본문).
- 얻는 것: 요청/응답 **본문**(SSRF의 URL, mass assignment 필드, SQLi 페이로드). 로그엔 본문이 안 남으므로 이 소스가 필요.
- 비용: 수집 부담·프라이버시. 목적 구분(`docs/11` §3-1).

### E. 메트릭 (Prometheus + node_exporter)
- 설치 → `cpu`, `mem`, `active_connections`, `network_bytes`를 시계열로.
- 얻는 것: `cpu_spike`, `bytes_out_rate` (자원소비·대량유출). "로그만 vs 로그+지표" 비교 실험(`docs/03`).

### F. 인증/IdP 로그
- 로그인 이벤트에서 `new_ip_for_account`, `mfa_fail`, `token_issued`.

### G. 자산 인벤토리 / API 스펙
- syscollector: 포트·프로세스 변화(`listening_ports_delta`).
- **OpenAPI/Swagger 스펙 ↔ 웹 로그 경로 대조**: 스펙에 없는 경로 = 섀도우 API(`undocumented_endpoint_hits`). 이게 API9의 핵심.

---

## 3. 현재 프로젝트 피처 ↔ 공격 매핑 (갭 분석)

| 공격 | 현재 피처 | 추가하면 좋은 것 (소스) |
|---|---|---|
| BOLA(API1) | `uniq_objects`, `distinct_where_ids` ✅ | `owned_vs_self_ratio`(앱), `id_access_entropy` |
| 인증(API2) | `auth_fail`, `max_req_1min`, `uniq_users` ✅ | `new_ip_for_account`(IdP), `token_reuse`(앱) |
| 과잉노출(API3) | — | `resp_bytes_p95`(웹), `unexpected_field`(앱/네트워크) |
| 자원소비(API4) | `req_count`, `max_req_1min` ✅ | `bytes_out_rate`(메트릭), `rows_returned`(DB) |
| BFLA(API5) | `write_ratio` ✅ | `admin_path_hits`(웹), `role`기반(앱) |
| 비즈흐름(API6) | `interval_cv` ✅ | `flow_completion`(앱), `headless_ua`(웹) |
| SSRF(API7) | — | `internal_ip_in_input`(네트워크) |
| 설정오류(API8) | `err_ratio` ✅ | `debug_path_hits`(웹) |
| 섀도우API(API9) | `uniq_paths`, `endpoint_entropy` ✅ | `undocumented_endpoint_hits`(스펙대조) |
| SQLi | `sqli_token_hits`, `uniq_query_templates` ✅ | `sql_error_ratio`(DB에러), `payload`(네트워크) |

**해석:** 지금 웹+DB 로그로 얻는 피처로 **API1·2·4·5·6·8·9 + SQLi의 1차 신호**는 커버된다. 더 정밀히 가려면 **앱 계측**(권한·세션·흐름)과 **메트릭/네트워크**(유출·페이로드)를 더한다. 우선순위: 앱 계측 > 메트릭 > 네트워크(비용 큼).

## 4. 주의 (피처를 늘릴 때)

- **피처 폭증 금지:** 공격 하나에 피처 1~3개면 충분. 많을수록 오탐·과적합↑. 작게 시작해 중요도 보고 추가.
- **상관 피처 중복:** `req_count`와 `max_req_1min`처럼 겹치면 하나로.
- **같은 윈도우 단위:** 모든 소스 피처를 IP(또는 세션)×5분으로 맞춰야 합쳐진다(`edge/correlate.py`).
- **출처 학습 함정:** 특정 소스가 공격 때만 생기면 모델이 소스를 학습(`docs/05` §1). 정상 때도 같은 소스 유지.
- **피처는 사람이 설계·소유:** 모델은 준 피처만 학습한다. 이 카탈로그는 후보일 뿐, 시나리오에 맞게 고른다.
