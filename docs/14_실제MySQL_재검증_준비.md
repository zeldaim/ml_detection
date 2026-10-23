# 14. 실제 MySQL 로그로 DB 모델 재검증 — 준비

> 작성일: 2026-10-24 · 전제: DB 모델(`models/db_model.joblib`)은 현재 **합성 로그**로 학습됨(`docs/13` §4·§7). 실제 MySQL 로그로 경향을 재확인한다.

## 0. 지금 공백과 재검증 목표

| 항목 | 현재(합성) | 재검증(실제) |
|---|---|---|
| DB 로그 | `tools/gen_db_traffic.py`가 만든 가짜 general log | **실제 MySQL general query log** |
| 쿼리 | 우리가 적은 문자열 | 앱이 실제로 날린 쿼리 |
| 출발지 | 합성이라 공격자 IP로 깔끔히 분리 | **앱 서버 하나로 보일 수 있음(귀속 문제, §4)** |
| 목표 | 틀 동작 확인 | 파서가 실제 형식과 맞나 + 피처가 실제 공격을 가르나 |

## 1. 인프라 — MySQL 티어 세우기

Juice Shop은 SQLite라 MySQL 로그가 안 나온다. 시나리오가 "PHP + MySQL 쇼핑몰"이므로 **PHP+MySQL 취약 앱**을 띄운다.

| 후보 | 특징 | 비고 |
|---|---|---|
| **DVWA** | PHP+MySQL, SQLi·IDOR 난이도 조절 | 가장 가벼움, 교육용 표준 |
| Mutillidae II | PHP+MySQL, OWASP 전종 취약점 | SQLi·BOLA 많음 |
| bWAPP | PHP+MySQL | 취약점 폭넓음 |
| 직접 만든 PHP 쇼핑몰 | 시나리오에 정확히 맞음 | 제작 비용 |

Docker 예(별도 VM 또는 웹 VM 안, 웹/DB 티어 분리 권장 — `docs/13` §8):
```bash
# MySQL (general log 켤 수 있게)
docker run -d --name shopdb -e MYSQL_ROOT_PASSWORD=labpass -p 3306:3306 mysql:8.0
# PHP 취약 앱 (예: DVWA)
docker run -d --name dvwa --link shopdb:db -p 8080:80 vulnerables/web-dvwa
```

## 2. MySQL general query log 켜기

```sql
SET GLOBAL general_log = 'ON';
SET GLOBAL log_output  = 'FILE';          -- 파일로 (TABLE도 가능)
SHOW VARIABLES LIKE 'general_log_file';   -- 경로 확인 (보통 /var/lib/mysql/<host>.log)
```
Docker면 로그를 꺼내기:
```bash
docker exec shopdb sh -c 'cat $(mysql -uroot -plabpass -N -e "SELECT @@general_log_file")' > data/general_real.log
```

⚠️ **주의**
- general log는 **모든 쿼리를 기록** → 디스크·성능 부담. **실험 기간만 켜고 끈다**(`SET GLOBAL general_log='OFF'`).
- 운영에선 general log 대신 **audit log 플러그인**을 쓴다(여기선 랩이라 general log).

## 3. 정상 + 공격 트래픽 (실제 쿼리 생성)

쿼리는 **앱을 통해** 발생시킨다(우리 `gen_attack_traffic.py`는 Juice Shop 엔드포인트라 PHP 앱엔 안 맞음 — 앱에 맞게 조정하거나 앱 기능으로 직접).

| 종류 | 앱에서 하는 일 | 남는 쿼리 |
|---|---|---|
| 정상 | 상품 조회, 로그인, 자기 주문 보기 | `SELECT ... WHERE id=자기것` |
| BOLA/IDOR | 주문/회원 번호 바꿔가며 조회 | `SELECT ... WHERE user_id=남의것` 다수 |
| SQLi | 취약 파라미터에 `' UNION ...`, `OR 1=1` | UNION·information_schema 쿼리 |
| 대량 수집 | 목록 API 반복 호출 | 같은 SELECT 대량 |

- 정상 기간/공격 기간을 **시간으로 분리**하고 각 공격 **시작·끝(UTC)** 기록 → `data/answer_db.csv` (형식: `attack_id,src,start,end,type`).
- 공격 실행은 통제된 랩에서 직접(`docs/09` 안전 제약).

## 4. ⚠️ 핵심 공백 — 출발지 귀속(attribution)

**실제로는 DB가 "앱 서버"만 본다.** PHP 앱이 하나의 DB 계정으로 접속하므로, general log의 Connect host가 전부 `app@웹서버IP`가 된다 → 공격자별로 못 나뉜다. `db_features.py --check`가 "출발지 1개"를 경고한다.

해결 옵션(재검증 전에 하나 택):

| 옵션 | 방법 | 난이도 |
|---|---|---|
| A. 시간 상관 | 웹 로그(출발지 IP)와 DB 쿼리를 **같은 5분 구간**으로 조인 → "그 시간대 그 IP가 보낸 요청이 이런 쿼리를 유발" | 중 |
| B. 앱 계측 | 앱이 쿼리에 **주석으로 사용자/세션 id**를 붙임(`/* uid=5 */`) → 파서가 그걸로 귀속 | 중(앱 수정) |
| C. DB 전체 단위 | 출발지 구분을 포기하고 **"DB 티어 전체가 공격받는가"**를 탐지(구간 단위 이상) | 쉬움 |

프로젝트 규모 권장: **C로 시작**(DB 티어 이상 탐지)하고, 여유되면 **A**(웹-DB 시간 상관)로 출발지까지. B는 앱을 고칠 수 있을 때.

**구현됨 — `edge/correlate.py`** (옵션 A·C 둘 다, 출력은 ml/ 파이프라인 그대로 받는 형식):

```bash
# 옵션 C: DB 티어 전체 단위 (구간별 1행, 정답지 src도 티어 id로 변환)
python edge/correlate.py --mode tier --db data/general_real.log     --out data/features_tier.csv --answer data/answer_db.csv --answer-out data/answer_tier.csv
python ml/supervised.py data/features_tier.csv --answer data/answer_tier.csv --group-by type --contamination 0.05

# 옵션 A: 웹-DB 시간 상관 (웹 IP 행에 같은 구간 DB 집계 db_* 추가)
python edge/correlate.py --mode join --web data/nginx.log --db data/general_real.log --out data/features_webdb.csv
python ml/supervised.py data/features_webdb.csv --answer data/answer.csv --group-by type --contamination 0.05
```

합성으로 동작 확인(2026-10-24): C는 구간별 티어 판정(티어로 뭉쳐 오탐↑, 출발지 해상도 포기의 트레이드오프), A는 웹 9 + db_ 8 = 17 피처 결합(겹치는 구간에 DB 집계가 붙음). 실제 로그로 같은 명령 재실행.

## 5. 재검증 실행 (파서 점검 → 피처 → 학습 → 비교)

```bash
# 1) 파서가 실제 형식과 맞는지 먼저 점검 (제일 중요)
python edge/db_features.py --log data/general_real.log --check
#   → "미파싱 0" 이어야 함. 아니면 샘플 보고 LINE_RE/CONNECT_HOST_RE 보강
#   → "출발지 1개" 경고 뜨면 §4 귀속 옵션 적용

# 2) 피처 추출
python edge/db_features.py --log data/general_real.log --out data/features_db_real.csv

# 3) 모델 재학습 + 평가 (합성 때와 같은 명령)
python ml/train_export.py data/features_db_real.csv --answer data/answer_db.csv --contamination 0.05 --out models/db_model_real.joblib
python ml/supervised.py   data/features_db_real.csv --answer data/answer_db.csv --group-by type --contamination 0.05
python ml/classify_type.py data/features_db_real.csv --answer data/answer_db.csv

# 4) 합성 결과(docs/13 §4)와 비교: 탐지율·오탐률·H5(IF 놓치고 LOF 잡은 구간)가 재현되나?
```

## 6. 성공 기준 체크리스트

```
[ ] PHP+MySQL 취약 앱 + MySQL general log 켜짐 (실험 기간만)
[ ] 정상/공격 기간 분리 + answer_db.csv (UTC)
[ ] db_features --check: 미파싱 0 (아니면 정규식 보강)
[ ] 출발지 귀속 방식 결정 (A 시간상관 / B 앱계측 / C 전체단위)
[ ] 실제 로그로 BOLA=distinct_where_ids↑, SQLi=sqli_token_hits↑ 가 정상과 갈리는지 확인
[ ] supervised/classify 재실행 → 합성 결과와 경향 비교(특히 H5)
[ ] 차이 나면 원인 기록 (피처 부족? 귀속? 데이터 양?)
```

## 7. 파서가 안 맞을 때 (자주 겪음)

실제 MySQL general log는 버전·설정에 따라 형식이 다를 수 있다. `--check`의 미파싱 샘플을 보고 맞춘다.
- 헤더 줄(`/usr/sbin/mysqld, Version: ...`)·빈 명령 등은 미파싱으로 남아도 됨(무시 가능).
- 시각 형식이 다르면(`YYMMDD HH:MM:SS` 구형) `LINE_RE`·`_ts()`를 그 형식에 맞춘다.
- Connect host가 `user@localhost`면 §4 귀속 문제 → 옵션 A/B/C.
