# normalize/ — 어떤 웹 요청 로그든 공통 형식으로

> 작성 2026-10-27. **수집 방식이 바뀌어도 피처·모델 코드는 그대로 두고 이 층만 거치게** 한다.
> nginx → Apache → WAF → API Gateway JSON → FortiWeb syslog → CSV 내보내기 → IIS … 무엇이 오든
> 요청 한 줄을 같은 모양으로 바꾸고, 그다음은 늘 같은 길(`ml/features.py --requests`)로 간다.

```
아무 웹 로그 ──▶ normalize.py ──▶ 공통 요청 JSONL ──▶ ml/features.py --requests [--key ip|user] ──▶ 피처 CSV ──▶ 기존 모델·채점 그대로
  (형식 자동 인식)                  {ts, ip, user, method, path, status, xff, request_id}
```

## 1. 공통 요청 형식 (한 줄 = 요청 하나)

```json
{"ts": "2026-10-27T00:00:03Z", "ip": "203.0.113.7", "user": "kim", "method": "GET",
 "path": "/rest/basket/3?x=1", "status": 200, "xff": null, "request_id": "r1"}
```

| 필드 | 필수 | 없으면 |
|---|---|---|
| `ts` (UTC) | ✅ | 그 줄은 버림 |
| `path` | ✅ | 그 줄은 버림. 전체 URL이 와도 경로+쿼리만 남김 |
| `ip` 또는 `user` | 둘 중 하나 ✅ | `ip`가 없으면 IP 키 불가, `user`가 없으면 사용자 키 불가 |
| `method` | | 피처에서 GET으로 채움 → `write_ratio` 항상 0 (쓰기 축 안 보임) |
| `status` | | 200으로 채움 → `err_ratio` 항상 0 (실패 축 안 보임) |
| `xff`, `request_id` | | `--trusted-proxy` 복원·짝짓기용. 없어도 됨 |

빠진 필드가 **어느 피처 축을 못 보게 하는지**를 실행할 때 경고로 알려 준다(축 설명은 `docs/32` §2).

## 2. 지금 바로 알아보는 형식 (코드 수정 없음)

| 형식 | 알아보는 방법 | 확인한 예 |
|---|---|---|
| nginx/Apache combined (+ 끝에 XFF·request_id) | `formats/combined.json` 정규식 | `data/attack_access.log`, `data/waf_gw_demo/waf_access.log` |
| JSON lines (중첩 OK) | 필드 이름 별칭 | Kong 스타일(`started_at` ms·`consumer.username`), `waf_gateway` Gateway 로그 |
| key=value (Forti 계열 syslog) | 별칭 + `date`·`time` 합치기 | FortiWeb 스타일 `src= http_method= http_url= http_retcode=` |
| CSV/TSV 내보내기 (첫 줄 헤더) | 별칭. `Source IP`·`source_ip`·`source-ip`를 같은 키로 봄 | `Timestamp,Source IP,Method,URL,Status Code,User` |
| W3C 확장 로그 (IIS) | `#Fields:` 줄 + 별칭. 시각은 규격대로 UTC | IIS 10 기본 필드 |

- 시각 형식은 epoch(초·ms·ns), ISO 8601, nginx `[27/Oct/2026:09:00:00 +0900]`, `2026-10-27 09:00:00` 등을 자동으로 읽는다.
- **시간대가 없는 시각**은 `--tz`(기본 `+09:00`)로 가정하고, 몇 건을 가정했는지 알려 준다. FortiWeb·CSV 내보내기는 장비나 PC의 현지 시각인 경우가 많다.
- 별칭 전체 목록은 `normalize.py`의 `ALIASES`에 있다.
- FortiWeb 필드 이름은 공개 문서 기준으로 추정한 것이다. **실제 장비 로그로 `--check`를 먼저 돌려** 채움률을 확인할 것.

## 3. 안 맞을 때 — 코드 대신 설정으로

1) **필드 이름만 다르면**: `--map 필드=키`. 중첩 JSON은 점으로 쓴다.
```bash
python normalize/normalize.py app.json --check --map ts=evt.when --map ip=evt.who --map path=evt.what --map status=evt.code
```
inbox라면 `meta.json`에 같은 내용을 넣는다.
```json
{"fields": {"user": "consumer.username"}, "tz": "+09:00", "trusted_proxies": ["10.16.1.2"]}
```

2) **줄 모양 자체가 새로우면** (JSON·CSV·key=value가 아닌 텍스트): `formats/<이름>.json`에 정규식 프로필을 하나 추가한다. 그룹 이름은 공통 필드 이름(`ts`, `ip`, `user`, `method`, `path`, `status`, `request`, `xff`, `request_id`)을 쓴다. `formats/combined.json`이 예시다.

## 4. 실행

```bash
# ① 먼저 확인만: 무엇으로 알아봤는지 · 필드 채움률 · 예시 3줄
python normalize/normalize.py <로그들…> --check

# ② 변환 → 피처 (IP 키 / 사용자 키)
python normalize/normalize.py <로그들…> --trusted-proxy 10.16.1.2 --out data/requests.jsonl
python ml/features.py --requests data/requests.jsonl --key ip   --out data/features_ip.csv
python ml/features.py --requests data/requests.jsonl --key user --out data/features_user.csv
```

**inbox로 쓰면 더 간단하다.** `ml/ingest.py`는 고정 형식(nginx·archives·MySQL·Prometheus)이 아닌 파일을 만나면 공통 형식으로 읽히는지 자동으로 시험한다. 읽히면 `normalize → features --requests` 순서로 돌린다. 폴더에 넣고 `python ml/ingest.py inbox/<이름> --retrain` 한 줄이면 된다.

## 5. 검증 (2026-10-27)

| 확인 | 결과 |
|---|---|
| 같은 nginx 로그: 기존 `--nginx` vs `normalize → --requests` | 피처 CSV **바이트까지 동일** (`data/attack_access.log`, 1435줄) |
| WAF 데모 로그 → `--key ip` vs `waf_gateway` IP 표 | 동일 (줄 끝 문자 제외, `uniq_users` 열 제외) |
| Gateway 데모 로그 → `--key user` vs `waf_gateway` 사용자 표 | **동일** |
| ingest: Gateway JSON + 정답지 폴더 (전에는 "안 씀") | 변환 → 피처 → 재학습 → 채점까지 자동. 공격 18/18 |
| ingest: nginx 폴더 수정 전/후 | 같은 결과 (5/46구간) |
| FortiWeb 스타일 · Kong 스타일 · CSV 내보내기 · IIS W3C | 시각·IP·사용자·메서드·경로·상태 정상 변환 |

## 6. 한계

- **웹 요청 로그 전용**이다. DB(MySQL)·호스트 지표는 각자의 파서(`edge/`)를 그대로 쓴다.
- **같은 요청이 두 로그에 있으면**(WAF와 Gateway) 둘 다 넣었을 때 두 번 센다. 하나만 넣거나, 사용자와 IP를 짝지어야 하면 `waf_gateway/`를 쓴다. ingest는 nginx/archives가 있으면 변환 대상을 쓰지 않는다.
- 자동 인식은 앞 50줄 기준이다. 중간에 형식이 바뀌는 파일은 바뀐 부분이 버려진다(변환 줄 수로 드러남).
- `consumer/`(실시간)는 아직 nginx 전용이다.
