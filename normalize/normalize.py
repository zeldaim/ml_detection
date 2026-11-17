#!/usr/bin/env python3
"""어떤 웹 요청 로그든 → 공통 요청 형식(JSONL) 한 줄씩.  (normalize/README.md)

수집 방식이 바뀌어도(nginx → Apache → WAF → Gateway JSON → FortiWeb syslog → CSV 내보내기 …)
피처 코드는 그대로 두고 이 층만 거치게 한다. 공통 형식:
  {"ts": "2026-10-27T00:00:03Z", "ip": "1.2.3.4", "user": "kim"|null, "method": "GET"|null,
   "path": "/api/x?q=1", "status": 200|null, "xff": ...|null, "request_id": ...|null}
→ python ml/features.py --requests requests.jsonl [--key ip|user] --out features.csv

형식 알아보기 (코드 수정 없이 늘리는 순서)
  1) 필드 이름 별칭(ALIASES) — JSON(중첩은 점: client.ip) · CSV · key=value · W3C(#Fields) 를 자동 매핑
  2) 별칭에 없으면 --map user=consumer.username  (inbox 라면 meta.json 의 "fields")
  3) 줄 형식 자체가 새롭다면 formats/<이름>.json 에 정규식 프로필 추가 (named group = 공통 필드 이름)

사용:
  python normalize/normalize.py access.log gw.jsonl.gz --check          # 무엇으로 알아봤는지·필드 채움률만
  python normalize/normalize.py fortiweb.log --tz +09:00 --out data/requests.jsonl
  python normalize/normalize.py kong.json --map user=consumer.username --out data/requests.jsonl
"""
import argparse
import csv
import glob
import gzip
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
FIELDS = ["ts", "ip", "user", "method", "path", "status", "xff", "request_id"]
# 소문자로 비교. 앞에 있을수록 우선. request_time(nginx JSON)은 소요 시간이라 ts 별칭에 넣지 않는다
ALIASES = {
    "ts": ["@timestamp", "timestamp", "time", "ts", "datetime", "date_time", "time_local", "time_iso8601",
           "started_at", "start_time", "eventtime", "event.created", "logtime"],
    "ip": ["client_ip", "clientip", "src_ip", "srcip", "source_ip", "remote_addr", "remote_ip", "c-ip",
           "client.ip", "source.ip", "client_addr", "realip", "real_ip", "src", "ip"],
    "user": ["user_id", "userid", "user", "username", "uid", "sub", "consumer.username", "consumer.id",
             "authenticated_entity.id", "remote_user", "cs-username", "user.name", "user.id", "srcuser"],
    "method": ["method", "http_method", "request_method", "request.method", "cs-method", "verb",
               "http.request.method"],
    "path": ["path", "uri", "request_uri", "request.uri", "url", "http_url", "cs-uri-stem", "url.path",
             "url.original", "request.url", "request_path"],
    "query": ["query", "query_string", "args", "cs-uri-query", "url.query"],
    "request": ["request", "request_line"],   # "GET /x HTTP/1.1" 통째
    "status": ["status", "status_code", "response.status", "http_status", "sc-status", "response_code",
               "http.response.status_code", "http_retcode", "return_code", "response"],
    "xff": ["x_forwarded_for", "http_x_forwarded_for", "xff", "request.headers.x-forwarded-for",
            "x-forwarded-for"],
    "request_id": ["request_id", "x_request_id", "request.headers.x-request-id", "req_id", "trace_id",
                   "unique_id"],
}
CANON_RE = re.compile(r"[^a-z0-9.]")


def canon(key):
    """'Source IP'·'source_ip'·'source-ip' → 'sourceip'. 내보내기 도구마다 다른 표기를 한 키로 비교한다."""
    return CANON_RE.sub("", str(key).lower())


ALIASES_C = {f: [canon(a) for a in names] for f, names in ALIASES.items()}
NO_VALUE = {"", "-", "null", "none", "n/a"}
KV_RE = re.compile(r'([A-Za-z_][\w.-]*)=("(?:[^"\\]|\\.)*"|\S*)')
TIME_FORMATS = ["%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%b %d %Y %H:%M:%S"]


def open_text(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def load_profiles():
    """formats/*.json — {"name", "pattern"(named group), "time_format"(선택)} 정규식 프로필."""
    out = []
    for p in sorted(glob.glob(os.path.join(HERE, "formats", "*.json"))):
        prof = json.load(open(p, encoding="utf-8"))
        prof["re"] = re.compile(prof["pattern"])
        out.append(prof)
    return out


def flatten(obj, prefix=""):
    flat = {}
    for k, v in obj.items():
        key = f"{prefix}{k}".lower()
        if isinstance(v, dict):
            flat.update(flatten(v, key + "."))
        else:
            flat[key] = v
    return flat


def parse_time(v, tz, fmt=None):
    """→ (aware datetime, 시간대 가정 여부). epoch(초·ms·ns)·ISO·nginx·흔한 날짜 형식."""
    if isinstance(v, (int, float)) or (isinstance(v, str) and re.fullmatch(r"\d{9,19}(\.\d+)?", v)):
        x = float(v)
        while x > 1e11:   # ms·µs·ns → 초
            x /= 1000
        return datetime.fromtimestamp(x, timezone.utc), False
    s = str(v).strip().strip("[]")
    dt = None
    for f in ([fmt] if fmt else []) + TIME_FORMATS:
        try:
            dt = datetime.strptime(s, f)
            break
        except ValueError:
            continue
    if dt is None:
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None, False
    if dt.tzinfo is None:
        return dt.replace(tzinfo=tz), True
    return dt, False


def clean(v):
    if v is None:
        return None
    s = str(v).strip().strip('"')
    return None if s.lower() in NO_VALUE else s


def pick(d, field, fmap):
    if field in fmap:
        return d.get(canon(fmap[field]))
    for a in ALIASES_C[field]:
        if a in d and clean(d[a]) is not None:
            return d[a]
    return None


def to_record(d, fmap, tz, time_format=None):
    """평평한 dict → 공통 레코드. ts·path·(ip 또는 user) 가 없으면 None."""
    d = {canon(k): v for k, v in d.items()}
    if "ts" not in fmap and "date" in d and "time" in d:   # FortiWeb·W3C: date=… time=… 따로 ('time' 만 집으면 날짜가 빠진다)
        raw_ts = f"{d['date']} {d['time']}"
    else:
        raw_ts = pick(d, "ts", fmap)
    if raw_ts is None:
        return None, False
    ts, assumed = parse_time(raw_ts, tz, time_format)
    method, path = clean(pick(d, "method", fmap)), clean(pick(d, "path", fmap))
    req = clean(pick(d, "request", fmap))
    if req and (not method or not path):
        parts = req.split()
        if len(parts) >= 2:
            method, path = method or parts[0], path or parts[1]
    if ts is None or not path:
        return None, False
    if "://" in path:
        u = urlsplit(path)
        path = u.path + ("?" + u.query if u.query else "")
    q = clean(pick(d, "query", fmap))
    if q and "?" not in path:
        path += "?" + q
    ip = clean(pick(d, "ip", fmap))
    if ip and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}:\d+", ip):
        ip = ip.rsplit(":", 1)[0]
    user = clean(pick(d, "user", fmap))
    if not (ip or user):
        return None, False
    status = clean(pick(d, "status", fmap))
    rec = {"ts": ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "ip": ip, "user": user,
           "method": method.upper() if method else None, "path": path,
           "status": int(status) if status and status.isdigit() else None,
           "xff": clean(pick(d, "xff", fmap)), "request_id": clean(pick(d, "request_id", fmap))}
    return rec, assumed


# ── 줄 → 평평한 dict 로 바꾸는 읽기 방식들 ───────────────────────────────────────
def lines_of(path, limit=None):
    with open_text(path) as f:
        n = 0
        for line in f:
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            yield line
            n += 1
            if limit and n >= limit:
                return


def read_json(lines):
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            yield None
            continue
        yield flatten(obj) if isinstance(obj, dict) else None


def read_kv(lines):
    for line in lines:
        pairs = KV_RE.findall(line)
        yield {k.lower(): v.strip('"') for k, v in pairs} if len(pairs) >= 3 else None


def read_table(lines):
    """CSV/TSV(첫 줄 헤더) 또는 W3C(#Fields: 줄, 공백 구분). 헤더 줄 자체는 내지 않는다."""
    header, delim, w3c = None, ",", False
    for line in lines:
        if line.startswith("#"):
            if line.startswith("#Fields:"):
                header, delim, w3c = line[8:].split(), " ", True
            continue
        if header is None:
            delim = "\t" if line.count("\t") > line.count(",") else ","
            header = [h.strip().lower() for h in next(csv.reader([line], delimiter=delim))]
            continue
        row = next(csv.reader([line], delimiter=delim))
        if len(row) != len(header):
            yield None
            continue
        rec = dict(zip([h.lower() for h in header], row))
        if w3c and "date" in rec and "time" in rec:   # W3C 확장 로그의 date·time 은 규격상 항상 UTC
            rec["@timestamp"] = f"{rec.pop('date')}T{rec.pop('time')}+00:00"
        yield rec


def read_regex(prof):
    def reader(lines):
        for line in lines:
            m = prof["re"].match(line)
            yield {k: v for k, v in m.groupdict().items() if v is not None} if m else None
    return reader


def readers(profiles):
    """(이름, 읽기 함수, 시각 형식). 같은 점수면 앞쪽(구체적인 것)이 이긴다."""
    out = [(f"regex:{p['name']}", read_regex(p), p.get("time_format")) for p in profiles]
    return out + [("json", read_json, None), ("csv/w3c", read_table, None), ("key=value", read_kv, None)]


def detect(path, fmap=None, tz=timezone.utc, profiles=None, sample=50):
    """앞 sample 줄로 각 읽기 방식을 시험 → (이름, 함수, 시각형식, 성공률). 60% 미만이면 이름 None."""
    fmap = fmap or {}
    head = list(lines_of(path, sample))
    if not head:
        return None, None, None, 0.0
    best = (None, None, None, 0.0)
    for name, fn, tf in readers(profiles if profiles is not None else load_profiles()):
        dicts = list(fn(head))
        ok = sum(1 for d in dicts if d and to_record(d, fmap, tz, tf)[0])
        rate = ok / max(1, len(dicts))
        if rate > best[3]:
            best = (name, fn, tf, rate)
    return best if best[3] >= 0.6 else (None, None, None, best[3])


def client_ip(remote, xff, trusted):
    """신뢰 프록시에서 온 요청만 XFF 를 오른쪽부터 보며 신뢰 목록 밖 첫 주소 (docs/29 §7-4)."""
    if not remote or remote not in trusted or not xff:
        return remote
    for hop in reversed([h.strip() for h in xff.split(",") if h.strip()]):
        if hop not in trusted:
            return hop
    return remote


def parse_tz(s):
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", s)
    if not m:
        raise ValueError(f"--tz 형식: +09:00 / -05:00 / +00:00 ({s})")
    sign = 1 if m[1] == "+" else -1
    return timezone(sign * timedelta(hours=int(m[2]), minutes=int(m[3])))


def normalize_file(path, fmap, tz, trusted, profiles, out_f=None):
    """파일 하나 → 통계 dict. out_f 가 있으면 레코드를 JSONL 로 쓴다."""
    name, fn, tf, rate = detect(path, fmap, tz, profiles)
    st = {"file": path, "format": name, "detect_rate": rate, "lines": 0, "ok": 0, "assumed_tz": 0,
          "filled": {f: 0 for f in FIELDS}, "sample": []}
    if not name:
        return st
    for d in fn(lines_of(path)):
        st["lines"] += 1
        rec, assumed = to_record(d, fmap, tz, tf) if d else (None, False)
        if not rec:
            continue
        rec["ip"] = client_ip(rec["ip"], rec["xff"], trusted)
        st["ok"] += 1
        st["assumed_tz"] += assumed
        for f in FIELDS:
            st["filled"][f] += rec[f] is not None
        if len(st["sample"]) < 3:
            st["sample"].append(rec)
        if out_f:
            out_f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return st


def describe(st, tz_label):
    """사람이 읽는 요약 + 빠진 필드가 피처에 주는 영향."""
    if not st["format"]:
        return [f"{st['file']}: ⚠ 형식을 모름 (가장 잘 맞은 방식도 {st['detect_rate']:.0%}) — "
                "--map 으로 필드 지정 또는 formats/ 에 프로필 추가 (normalize/README.md §3)"]
    ok = st["ok"]
    out = [f"{st['file']}: {st['format']} · {ok}/{st['lines']}줄 변환"]
    fill = " · ".join(f"{f} {st['filled'][f] / ok:.0%}" for f in FIELDS) if ok else "-"
    out.append(f"  필드 채움률: {fill}")
    if st["assumed_tz"]:
        out.append(f"  시간대 없는 시각 {st['assumed_tz']}건 → {tz_label} 로 가정 (다르면 --tz)")
    impact = {"user": "사용자 키(--key user) 불가 → IP 키만", "status": "err_ratio 항상 0 (실패 축 안 보임)",
              "method": "write_ratio 항상 0 (쓰기 축 안 보임)", "ip": "IP 키 불가 → 사용자 키만"}
    for f, msg in impact.items():
        if ok and st["filled"][f] == 0:
            out.append(f"  ⚠ {f} 없음: {msg}")
    return out


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="웹 요청 로그(형식 무관) → 공통 요청 JSONL")
    ap.add_argument("files", nargs="+", help="로그 파일 (.gz 가능)")
    ap.add_argument("--out", help="출력 JSONL (--check 면 생략)")
    ap.add_argument("--check", action="store_true", help="알아본 형식·필드 채움률·예시만 보고 끝")
    ap.add_argument("--map", action="append", default=[], metavar="필드=키",
                    help=f"별칭으로 못 찾을 때 직접 지정. 필드: {', '.join(ALIASES)}. 중첩 JSON 은 점")
    ap.add_argument("--tz", default="+09:00", help="시간대 없는 시각에 붙일 시간대 (기본 +09:00)")
    ap.add_argument("--trusted-proxy", action="append", default=[], help="XFF 로 원래 IP 를 복원할 프록시 IP")
    args = ap.parse_args()
    if not args.check and not args.out:
        ap.error("--out 또는 --check 필요")
    fmap = {}
    for kv in args.map:
        f, _, key = kv.partition("=")
        if f not in ALIASES or not key:
            ap.error(f"--map 은 {list(ALIASES)} 중 하나=키: {kv}")
        fmap[f] = key
    tz, profiles = parse_tz(args.tz), load_profiles()

    out_f = None
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        out_f = open(args.out, "w", encoding="utf-8")
    total = 0
    for p in args.files:
        st = normalize_file(p, fmap, tz, set(args.trusted_proxy), profiles, out_f)
        total += st["ok"]
        print("\n".join(describe(st, args.tz)))
        if args.check:
            for rec in st["sample"]:
                print("    " + json.dumps(rec, ensure_ascii=False))
    if out_f:
        out_f.close()
        print(f"→ {args.out} ({total}건)")
    if total == 0:
        sys.exit("변환된 요청이 0건")


if __name__ == "__main__":
    main()
