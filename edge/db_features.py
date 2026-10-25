#!/usr/bin/env python3
"""MySQL general query log → DB 계층 피처 (호스트 = DB 서버에서 뽑는 '엣지 피처').

DB 보안 관점: HTTP 로그가 못 보는 것을 쿼리 로그가 본다.
  - BOLA/열거  : WHERE 절의 서로 다른 id 수 (남의 데이터 접근 범위)
  - SQLi       : UNION·주석·information_schema·sleep() 같은 토큰
  - 대량 수집  : 쿼리 수, 쿼리 템플릿 다양성
  - AI 에이전트: 요청 간격의 규칙성(interval_cv)

엣지 개념: 원본 쿼리(민감·개인정보 포함)는 호스트 밖으로 내보내지 않고, 여기서 '숫자 벡터'만 만든다.
연결 id→클라이언트 host 매핑은 Connect 줄에서 얻어, 쿼리를 출발지별로 묶는다.

general query log 켜기 (MySQL):
  SET GLOBAL general_log = 'ON';
  SET GLOBAL log_output = 'FILE';          -- /var/lib/mysql/<host>.log

사용:
  python edge/db_features.py --log general.log --out db_features.csv
  python edge/db_features.py --log general.log --window 5 --print   # 벡터만 출력
"""
import argparse
import csv
import os
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone

# general log: "2026-10-24T08:00:00.000000Z\t   10 Query\tSELECT ..."  (시각 없는 줄은 이전 줄에 이어짐)
LINE_RE = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\dT[\d:.]+Z)?\s*(?P<cid>\d+)\s+(?P<cmd>\w+)\t?(?P<arg>.*)$")
CONNECT_HOST_RE = re.compile(r"@([\w.\-]+|\d{1,3}(?:\.\d{1,3}){3})")   # app@10.16.1.213 → 10.16.1.213
NUM_RE = re.compile(r"\b\d+\b")
STR_RE = re.compile(r"'(?:[^'\\]|\\.)*'")
TABLE_RE = re.compile(r"\b(?:from|join|into|update)\s+`?(\w+)`?", re.I)
# distinct_where_ids는 '주인만 봐야 하는' 테이블의 id만 센다 (BOLA). 상품 같은 공개 테이블은 제외 —
# 정상 상품 조회가 BOLA 신호를 오염시키지 않도록 (웹의 uniq_objects 소유자원 제한과 같은 원리).
OWNED_TABLES = {"orders", "order", "users", "user", "basket", "baskets", "basketitems",
                "addresses", "address", "cards", "card", "payments", "payment", "wallets"}
EQ_ID_RE = re.compile(r"=\s*(\d+)")                    # WHERE id = 5
IN_LIST_RE = re.compile(r"\bin\s*\(([^)]*)\)", re.I)   # id IN (1,2,3) → 전체 리스트


def where_ids(q):
    """WHERE 절에서 접근한 레코드 id들(= N, IN(...)의 모든 숫자). BOLA/열거 범위 측정."""
    ids = set(EQ_ID_RE.findall(q))
    for grp in IN_LIST_RE.findall(q):
        ids.update(NUM_RE.findall(grp))
    return ids
SQLI_TOKENS = [
    r"\bunion\b", r"\bsleep\s*\(", r"\bbenchmark\s*\(", r"information_schema",
    r"\bor\b\s+\d+\s*=\s*\d+", r"--\s", r"/\*", r"\bchar\s*\(", r"0x[0-9a-f]{4,}",
    r"\bwaitfor\b", r"\bload_file\s*\(", r"\binto\s+outfile\b",
]
SQLI_RE = re.compile("|".join(SQLI_TOKENS), re.I)
WRITE_CMDS = ("insert", "update", "delete", "replace")

DB_FEATURES = ["q_count", "select_ratio", "write_ratio", "uniq_templates", "distinct_tables",
               "distinct_where_ids", "sqli_token_hits", "interval_cv"]


def normalize(q):
    """쿼리를 템플릿으로: 숫자·문자열 리터럴을 ?로, 공백 축약. 'SELECT * FROM a WHERE id=5' → 'select * from a where id=?'"""
    q = STR_RE.sub("?", q)
    q = NUM_RE.sub("?", q)
    return re.sub(r"\s+", " ", q).strip().lower()


def interval_cv(ts):
    ts = sorted(ts)
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    if len(gaps) < 2:
        return 1.0
    mean = statistics.fmean(gaps)
    return statistics.pstdev(gaps) / mean if mean > 0 else 0.0


class Win:
    def __init__(self):
        self.ts = []
        self.cmds = Counter()
        self.templates = set()
        self.tables = set()
        self.where_ids = set()
        self.sqli = 0

    def add(self, t, cmd, arg):
        self.ts.append(t)
        self.cmds[cmd.lower()] += 1
        if cmd.lower() in ("query", "execute") and arg:
            self.templates.add(normalize(arg))
            tables = {m.lower() for m in TABLE_RE.findall(arg)}
            self.tables.update(tables)
            if tables & OWNED_TABLES:               # 소유 테이블을 건드린 쿼리의 id만 셈
                self.where_ids.update(where_ids(arg))
            if SQLI_RE.search(arg):
                self.sqli += 1

    def row(self):
        n = len(self.ts)
        q = sum(self.cmds[c] for c in ("query", "execute"))
        writes = sum(self.cmds[c] for c in WRITE_CMDS)
        selects = self.cmds.get("query", 0) - writes  # 근사: query 중 쓰기류 빼면 읽기류
        return [n, round(max(selects, 0) / n, 4) if n else 0.0,
                round(writes / n, 4) if n else 0.0,
                len(self.templates), len(self.tables), len(self.where_ids),
                self.sqli, round(interval_cv(self.ts), 4)]


def parse(path, win_sec, stats=None, force_host=None):
    """general log → {(host, window_start): Win}. Connect 줄로 연결 id→host 매핑.
    stats(dict)를 주면 파싱 커버리지를 채운다: total/connect/query/cont/unparsed/samples.
    force_host를 주면 모든 쿼리를 그 식별자 하나로 묶는다(옵션 C: DB 티어 전체 단위)."""
    conn_host = {}
    windows = defaultdict(Win)
    last = None  # (host, cmd, ts) 이어지는 줄 처리용
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if stats is not None:
                stats["total"] += 1
            m = LINE_RE.match(line.rstrip("\n"))
            if not m:
                if last and last[1].lower() in ("query", "execute"):  # 여러 줄 쿼리의 이어지는 줄
                    host, cmd, t = last
                    windows[(host, int(t // win_sec * win_sec))].add(t, cmd, line.strip())
                    if stats is not None:
                        stats["cont"] += 1
                elif stats is not None and line.strip():
                    stats["unparsed"] += 1
                    if len(stats["samples"]) < 5:
                        stats["samples"].append(line.rstrip("\n")[:160])
                continue
            cid, cmd, arg = m["cid"], m["cmd"], m["arg"]
            t = _ts(m["ts"]) if m["ts"] else (last[2] if last else 0)
            if cmd.lower() == "connect":
                hm = CONNECT_HOST_RE.search(arg)
                conn_host[cid] = hm.group(1) if hm else cid
                last = None
                if stats is not None:
                    stats["connect"] += 1
                continue
            host = force_host or conn_host.get(cid, cid)   # force_host면 전부 한 식별자로(티어 단위)
            windows[(host, int(t // win_sec * win_sec))].add(t, cmd, arg)
            last = (host, cmd, t)
            if stats is not None:
                stats["query"] += 1
    return windows


def _ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc).timestamp()


def main():
    ap = argparse.ArgumentParser(description="MySQL general log → DB 피처 (엣지)")
    ap.add_argument("--log", required=True, help="MySQL general query log")
    ap.add_argument("--window", type=float, default=5, help="구간 길이(분)")
    ap.add_argument("--out", help="피처 CSV 저장")
    ap.add_argument("--print", action="store_true", dest="show", help="벡터를 화면에 출력")
    ap.add_argument("--check", action="store_true",
                    help="파싱 커버리지만 점검(실제 로그 형식이 맞는지). 미파싱 줄 샘플 출력")
    args = ap.parse_args()

    import os
    if not os.path.isfile(args.log):
        raise SystemExit(f"MySQL general log 파일 없음: {args.log}")
    win_sec = int(args.window * 60)
    stats = {"total": 0, "connect": 0, "query": 0, "cont": 0, "unparsed": 0, "samples": []}
    windows = parse(args.log, win_sec, stats)

    if args.check:
        print(f"총 {stats['total']}줄 · Connect {stats['connect']} · Query {stats['query']} · "
              f"이어진 줄 {stats['cont']} · 미파싱 {stats['unparsed']}")
        hosts = {h for h, _ in windows}
        print(f"식별된 출발지(host/connid) {len(hosts)}개: {', '.join(sorted(hosts)[:10])}"
              + (" ..." if len(hosts) > 10 else ""))
        if stats["unparsed"]:
            print(f"\n⚠️ 미파싱 {stats['unparsed']}줄 — LINE_RE 보강 필요. 샘플:")
            for s in stats["samples"]:
                print(f"  | {s}")
            print("\n실제 로그 형식이 다르면 db_features.py의 LINE_RE·CONNECT_HOST_RE를 맞춰야 한다.")
        else:
            print("\n✅ 미파싱 0 — 파서가 이 로그 형식과 맞음.")
        if len(hosts) <= 1:
            print("\n⚠️ 출발지가 1개뿐 — DB가 앱 서버만 보는 '귀속 문제'일 수 있다. docs/14 §4 참고.")
        return
    rows = []
    for (host, ws), w in sorted(windows.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        start = datetime.fromtimestamp(ws, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rows.append([host, start] + w.row())

    hdr = ["ip", "window_start"] + DB_FEATURES   # 'ip' = 클라이언트 주소. ml/ 스크립트 호환 위해 동일 열 이름
    if args.show or not args.out:
        print("\t".join(hdr))
        for r in rows:
            print("\t".join(str(x) for x in r))
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        with open(args.out, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerows([hdr] + rows)
        print(f"\n저장: {args.out} ({len(rows)}행, DB 피처 {len(DB_FEATURES)}개)")


if __name__ == "__main__":
    main()
