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
            self.tables.update(m.lower() for m in TABLE_RE.findall(arg))
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


def parse(path, win_sec):
    """general log → {(host, window_start): Win}. Connect 줄로 연결 id→host 매핑."""
    conn_host = {}
    windows = defaultdict(Win)
    last = None  # (host, cmd, ts) 이어지는 줄 처리용
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = LINE_RE.match(line.rstrip("\n"))
            if not m:
                if last and last[1].lower() in ("query", "execute"):  # 여러 줄 쿼리의 이어지는 줄
                    host, cmd, t = last
                    windows[(host, int(t // win_sec * win_sec))].add(t, cmd, line.strip())
                continue
            cid, cmd, arg = m["cid"], m["cmd"], m["arg"]
            t = _ts(m["ts"]) if m["ts"] else (last[2] if last else 0)
            if cmd.lower() == "connect":
                hm = CONNECT_HOST_RE.search(arg)
                conn_host[cid] = hm.group(1) if hm else cid
                last = None
                continue
            host = conn_host.get(cid, cid)   # 매핑 없으면 연결 id를 식별자로
            windows[(host, int(t // win_sec * win_sec))].add(t, cmd, arg)
            last = (host, cmd, t)
    return windows


def _ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc).timestamp()


def main():
    ap = argparse.ArgumentParser(description="MySQL general log → DB 피처 (엣지)")
    ap.add_argument("--log", required=True, help="MySQL general query log")
    ap.add_argument("--window", type=float, default=5, help="구간 길이(분)")
    ap.add_argument("--out", help="피처 CSV 저장")
    ap.add_argument("--print", action="store_true", dest="show", help="벡터를 화면에 출력")
    args = ap.parse_args()

    win_sec = int(args.window * 60)
    windows = parse(args.log, win_sec)
    rows = []
    for (host, ws), w in sorted(windows.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        start = datetime.fromtimestamp(ws, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rows.append([host, start] + w.row())

    hdr = ["host", "window_start"] + DB_FEATURES
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
