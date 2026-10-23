#!/usr/bin/env python3
"""Wazuh 로그 → 출발지 IP × 시간 구간 피처 표(CSV).  (docs/10 §3-0, docs/07 §5 행위 층)

입력 (하나 또는 둘 다)
  --alerts   alerts.json   : 룰에 걸린 이벤트만
  --archives archives.json : 전체 이벤트(logall_json). full_log 안의 nginx 접근 로그 줄과 sshd 줄을 쓴다

09 Q12 비교 실험은 같은 기간을 --alerts만 / --archives만으로 각각 만들어 같은 모델에 넣는다.

피처 (구간 하나 = IP 하나 × window 분)
  alerts   : alert_count, rule_level_max, uniq_rules, auth_fail, uniq_users
  archives : req_count, uniq_paths, uniq_objects, err_ratio, write_ratio,
             interval_cv, endpoint_entropy, ssh_fail

사용:
  python ml/features.py --alerts samples/sample_alerts_if.json --out data/features_alerts.csv
  python ml/features.py --archives archives.json --out data/features_archives.csv
"""
import argparse
import csv
import math
import os
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "detector"))
from wazuh_ml_detect import dig, extract_srcip, iter_alerts, parse_ts, shannon  # noqa: E402

ALERT_FEATURES = ["alert_count", "rule_level_max", "uniq_rules", "auth_fail", "uniq_users"]
WEB_FEATURES = ["req_count", "uniq_paths", "uniq_objects", "err_ratio", "write_ratio",
                "interval_cv", "endpoint_entropy", "ssh_fail"]

# nginx combined: IP - - [시각] "메서드 경로 프로토콜" 상태 크기 "Referer" "User-Agent"
NGINX_RE = re.compile(r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+) \S+ \S+ '
                      r'\[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
                      r'(?P<status>\d{3}) ')
SSH_FAIL_RE = re.compile(r"sshd\[\d+\]: (?:Failed password|Invalid user)")
SSH_IP_RE = re.compile(r"from (\d{1,3}(?:\.\d{1,3}){3})")
NUM_SEG_RE = re.compile(r"/(\d+)(?=/|$)")
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def interval_cv(ts_list) -> float:
    """요청 간격의 변동계수(표준편차/평균). 0에 가까울수록 기계처럼 일정.
    간격이 2개 미만이면 판단 불가 → 1.0(무작위 간격 수준의 중립값)."""
    ts = sorted(ts_list)
    gaps = [b - a for a, b in zip(ts, ts[1:])]
    if len(gaps) < 2:
        return 1.0
    mean = statistics.fmean(gaps)
    return statistics.pstdev(gaps) / mean if mean > 0 else 0.0


def path_template(path: str):
    """'/rest/basket/6?x=1' → ('/rest/basket/{id}', ['6']). 숫자 경로 조각 = 객체 ID."""
    p = path.split("?", 1)[0]
    return NUM_SEG_RE.sub("/{id}", p), NUM_SEG_RE.findall(p)


class Window:
    def __init__(self):
        # alerts
        self.alerts = 0
        self.level_max = 0
        self.rules = set()
        self.auth_fail = 0
        self.users = set()
        # archives
        self.req_ts = []
        self.templates = Counter()
        self.objects = set()
        self.errors = 0
        self.writes = 0
        self.ssh_fail = 0

    def alert_row(self):
        return [self.alerts, self.level_max, len(self.rules), self.auth_fail, len(self.users)]

    def web_row(self):
        n = len(self.req_ts)
        return [n, len(self.templates), len(self.objects),
                round(self.errors / n, 4) if n else 0.0,
                round(self.writes / n, 4) if n else 0.0,
                round(interval_cv(self.req_ts), 4),
                round(shannon(list(self.templates.values())), 4),
                self.ssh_fail]


def add_alerts(path, windows, win_sec):
    for a in iter_alerts(path):
        ip = extract_srcip(a)
        if not ip:
            continue
        w = windows[(ip, int(parse_ts(dig(a, "timestamp")) // win_sec * win_sec))]
        w.alerts += 1
        w.level_max = max(w.level_max, int(dig(a, "rule", "level", default=0) or 0))
        w.rules.add(str(dig(a, "rule", "id", default="")))
        groups = dig(a, "rule", "groups", default=[]) or []
        if any(g.startswith("authentication_fail") for g in groups):
            w.auth_fail += 1
        user = dig(a, "data", "srcuser") or dig(a, "data", "dstuser")
        if user:
            w.users.add(str(user))


def add_archives(path, windows, win_sec):
    web = ssh = 0
    for e in iter_alerts(path):
        line = str(e.get("full_log") or "")
        m = NGINX_RE.search(line)
        if m:
            try:
                ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z").timestamp()
            except ValueError:
                ts = parse_ts(dig(e, "timestamp"))
            w = windows[(m["ip"], int(ts // win_sec * win_sec))]
            tmpl, ids = path_template(m["path"])
            w.req_ts.append(ts)
            w.templates[(m["method"], tmpl)] += 1
            w.objects.update((tmpl, i) for i in ids)
            if int(m["status"]) >= 400:
                w.errors += 1
            if m["method"] in WRITE_METHODS:
                w.writes += 1
            web += 1
            continue
        if SSH_FAIL_RE.search(line):
            ip = dig(e, "data", "srcip") or (SSH_IP_RE.search(line) or [None, None])[1]
            if ip:
                windows[(ip, int(parse_ts(dig(e, "timestamp")) // win_sec * win_sec))].ssh_fail += 1
                ssh += 1
    return web, ssh


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Wazuh 로그 → IP × 구간 피처 CSV")
    ap.add_argument("--alerts", help="alerts.json 경로")
    ap.add_argument("--archives", help="archives.json 경로")
    ap.add_argument("--window", type=float, default=5, help="구간 길이(분), 기본 5")
    ap.add_argument("--out", required=True, help="출력 CSV")
    args = ap.parse_args()
    if not args.alerts and not args.archives:
        ap.error("--alerts 또는 --archives 중 하나는 필요")

    win_sec = int(args.window * 60)
    windows = defaultdict(Window)
    if args.alerts:
        add_alerts(args.alerts, windows, win_sec)
    if args.archives:
        web, ssh = add_archives(args.archives, windows, win_sec)
        print(f"archives: nginx 요청 {web}줄, sshd 실패 {ssh}줄 사용")

    cols = (ALERT_FEATURES if args.alerts else []) + (WEB_FEATURES if args.archives else [])
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        wr = csv.writer(f)
        wr.writerow(["ip", "window_start"] + cols)
        for (ip, ws), w in sorted(windows.items(), key=lambda kv: (kv[0][1], kv[0][0])):
            row = (w.alert_row() if args.alerts else []) + (w.web_row() if args.archives else [])
            start = datetime.fromtimestamp(ws, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            wr.writerow([ip, start] + row)

    ips = {ip for ip, _ in windows}
    print(f"IP {len(ips)}개 × {args.window:g}분 구간 → {len(windows)}행, 피처 {len(cols)}개 → {args.out}")


if __name__ == "__main__":
    main()
