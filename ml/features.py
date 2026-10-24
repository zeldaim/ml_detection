#!/usr/bin/env python3
"""로그 → 출발지 IP × 시간 구간 피처 표(CSV).  (docs/10 §3-0, docs/07 §5 행위 층)

입력 (웹 로그는 --archives 또는 --nginx 중 하나, --alerts는 함께 써도 됨)
  --alerts   alerts.json   : Wazuh 룰에 걸린 이벤트만
  --archives archives.json : Wazuh 전체 이벤트(logall_json). full_log 안의 nginx 줄과 sshd 줄을 쓴다
  --nginx    access.log    : Wazuh 없이 웹서버의 nginx 접근 로그를 직접 (combined 형식)
.gz 파일(로그 로테이션으로 압축된 것)도 그대로 넣을 수 있다. 같은 옵션을 여러 번 주면 모두 읽는다.

09 Q12 비교 실험은 같은 기간을 --alerts만 / --archives만으로 각각 만들어 같은 모델에 넣는다.

피처 (구간 하나 = IP 하나 × window 분)
  alerts : alert_count, rule_level_max, uniq_rules, auth_fail, uniq_users
  웹     : req_count, max_req_1min, uniq_paths, uniq_objects, err_ratio, write_ratio,
           interval_cv, endpoint_entropy, ssh_fail(archives에서만 채워짐)

사용:
  python ml/features.py --alerts samples/sample_alerts_if.json --out data/features_alerts.csv
  python ml/features.py --archives archives.json --out data/features_archives.csv
  python ml/features.py --nginx access.log.2.gz --nginx access.log.1 --nginx access.log --out data/features_web.csv
"""
import argparse
import csv
import gzip
import json
import os
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "detector"))
from wazuh_ml_detect import dig, extract_srcip, parse_ts, shannon  # noqa: E402

ALERT_FEATURES = ["alert_count", "rule_level_max", "uniq_rules", "auth_fail", "uniq_users"]
WEB_FEATURES = ["req_count", "max_req_1min", "uniq_paths", "uniq_objects", "err_ratio",
                "write_ratio", "interval_cv", "endpoint_entropy", "ssh_fail"]

# nginx combined: IP - - [시각] "메서드 경로 프로토콜" 상태 크기 "Referer" "User-Agent"
NGINX_RE = re.compile(r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+) \S+ \S+ '
                      r'\[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
                      r'(?P<status>\d{3}) ')
SSH_FAIL_RE = re.compile(r"sshd\[\d+\]: (?:Failed password|Invalid user)")
SSH_IP_RE = re.compile(r"from (\d{1,3}(?:\.\d{1,3}){3})")
NUM_SEG_RE = re.compile(r"/(\d+)(?=/|$)")
# crAPI 등은 객체 ID로 UUID를 쓴다(예: /identity/api/v2/vehicle/<uuid>/location).
# 숫자 ID와 같게 {id}로 템플릿화하고 BOLA 객체 집합에 넣어, uniq_paths 폭증·객체 미집계를 막는다.
UUID_SEG_RE = re.compile(r"/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                         r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?=/|$)")
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# uniq_objects는 "주인만 봐야 하는 자원"의 ID만 센다 (BOLA 징후). 상품처럼 공개 자원은 제외 —
# 정상 쇼핑객이 상품을 많이 보면 공격자와 구분이 안 되기 때문. 경로 템플릿 접두어, --owned-path로 교체 가능.
OWNED_PREFIXES = ["/rest/basket/{id}", "/api/BasketItems/{id}", "/api/Users/{id}",
                  "/api/Cards/{id}", "/api/Addresss/{id}"]


def open_text(path):
    """일반 파일과 .gz를 똑같이 줄 단위로 연다."""
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def iter_json(path):
    """JSON lines(alerts.json / archives.json)를 한 줄씩 dict로. 깨진 줄은 건너뛴다."""
    with open_text(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


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
    """'/rest/basket/6?x=1' → ('/rest/basket/{id}', ['6']). 숫자/UUID 경로 조각 = 객체 ID."""
    p = path.split("?", 1)[0]
    ids = UUID_SEG_RE.findall(p) + NUM_SEG_RE.findall(p)
    tmpl = NUM_SEG_RE.sub("/{id}", UUID_SEG_RE.sub("/{id}", p))
    return tmpl, ids


def is_owned(tmpl: str) -> bool:
    """'/rest/basket/{id}/checkout'처럼 소유 자원 경로(또는 그 하위)인가."""
    return any(tmpl == p or tmpl.startswith(p + "/") for p in OWNED_PREFIXES)


class Window:
    def __init__(self):
        # alerts
        self.alerts = 0
        self.level_max = 0
        self.rules = set()
        self.auth_fail = 0
        self.users = set()
        # 웹
        self.req_ts = []
        self.minutes = Counter()
        self.templates = Counter()
        self.objects = set()
        self.errors = 0
        self.writes = 0
        self.ssh_fail = 0

    def alert_row(self):
        return [self.alerts, self.level_max, len(self.rules), self.auth_fail, len(self.users)]

    def web_row(self):
        n = len(self.req_ts)
        return [n, max(self.minutes.values(), default=0), len(self.templates), len(self.objects),
                round(self.errors / n, 4) if n else 0.0,
                round(self.writes / n, 4) if n else 0.0,
                round(interval_cv(self.req_ts), 4),
                round(shannon(list(self.templates.values())), 4),
                self.ssh_fail]


def add_request(windows, win_sec, m):
    """nginx 한 줄(정규식 매치)을 구간에 더한다. 시각은 로그 원문 시각."""
    ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z").timestamp()
    w = windows[(m["ip"], int(ts // win_sec * win_sec))]
    tmpl, ids = path_template(m["path"])
    w.req_ts.append(ts)
    w.minutes[int(ts // 60)] += 1
    w.templates[(m["method"], tmpl)] += 1
    if is_owned(tmpl):
        w.objects.update((tmpl.split("{id}")[0], i) for i in ids)
    if int(m["status"]) >= 400:
        w.errors += 1
    if m["method"] in WRITE_METHODS:
        w.writes += 1


def add_alerts(path, windows, win_sec):
    for a in iter_json(path):
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
    for e in iter_json(path):
        line = str(e.get("full_log") or "")
        m = NGINX_RE.search(line)
        if m:
            try:
                add_request(windows, win_sec, m)
                web += 1
            except ValueError:
                pass
            continue
        if SSH_FAIL_RE.search(line):
            ip = dig(e, "data", "srcip") or (SSH_IP_RE.search(line) or [None, None])[1]
            if ip:
                windows[(ip, int(parse_ts(dig(e, "timestamp")) // win_sec * win_sec))].ssh_fail += 1
                ssh += 1
    return web, ssh


def add_nginx(path, windows, win_sec):
    used = skipped = 0
    with open_text(path) as f:
        for line in f:
            m = NGINX_RE.match(line)
            if not m:
                skipped += 1
                continue
            try:
                add_request(windows, win_sec, m)
                used += 1
            except ValueError:
                skipped += 1
    return used, skipped


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="로그 → IP × 구간 피처 CSV")
    ap.add_argument("--alerts", action="append", default=[], help="Wazuh alerts.json (.gz 가능)")
    ap.add_argument("--archives", action="append", default=[], help="Wazuh archives.json (.gz 가능)")
    ap.add_argument("--nginx", action="append", default=[], help="nginx access.log (.gz 가능)")
    ap.add_argument("--window", type=float, default=5, help="구간 길이(분), 기본 5")
    ap.add_argument("--out", required=True, help="출력 CSV")
    ap.add_argument("--owned-path", action="append", default=[],
                    help="uniq_objects로 셀 소유 자원 경로 템플릿 (여러 번 가능, 주면 기본 목록을 대체). "
                         "예: --owned-path /api/Orders/{id}")
    args = ap.parse_args()
    if args.owned_path:
        OWNED_PREFIXES[:] = args.owned_path
    if not (args.alerts or args.archives or args.nginx):
        ap.error("--alerts / --archives / --nginx 중 하나는 필요")
    if args.archives and args.nginx:
        ap.error("--archives와 --nginx는 같은 요청을 두 번 세게 되므로 하나만")

    win_sec = int(args.window * 60)
    windows = defaultdict(Window)
    for p in args.alerts:
        add_alerts(p, windows, win_sec)
    for p in args.archives:
        web, ssh = add_archives(p, windows, win_sec)
        print(f"{p}: nginx 요청 {web}줄, sshd 실패 {ssh}줄 사용")
    for p in args.nginx:
        used, skipped = add_nginx(p, windows, win_sec)
        print(f"{p}: nginx 요청 {used}줄 사용" + (f", 형식이 다른 줄 {skipped}개 건너뜀" if skipped else ""))

    has_web = bool(args.archives or args.nginx)
    cols = (ALERT_FEATURES if args.alerts else []) + (WEB_FEATURES if has_web else [])
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        wr = csv.writer(f)
        wr.writerow(["ip", "window_start"] + cols)
        for (ip, ws), w in sorted(windows.items(), key=lambda kv: (kv[0][1], kv[0][0])):
            row = (w.alert_row() if args.alerts else []) + (w.web_row() if has_web else [])
            start = datetime.fromtimestamp(ws, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            wr.writerow([ip, start] + row)

    ips = {ip for ip, _ in windows}
    print(f"IP {len(ips)}개 × {args.window:g}분 구간 → {len(windows)}행, 피처 {len(cols)}개 → {args.out}")


if __name__ == "__main__":
    main()
