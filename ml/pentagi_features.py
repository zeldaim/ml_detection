#!/usr/bin/env python3
"""Wazuh archives.json → PentAGI 탐지용 8대 행동 피처 (client_ip × 30초 창).  (계획서 §4-5)

계획서의 Wazuh 원천 필드(data.client_ip/method/path/status/response_bytes/user_agent/
timestamp)를 읽어 IP별 30초 창으로 **계획서 §5-2의 8대 피처**를 만든다.
세션 기록표(CSV)로 라벨(0/1)과 session_id 를 붙인다 (계획서 §4-4).

8대 피처 (계획서 §5-2):
  req_count · interval_mean · interval_std · error_404_ratio
  unique_url_count · unique_ua_count · bytes_mean · new_path_ratio

세션표 CSV : session_id,label,ip,start,end    (start/end = ISO8601, 계획서 §4-4)
출력 CSV   : ip,window_start,session_id,label, <8 features>

정적 리소스(.css/.js/.png ...)는 계획서 §3-3 전처리 원칙대로 제외.
new_path_ratio 의 '정상 베이스라인 경로'는 세션표에서 label=0 인 요청의 경로 템플릿 집합으로 둔다
(운영에선 알려진 라우트 목록. 여기서는 데이터 내 정상 세션으로 근사 — 그 전제를 출력에 알린다).

사용:
  python ml/pentagi_features.py --archives archives.json --sessions sessions.csv \
      --out data/features_pentagi.csv
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
from datetime import datetime, timedelta, timezone

FEATURES = ["req_count", "interval_mean", "interval_std", "error_404_ratio",
            "unique_url_count", "unique_ua_count", "bytes_mean", "new_path_ratio"]

STATIC_RE = re.compile(r"\.(?:css|js|png|jpe?g|gif|ico|svg|woff2?|ttf|map|webp|bmp)$", re.I)
NUM_SEG_RE = re.compile(r"/(\d+)(?=/|$)")
UUID_SEG_RE = re.compile(r"/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                         r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?=/|$)")
QNUM_RE = re.compile(r"(=)\d+")   # ?id=5 → ?id=  (쿼리 숫자값 템플릿화)


def open_text(path):
    return (gzip.open(path, "rt", encoding="utf-8", errors="replace")
            if path.endswith(".gz") else open(path, "r", encoding="utf-8", errors="replace"))


def iter_json(path):
    with open_text(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def dig(d, *keys):
    for k in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


def parse_ts(s):
    """ISO8601(오프셋 포함) → epoch 초. '2026-10-26T06:18:26.984+09:00' 지원."""
    return datetime.fromisoformat(s).timestamp()


def path_only(url):
    return url.split("?", 1)[0]


def path_template(url):
    """경로의 숫자/UUID 조각을 {id}로. 쿼리는 버린다. (hidden 엔드포인트 식별용)"""
    p = path_only(url)
    return NUM_SEG_RE.sub("/{id}", UUID_SEG_RE.sub("/{id}", p))


def url_key(url):
    """unique_url_count 용 — 경로+쿼리(쿼리 숫자값만 템플릿화). ?id=1,?id=2 는 서로 다른 URL로 센다."""
    return QNUM_RE.sub(r"\1", url)


def load_sessions(path):
    """세션표 → [(ip, start_epoch, end_epoch, session_id, label)]."""
    out = []
    for r in csv.DictReader(open(path, encoding="utf-8")):
        out.append((r["ip"].strip(), parse_ts(r["start"]), parse_ts(r["end"]),
                    r["session_id"].strip(), int(r["label"])))
    return out


def session_of(ip, ts, sessions):
    for sip, start, end, sid, label in sessions:
        if sip == ip and start <= ts < end:
            return sid, label
    return None, None


class Win:
    def __init__(self):
        self.ts = []
        self.statuses = []
        self.urls = set()
        self.uas = set()
        self.bytes = []
        self.templates = []     # 요청별 경로 템플릿 (new_path_ratio 계산용)
        self.session_id = None
        self.label = None


def extract(records, baseline_paths, win_sec):
    """records: [(ip, ts, status, url, ua, nbytes, sid, label)] → {(ip, win_start): Win}."""
    windows = defaultdict(Win)
    for ip, ts, status, url, ua, nbytes, sid, label in records:
        w = windows[(ip, int(ts // win_sec * win_sec))]
        w.ts.append(ts)
        w.statuses.append(status)
        w.urls.add(url_key(url))
        w.uas.add(ua)
        w.bytes.append(nbytes)
        w.templates.append(path_template(url))
        w.session_id, w.label = sid, label   # 창 안 요청은 같은 세션
    return windows


def row_of(w, baseline_paths):
    n = len(w.ts)
    gaps = [b - a for a, b in zip(sorted(w.ts), sorted(w.ts)[1:])]
    interval_mean = statistics.fmean(gaps) if gaps else 0.0
    interval_std = statistics.pstdev(gaps) if len(gaps) >= 2 else 0.0
    err404 = sum(1 for s in w.statuses if s == 404) / n if n else 0.0
    new_paths = sum(1 for t in w.templates if t not in baseline_paths)
    return [
        n,
        round(interval_mean, 4),
        round(interval_std, 4),
        round(err404, 4),
        len(w.urls),
        len(w.uas),
        round(statistics.fmean(w.bytes), 1) if w.bytes else 0.0,
        round(new_paths / n, 4) if n else 0.0,
    ]


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Wazuh archives → PentAGI 8대 피처 (계획서)")
    ap.add_argument("--archives", action="append", required=True, help="archives.json (.gz 가능, 여러 번)")
    ap.add_argument("--sessions", required=True, help="세션표 CSV (session_id,label,ip,start,end)")
    ap.add_argument("--window", type=float, default=0.5, help="창 길이(분). 계획서=30초=0.5")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    sessions = load_sessions(args.sessions)
    win_sec = int(args.window * 60)

    records = []
    skipped_static = unlabeled = 0
    for path in args.archives:
        for e in iter_json(path):
            ts_raw = e.get("timestamp") or dig(e, "data", "timestamp")
            ip = dig(e, "data", "client_ip") or dig(e, "data", "srcip")
            url = dig(e, "data", "path") or dig(e, "data", "url")
            if not (ts_raw and ip and url):
                continue
            if STATIC_RE.search(path_only(url)):
                skipped_static += 1
                continue
            ts = parse_ts(ts_raw)
            sid, label = session_of(ip, ts, sessions)
            if sid is None:
                unlabeled += 1
                continue
            status = int(dig(e, "data", "status") or 0)
            ua = (dig(e, "data", "user_agent") or "-")
            nbytes = int(dig(e, "data", "response_bytes") or 0)
            records.append((ip, ts, status, url, ua, nbytes, sid, label))

    if not records:
        sys.exit("라벨링된 요청이 0건 — 세션표의 ip/start/end 와 archives 시각대를 확인")

    # new_path_ratio 베이스라인: label=0(정상) 요청의 경로 템플릿 집합
    baseline_paths = {path_template(url) for (_, _, _, url, _, _, _, lbl) in records if lbl == 0}

    windows = extract(records, baseline_paths, win_sec)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        wr = csv.writer(f)
        wr.writerow(["ip", "window_start", "session_id", "label"] + FEATURES)
        for (ip, ws), w in sorted(windows.items(), key=lambda kv: (kv[0][1], kv[0][0])):
            start = datetime.fromtimestamp(ws, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            wr.writerow([ip, start, w.session_id, w.label] + row_of(w, baseline_paths))

    pos = sum(1 for w in windows.values() if w.label == 1)
    print(f"요청 {len(records)}건(정적 {skipped_static} 제외, 미라벨 {unlabeled} 제외) → "
          f"{len(windows)}창 (공격 {pos} / 정상 {len(windows) - pos}), "
          f"피처 {len(FEATURES)}개 · 베이스라인 경로 {len(baseline_paths)}개 → {args.out}")


if __name__ == "__main__":
    main()
