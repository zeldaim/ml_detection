#!/usr/bin/env python3
"""node_exporter 지표 → 호스트 × 5분 구간 피처 CSV.  (docs/26 §4 '입구 추가', docs/27 §3)

로그가 못 보는 **자원/가용성 공격**(채굴·연결 폭주·대량 유출)을 위한 ML 입구.
API 로직 공격(BOLA 등)엔 무신호 — 그건 웹/DB 피처 몫(docs/26 §2). 둘은 다른 모델로 학습한다.

입력 3가지 (모두 같은 내부 형식 '시각별 원시 시계열'로 바뀐 뒤 같은 코드로 피처화):
  --prom URL --start ISO --end ISO   Prometheus HTTP API(query_range)에서 원시 카운터를 직접 가져옴
  --matrix FILE                      query_range 응답(JSON, .gz 가능)을 저장해 둔 파일. 생성기 출력도 이 형식
  --snapshots DIR                    Prometheus 없이 node_exporter /metrics 를 주기적으로 떠 둔 텍스트
                                     (DIR/<host>/<epoch>.prom — 아래 --collect 가 만든다)
수집(Prometheus 없는 랩):
  --collect http://10.16.1.10:9100/metrics --out-dir data/host_snap --interval 15 --duration 3600

카운터(…_total)는 연속 표본 차분/시간 = 초당 속도. 카운터 리셋(재부팅)은 음수 차분이라 그 표본만 버린다.
출력 열 'ip' = 호스트(instance 에서 포트 뗀 것) — 기존 파이프라인(train_export·predict·relative_features)이
그대로 받도록 열 이름을 맞췄다. 원문 값(프로세스명·경로 등)은 피처로 안 넣는다(edge/ 원칙).

사용:
  python edge/host_metrics.py --matrix data/host_matrix.json.gz --out data/host_features.csv
  python edge/host_metrics.py --prom http://10.16.1.1:9090 --start 2026-10-25T00:00:00Z --end 2026-10-25T06:00:00Z --out data/host_features.csv
  python edge/host_metrics.py --snapshots data/host_snap --out data/host_features.csv --per-host-dir data/host_by_host
"""
import argparse
import csv
import glob
import gzip
import json
import os
import re
import statistics
import sys
import time
import urllib.parse
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

# 가져올 원시 지표 (node_exporter 표준 이름). 카운터는 속도로, 게이지는 값 그대로 쓴다.
COUNTERS = ["node_cpu_seconds_total", "node_network_receive_bytes_total",
            "node_network_transmit_bytes_total", "node_disk_read_bytes_total",
            "node_disk_written_bytes_total"]
GAUGES = ["node_load1", "node_memory_MemAvailable_bytes", "node_memory_MemTotal_bytes",
          "node_netstat_Tcp_CurrEstab", "node_procs_running"]
# 가상/루프백 NIC 은 호스트 바깥 트래픽이 아니라 제외 (컨테이너 내부 통신이 유출처럼 보이는 것 방지)
# 본딩·브리지(bond0·vmbr0·team0)는 멤버 NIC 의 합이라 같이 세면 이중 집계 → 멤버(물리)만 센다
SKIP_NIC_RE = re.compile(r"^(lo|veth|docker|br-|virbr|cni|flannel|cali|bond|team|vmbr)")
SKIP_DISK_RE = re.compile(r"^(loop|ram|sr|dm-|md)")   # dm-/md 는 멤버 디스크의 논리 묶음(이중 집계)
BUSY_HIGH = 0.8   # cpu_busy_sustain: 구간 안에서 CPU 가 이 값 이상인 표본 비율

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml"))
from feature_spec import columns  # noqa: E402

HOST_FEATURES = columns("host_v1")   # 열 정의는 ml/feature_spec.py 한 곳 (window_row 순서와 같아야 함)
PROM_MAX_SPAN = 86400                 # query_range 1회 범위(초). Prometheus 는 시계열당 11,000점 제한(15s x ~45h)

PROM_LINE_RE = re.compile(r'^(?P<name>[a-zA-Z_:][\w:]*)(?:\{(?P<labels>[^}]*)\})?\s+(?P<value>\S+)')
LABEL_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


def host_of(instance: str) -> str:
    """'10.16.1.10:9100' → '10.16.1.10'. 웹/DB 피처의 출발지 키와 같은 모양으로."""
    return instance.rsplit(":", 1)[0] if instance.count(":") == 1 else instance


def keep(name, labels) -> bool:
    if name not in COUNTERS and name not in GAUGES:
        return False
    if name.startswith("node_network_"):
        return not SKIP_NIC_RE.match(labels.get("device", ""))
    if name.startswith("node_disk_"):
        return not SKIP_DISK_RE.match(labels.get("device", ""))
    return True


def series_key(name, labels):
    """같은 지표의 시계열 구분 키 (cpu·mode·device). instance/job 은 호스트 키라 빼고."""
    return (name,) + tuple(sorted((k, v) for k, v in labels.items() if k not in ("instance", "job", "__name__")))


# ── 입력 1·2: Prometheus query_range (API 또는 저장 파일) ───────────────────────────
def add_matrix(doc, store):
    """query_range 응답 → store[host][series_key] = [(ts, value), ...]"""
    if doc.get("status") != "success" or doc.get("data", {}).get("resultType") != "matrix":
        raise ValueError("query_range matrix 응답이 아님")
    for s in doc["data"]["result"]:
        labels = s["metric"]
        name = labels.get("__name__", "")
        if not keep(name, labels):
            continue
        host = host_of(labels.get("instance", "unknown"))
        store[host][series_key(name, labels)].extend((float(t), float(v)) for t, v in s["values"])


def load_matrix_file(path, store):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as f:
        text = f.read()
    # 파일 하나에 응답 하나(JSON) 또는 여러 개(JSON lines) 둘 다 받는다
    try:
        docs = [json.loads(text)]
    except json.JSONDecodeError:
        docs = [json.loads(line) for line in text.splitlines() if line.strip()]
    for d in docs:
        add_matrix(d, store)


def to_epoch(s):
    """ISO8601 -> epoch. 시간대가 없으면 UTC 로 본다(로컬 KST 로 해석돼 9시간 밀리는 것 방지)."""
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()


def fetch_prom(url, start, end, step, store):
    """지표 이름마다 query_range. 원시 카운터를 그대로 받아 속도 계산은 여기서(스냅샷 경로와 같은 코드).
    긴 범위는 PROM_MAX_SPAN 단위로 나눠 받는다(경계 시각 중복은 rates() 가 같은 시각을 버려 무해)."""
    t, t_end = to_epoch(start), to_epoch(end)
    while t < t_end:
        t2 = min(t + PROM_MAX_SPAN, t_end)
        for name in COUNTERS + GAUGES:
            q = urllib.parse.urlencode({"query": name, "start": t, "end": t2, "step": step})
            try:
                with urllib.request.urlopen(f"{url.rstrip('/')}/api/v1/query_range?{q}", timeout=30) as r:
                    add_matrix(json.load(r), store)
            except urllib.error.HTTPError as e:
                sys.exit(f"Prometheus 오류 {e.code} ({name}): {e.read().decode('utf-8', 'replace')[:300]}")
        t = t2


# ── 입력 3: node_exporter 텍스트 스냅샷 ──────────────────────────────────────────────
def parse_exposition(text):
    """Prometheus 텍스트 노출 형식 → [(name, labels, value)]. 주석·HELP·TYPE 줄은 건너뜀."""
    out = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        m = PROM_LINE_RE.match(line)
        if not m:
            continue
        try:
            v = float(m["value"])
        except ValueError:
            continue
        out.append((m["name"], dict(LABEL_RE.findall(m["labels"] or "")), v))
    return out


def load_snapshots(root, store):
    n = 0
    for path in glob.glob(os.path.join(root, "*", "*.prom")):
        host = os.path.basename(os.path.dirname(path))
        try:
            ts = float(os.path.splitext(os.path.basename(path))[0])
        except ValueError:
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            for name, labels, v in parse_exposition(f.read()):
                if keep(name, labels):
                    store[host][series_key(name, labels)].append((ts, v))
        n += 1
    return n


def collect(url, out_dir, interval, duration, host):
    """Prometheus 없이 /metrics 를 주기적으로 떠서 DIR/<host>/<epoch>.prom 로 저장 (랩용)."""
    host = host or host_of(urllib.parse.urlparse(url).netloc)
    d = os.path.join(out_dir, host)
    os.makedirs(d, exist_ok=True)
    end = time.time() + duration
    n = 0
    while time.time() < end:
        t0 = time.time()
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                body = r.read().decode("utf-8", errors="replace")
            with open(os.path.join(d, f"{int(t0)}.prom"), "w", encoding="utf-8") as f:
                f.write(body)
            n += 1
        except OSError as e:
            print(f"수집 실패({e}) — 다음 주기에 재시도", file=sys.stderr)
        time.sleep(max(0.0, interval - (time.time() - t0)))
    print(f"{n}개 스냅샷 → {d}")


# ── 원시 시계열 → 표본별 순간값 → 구간 피처 ───────────────────────────────────────
def rates(points):
    """카운터 [(ts, v)] → [(ts, 초당 증가량)]. 리셋(음수 차분)·같은 시각은 버린다."""
    pts = sorted(points)
    out = []
    for (t0, v0), (t1, v1) in zip(pts, pts[1:]):
        if t1 > t0 and v1 >= v0:
            out.append((t1, (v1 - v0) / (t1 - t0)))
    return out


def fresh_times(series):
    """CPU 카운터 합이 실제로 늘어난 시각 = 새로 긁힌 표본. CPU 지표가 없으면 None.
    query_range 의 step 이 scrape 간격보다 짧으면 Prometheus 는 마지막 값을 반복해 준다. 반복 시각을 남기면
    차분 0 표본 뒤 표본이 scrape 간격치 증가를 step 하나로 나눠 속도가 (간격/step)배 부푼다 -> 반복 시각을 먼저 버린다.
    (idle 은 실제로 항상 증가하므로 CPU 합이 기준으로 안전.)"""
    total = defaultdict(float)
    for key, pts in series.items():
        if key[0] == "node_cpu_seconds_total":
            for t, v in pts:
                total[t] += v
    if not total:
        return None
    keep_ts, last = set(), None
    for t in sorted(total):
        if last is None or total[t] > last:
            keep_ts.add(t)
            last = total[t]
    return keep_ts


def host_samples(series):
    """한 호스트의 시계열 묶음 → 시각별 순간값 dict {ts: {cpu_busy, ...}}. CPU 지표가 없으면 ({}, 1)."""
    fresh = fresh_times(series)
    if fresh is None:
        return {}, 1
    series = {k: [(t, v) for t, v in pts if t in fresh] for k, pts in series.items()}
    by_ts = defaultdict(lambda: defaultdict(float))
    cpu_mode = defaultdict(lambda: defaultdict(float))   # ts → mode → 초당 cpu초(전 코어 합)
    cpus = set()
    for key, pts in series.items():
        name, labels = key[0], dict(key[1:])
        if name == "node_cpu_seconds_total":
            cpus.add(labels.get("cpu"))
            for t, r in rates(pts):
                cpu_mode[t][labels.get("mode", "")] += r
        elif name in COUNTERS:
            field = {"node_network_receive_bytes_total": "rx", "node_network_transmit_bytes_total": "tx",
                     "node_disk_read_bytes_total": "disk", "node_disk_written_bytes_total": "disk"}[name]
            for t, r in rates(pts):
                by_ts[t][field] += r
        else:
            for t, v in pts:
                by_ts[t][name] = v
    for t, modes in cpu_mode.items():
        total = sum(modes.values())
        if total > 0:
            # steal(하이퍼바이저가 가져간 시간)은 게스트 부하가 아님 -> busy 에서 뺀다 (VM 시끄러운 이웃이 채굴처럼 보이는 것 방지)
            by_ts[t]["cpu_busy"] = 1 - (modes.get("idle", 0) + modes.get("iowait", 0) + modes.get("steal", 0)) / total
            by_ts[t]["cpu_iowait"] = modes.get("iowait", 0) / total
    return by_ts, max(1, len(cpus))


def window_row(samples, ncpu):
    """한 구간의 표본들 → 피처 12개. 값이 없는 지표는 0 (해당 collector 꺼짐 = 신호 없음)."""
    def col(k):
        return [s[k] for s in samples if k in s]

    def mean(xs):
        return statistics.fmean(xs) if xs else 0.0

    busy, tx, rx = col("cpu_busy"), col("tx"), col("rx")
    mem = [1 - s["node_memory_MemAvailable_bytes"] / s["node_memory_MemTotal_bytes"]
           for s in samples if s.get("node_memory_MemTotal_bytes")
           and "node_memory_MemAvailable_bytes" in s]
    tx_m, rx_m = mean(tx), mean(rx)
    return [round(mean(busy), 4),
            round(sum(b >= BUSY_HIGH for b in busy) / len(busy), 4) if busy else 0.0,
            round(mean(col("cpu_iowait")), 4),
            round(max(col("node_load1"), default=0.0) / ncpu, 4),
            round(mean(mem), 4),
            round(rx_m, 1), round(tx_m, 1),
            round(tx_m / (rx_m + 1.0), 4),                      # +1: rx 0 일 때 폭주 방지
            round(statistics.pstdev(tx) / tx_m, 4) if len(tx) > 1 and tx_m > 0 else 0.0,
            max(col("node_netstat_Tcp_CurrEstab"), default=0.0),
            round(mean(col("disk")), 1),
            max(col("node_procs_running"), default=0.0)]


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="node_exporter 지표 → 호스트 × 구간 피처 CSV")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--prom", help="Prometheus 주소 (예: http://10.16.1.1:9090)")
    src.add_argument("--matrix", action="append", help="저장된 query_range JSON(.gz 가능), 여러 번 가능")
    src.add_argument("--snapshots", help="--collect 가 만든 스냅샷 디렉터리")
    src.add_argument("--collect", metavar="METRICS_URL", help="수집 모드: node_exporter /metrics 주소")
    ap.add_argument("--start", help="--prom: 시작(ISO8601)")
    ap.add_argument("--end", help="--prom: 끝(ISO8601)")
    ap.add_argument("--step", default="15s", help="--prom: 표본 간격 (scrape_interval 과 같게)")
    ap.add_argument("--out-dir", default="data/host_snap", help="--collect: 저장 위치")
    ap.add_argument("--interval", type=float, default=15, help="--collect: 수집 주기(초)")
    ap.add_argument("--duration", type=float, default=3600, help="--collect: 수집 시간(초)")
    ap.add_argument("--host-id", help="--collect: 호스트 이름(기본 URL 의 호스트)")
    ap.add_argument("--window", type=float, default=5, help="구간 길이(분), 기본 5 — 웹/DB 피처와 같게")
    ap.add_argument("--min-coverage", type=float, default=0.5,
                    help="구간 표본 수가 기대치(구간/표본간격)의 이 비율 미만이면 버림(끊긴 수집을 '조용함'으로 오인 방지)")
    ap.add_argument("--per-host-dir", help="호스트별 CSV 도 따로 저장할 디렉터리 (호스트별 모델 학습용, docs/27 §3-4)")
    ap.add_argument("--out", help="출력 CSV")
    args = ap.parse_args()

    if args.collect:
        collect(args.collect, args.out_dir, args.interval, args.duration, args.host_id)
        return
    if not args.out:
        ap.error("--out 필요")

    store = defaultdict(lambda: defaultdict(list))
    if args.prom:
        if not (args.start and args.end):
            ap.error("--prom 에는 --start/--end 필요")
        fetch_prom(args.prom, args.start, args.end, args.step, store)
    elif args.matrix:
        for p in args.matrix:
            load_matrix_file(p, store)
    else:
        print(f"스냅샷 {load_snapshots(args.snapshots, store)}개 읽음")
    if not store:
        sys.exit("읽은 지표가 없음 — 이름/instance/기간 확인")

    win_sec = int(args.window * 60)
    rows, dropped = [], 0
    for host, series in store.items():
        by_ts, ncpu = host_samples(series)
        times = sorted(t for t, s in by_ts.items() if "cpu_busy" in s)   # 속도가 계산된 표본만 (첫 표본은 차분 불가)
        if len(times) < 2:
            print(f"경고: {host} — CPU 속도 표본 없음(node_cpu_seconds_total 미수집?) → 이 호스트 건너뜀", file=sys.stderr)
            continue
        dt = statistics.median(b - a for a, b in zip(times, times[1:]))
        need = max(2, int(args.min_coverage * win_sec / dt))
        windows = defaultdict(list)
        for t in times:
            # 속도 표본 t 는 (직전 표본, t] 의 값 -> 구간 시작 시각과 같으면 앞 구간 몫
            windows[int((t - 1e-6) // win_sec * win_sec)].append(by_ts[t])
        for ws, samples in windows.items():
            if len(samples) < need:
                dropped += 1
                continue
            start = datetime.fromtimestamp(ws, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            rows.append([host, start] + window_row(samples, ncpu))
    if not rows:
        sys.exit("만든 구간이 없음 — CPU 지표·기간·--min-coverage 확인")
    rows.sort(key=lambda r: (r[1], r[0]))

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "window_start"] + HOST_FEATURES)
        w.writerows(rows)
    if args.per_host_dir:
        os.makedirs(args.per_host_dir, exist_ok=True)
        for host in sorted({r[0] for r in rows}):
            with open(os.path.join(args.per_host_dir, f"{host}.csv"), "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["ip", "window_start"] + HOST_FEATURES)
                w.writerows(r for r in rows if r[0] == host)
        print(f"호스트별 CSV → {args.per_host_dir}/<호스트>.csv")
    print(f"호스트 {len(store)}개 × {args.window:g}분 구간 → {len(rows)}행, 피처 {len(HOST_FEATURES)}개 → {args.out}"
          + (f" (표본 부족 구간 {dropped}개 버림)" if dropped else ""))


if __name__ == "__main__":
    main()
