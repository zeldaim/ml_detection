#!/usr/bin/env python3
"""OTTO 세션 샘플 추출 + 행동 분포 요약.  (docs/34 §3)

OTTO Recommender Systems Dataset (CC BY 4.0, https://github.com/otto-de/recsys-dataset)
원본 otto-recsys-train.jsonl(11.3GB)은 레포에 넣지 않는다. 한 줄 = {"session": id, "events": [{"aid","ts","type"}...]}.

샘플은 무작위가 아니라 세션 id 의 crc32 로 고른다 → 같은 원본이면 언제 돌려도 같은 샘플(재현 가능, 한 번 읽기).
  crc32(str(session)) % 1000 < --per-mille  인 세션만 남긴다.

사용:
  python tools/sample_otto.py D:/data_external/otto/otto-recsys-train.jsonl \
      --per-mille 2 --out datasets/public/otto/sample_sessions.jsonl.gz --stats datasets/public/otto/sample_stats.json
"""
import argparse
import gzip
import json
import statistics
import sys
import zlib
from collections import Counter


def quantiles(xs, qs=(0.1, 0.25, 0.5, 0.75, 0.9, 0.99)):
    if not xs:
        return {}
    xs = sorted(xs)
    return {f"p{int(q * 100)}": xs[min(len(xs) - 1, int(q * len(xs)))] for q in qs}


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="OTTO 세션 해시 샘플 + 분포 요약")
    ap.add_argument("src", help="otto-recsys-train.jsonl (.gz 가능, - 면 표준입력)")
    ap.add_argument("--per-mille", type=int, default=2, help="천 분의 몇 세션을 남길지 (기본 2 = 0.2%%)")
    ap.add_argument("--out", required=True, help="샘플 jsonl.gz")
    ap.add_argument("--stats", required=True, help="분포 요약 JSON")
    args = ap.parse_args()

    if args.src == "-":  # 예: unzip -p otto-recsys-train.jsonl.zip | python tools/sample_otto.py - ...
        src = open(sys.stdin.fileno(), "r", encoding="utf-8", closefd=False)
    elif args.src.endswith(".gz"):
        src = gzip.open(args.src, "rt", encoding="utf-8")
    else:
        src = open(args.src, "r", encoding="utf-8")
    total_sessions = kept = 0
    n_events, types, gaps_s, lens, span_s = 0, Counter(), [], [], []
    ts_digits = Counter()
    with src as f, gzip.open(args.out, "wt", encoding="utf-8") as out:
        for line in f:
            total_sessions += 1
            # 전체 줄을 파싱하지 않고 세션 id 만 먼저 본다 (11GB 한 번 읽기 비용 절감)
            sid = line[line.index(":") + 1:line.index(",")].strip()
            if zlib.crc32(sid.encode()) % 1000 >= args.per_mille:
                continue
            s = json.loads(line)
            out.write(json.dumps(s, separators=(",", ":")) + "\n")
            kept += 1
            ev = s["events"]
            n_events += len(ev)
            lens.append(len(ev))
            types.update(e["type"] for e in ev)
            ts = [e["ts"] for e in ev]
            ts_digits[len(str(ts[0]))] += 1
            span_s.append(ts[-1] - ts[0])
            gaps_s.extend(b - a for a, b in zip(ts, ts[1:]))
            if total_sessions % 2_000_000 == 0:
                print(f"  읽은 세션 {total_sessions:,} · 남긴 세션 {kept:,}", flush=True)

    # ts 단위: 10자리 = 초, 13자리 = 밀리초 → 요약은 초로 통일
    unit = 1000 if ts_digits and max(ts_digits, key=ts_digits.get) == 13 else 1
    gaps = [g / unit for g in gaps_s]
    stats = {
        "source": "OTTO Recommender Systems Dataset, otto-recsys-train.jsonl (CC BY 4.0)",
        "selection": f"crc32(session) % 1000 < {args.per_mille}",
        "sessions_read": total_sessions,
        "sessions_kept": kept,
        "events": n_events,
        "ts_digits": dict(ts_digits),
        "ts_unit": "ms" if unit == 1000 else "s",
        "event_types": dict(types),
        "events_per_session": {**quantiles(lens), "mean": round(statistics.fmean(lens), 2) if lens else 0},
        "single_event_session_ratio": round(sum(1 for x in lens if x == 1) / kept, 4) if kept else 0,
        "gap_seconds": quantiles(gaps),
        "gap_over_30min_ratio": round(sum(1 for g in gaps if g > 1800) / len(gaps), 4) if gaps else 0,
        "session_span_seconds": quantiles([x / unit for x in span_s]),
    }
    with open(args.stats, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(json.dumps(stats, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
