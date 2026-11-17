#!/usr/bin/env python3
"""UEBA 상대 피처 — 출발지의 '평소 대비 배수'를 더한다.  (docs/21 §K, docs/19 §6-1 상대속도)

아이디어(사용자 제안): "빠름"을 절대값이 아니라 **그 출발지의 평소 대비**로 보면,
빠른 합법 클라이언트(평소가 빠름→배수 ~1)와 급변(탈취, 평소의 N배)을 가른다. = UEBA/정규화.

입력: features.py 출력 CSV (ip, window_start, 피처...). 시간순 정렬 가정 안 함(여기서 정렬).
출력: 같은 CSV + rel_<feature> 열 (각 IP의 '기준선' 대비 배수).

기준선(baseline) 정하기:
  --mode self      : 그 IP의 '첫 --baseline-frac 비율' 구간 중앙값 (평소→급변 탐지; 탈취형)
  --mode expanding : 각 구간 직전까지 그 IP의 누적 중앙값 (온라인 UEBA 근사)
  --mode peer      : 전체 정상 IP의 중앙값 (또래 대비; 평소 이력 없을 때)
기준선이 0이면 배수=요청수(+1 스무딩)로 폭주 방지.

사용:
  python ml/relative_features.py data/x_features.csv --mode self --cols req_count max_req_1min --out data/x_rel.csv
"""
import argparse
import csv
import statistics as st
from collections import defaultdict
from datetime import datetime


def parse_ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def median(xs):
    xs = [x for x in xs if x is not None]
    return st.median(xs) if xs else 0.0


def main():
    ap = argparse.ArgumentParser(description="UEBA 상대 피처 추가")
    ap.add_argument("features")
    ap.add_argument("--out", required=True)
    ap.add_argument("--cols", nargs="+", default=["req_count", "max_req_1min"],
                    help="상대화할 피처(속도/양 위주)")
    ap.add_argument("--mode", choices=["self", "expanding", "peer"], default="self")
    ap.add_argument("--baseline-frac", type=float, default=0.4,
                    help="self 모드: 각 IP 앞쪽 몇 비율을 평소로 볼지")
    args = ap.parse_args()

    rows = list(csv.DictReader(open(args.features, encoding="utf-8")))
    if not rows:
        raise SystemExit("빈 입력")
    for r in rows:
        r["_ts"] = parse_ts(r["window_start"])
    rows.sort(key=lambda r: (r["ip"], r["_ts"]))

    by_ip = defaultdict(list)
    for r in rows:
        by_ip[r["ip"]].append(r)

    # peer 기준선: 전체 IP별 중앙값들의 중앙값(또래 평소)
    peer_base = {}
    if args.mode == "peer":
        for c in args.cols:
            per_ip_med = [median([float(x[c]) for x in g]) for g in by_ip.values()]
            peer_base[c] = median(per_ip_med)

    rel_cols = [f"rel_{c}" for c in args.cols]
    for ip, g in by_ip.items():
        for c in args.cols:
            vals = [float(x[c]) for x in g]
            if args.mode == "self":
                k = max(1, int(len(g) * args.baseline_frac))
                base = median(vals[:k])
            for i, x in enumerate(g):
                if args.mode == "expanding":
                    base = median(vals[:i]) if i > 0 else vals[0]
                elif args.mode == "peer":
                    base = peer_base[c]
                b = base if base and base > 0 else 1.0
                x[f"rel_{c}"] = round(float(x[c]) / b, 4)

    out_cols = [k for k in rows[0].keys() if not k.startswith("_")]
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=out_cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: r[k] for k in out_cols})
    print(f"{len(rows)}행 → {args.out}  (+{', '.join(rel_cols)}, mode={args.mode})")


if __name__ == "__main__":
    main()
