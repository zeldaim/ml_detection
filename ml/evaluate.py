#!/usr/bin/env python3
"""탐지 결과 채점: Precision / Recall / F1.  (docs/10 §3-5)

정답지 형식 (둘 중 하나)
  ① 시간 구간형 (docs/05 §5-2, docs/08 §4): attack_id,src,start,end,type
     → 그 IP의 구간 중 [start, end)와 겹치는 구간 = 양성
  ② IP형 (labs/01 answer.csv와 같음): ip,label,type   (label = attack / normal)
     → 그 IP의 모든 구간 = 양성

채점 단위 두 가지를 함께 낸다
  구간 : IP × 시간 구간 하나하나
  IP   : 구간 중 하나라도 이상이면 그 IP를 이상으로

--train-until로 학습한 경우 기본은 학습 밖 구간만 채점한다 (--include-train으로 전체).

사용:
  python ml/evaluate.py data/detections.csv --answer samples/sample_answer_if.csv
"""
import argparse
import csv
import sys
from collections import defaultdict
from datetime import datetime, timedelta


def parse_utc(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def load_answer(path):
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    if rows and "start" in rows[0]:
        return [(r["src"], parse_utc(r["start"]), parse_utc(r["end"]), r.get("type", ""))
                for r in rows]
    return [(r["ip"], None, None, r.get("type", "")) for r in rows if r.get("label") == "attack"]


def is_positive(ip, ws, attacks, win):
    for src, start, end, _ in attacks:
        if src != ip:
            continue
        if start is None or (ws < end and ws + win > start):
            return True
    return False


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="탐지 결과 P/R/F1 채점")
    ap.add_argument("detections", help="ml/models.py 출력 CSV")
    ap.add_argument("--answer", required=True, help="정답지 CSV")
    ap.add_argument("--window", type=float, default=5, help="구간 길이(분) — features.py와 같게")
    ap.add_argument("--include-train", action="store_true", help="학습 구간도 채점")
    args = ap.parse_args()

    attacks = load_answer(args.answer)
    win = timedelta(minutes=args.window)
    dets = list(csv.DictReader(open(args.detections, encoding="utf-8")))
    has_test = any(d["in_train"] == "0" for d in dets)
    if has_test and not args.include_train:
        dets = [d for d in dets if d["in_train"] == "0"]
        print("채점 범위: 학습 밖 구간만\n")
    else:
        print("채점 범위: 전체 구간\n")

    by_method = defaultdict(list)
    for d in dets:
        by_method[d["method"]].append(d)

    print(f"{'방법':<8}{'단위':<5}{'TP':>4}{'FP':>4}{'FN':>4}{'TN':>5}"
          f"{'Precision':>11}{'Recall':>8}{'F1':>7}")
    per_attack = defaultdict(dict)
    for method, ds in by_method.items():
        # 구간 단위
        c = defaultdict(int)
        ip_flag, ip_pos = defaultdict(bool), defaultdict(bool)
        for d in ds:
            pos = is_positive(d["ip"], parse_utc(d["window_start"]), attacks, win)
            flag = d["is_anomaly"] == "1"
            c[(pos, flag)] += 1
            ip_flag[d["ip"]] |= flag
            ip_pos[d["ip"]] |= pos
        rows = [("구간", c[(True, True)], c[(False, True)], c[(True, False)], c[(False, False)])]
        # IP 단위
        ic = defaultdict(int)
        for ip in ip_flag:
            ic[(ip_pos[ip], ip_flag[ip])] += 1
        rows.append(("IP", ic[(True, True)], ic[(False, True)], ic[(True, False)], ic[(False, False)]))
        for unit, tp, fp, fn, tn in rows:
            p, r, f = prf(tp, fp, fn)
            print(f"{method:<8}{unit:<5}{tp:>4}{fp:>4}{fn:>4}{tn:>5}{p:>11.2f}{r:>8.2f}{f:>7.2f}")
        for src, _, _, typ in attacks:
            if src in ip_flag:
                per_attack[(src, typ)][method] = "탐지" if ip_flag[src] else "놓침"

    if per_attack:
        methods = list(by_method)
        print("\n── 정답지 공격별 (IP 단위) ──")
        print(f"{'IP':<18}" + "".join(f"{m:<9}" for m in methods) + "유형")
        for (src, typ), res in per_attack.items():
            print(f"{src:<18}" + "".join(f"{res.get(m, '-'):<9}" for m in methods) + typ)
    print("\n공격 건수가 적으면 한두 건에 수치가 크게 흔들린다 — TP·FP 건수를 함께 보고할 것")


if __name__ == "__main__":
    main()
