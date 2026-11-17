#!/usr/bin/env python3
"""플라이휠: 라벨 붙인 피처를 누적 데이터셋에 append 한다.  (docs/19)

탐지는 모델을 쓰는 것, 학습은 쌓인 데이터로 다시 만드는 것.
이 스크립트는 "한 번의 수집분(피처 + 정답지)"을 받아
  - 각 구간에 라벨(공격 종류 또는 normal)을 붙이고
  - source(어느 랩/언제)·labeled_at provenance 를 달아
  - 누적 데이터셋 CSV 에 '같은 스키마로' append 한다.

라벨 규칙: evaluate.py 와 동일 — 출발지(src) AND 시각(start~end) 교집합일 때만 그 공격 종류.
          그 외는 normal (공격 중 흐른 정상 트래픽도 normal 로 남는다).

스키마 고정이 핵심: 열 순서/이름이 매번 같아야 쌓인다. 피처를 늘리면 SCHEMA_VERSION 을 올리고
과거분을 재생성해 다시 쌓는다(섞으면 안 됨).

사용:
  # 첫 삽: 기존 합성 데이터를 누적셋에 쌓기
  python ml/accumulate.py data/features_combined.csv --answer data/answer.csv \
      --source synth_juiceshop --dataset data/dataset_web.csv

  # 다음 바퀴: 실제 로그로 만든 피처를 같은 누적셋에 append
  python ml/accumulate.py data/features_real.csv --answer data/answer_real.csv \
      --source real_juiceshop_2026-10-24 --dataset data/dataset_web.csv

  # 쌓인 현황
  python ml/accumulate.py --dataset data/dataset_web.csv --stats
"""
import argparse
import csv
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evaluate import load_answer, parse_utc  # noqa: E402

SCHEMA_VERSION = 1
META_COLS = ["label", "source", "schema_version", "labeled_at"]


def label_type(ip, ws, attacks, win):
    """구간(ip, window_start)에 맞는 공격 종류를 돌려준다. 없으면 'normal'."""
    for src, start, end, typ in attacks:
        if src != ip:
            continue
        if start is None or (ws < end and ws + win > start):
            return typ or "attack"
    return "normal"


def read_stats(dataset):
    if not os.path.exists(dataset):
        print(f"누적셋 없음: {dataset}")
        return
    rows = list(csv.DictReader(open(dataset, encoding="utf-8")))
    print(f"누적셋: {dataset}  ({len(rows)}행)")
    print("  라벨 분포:", dict(Counter(r["label"] for r in rows)))
    print("  출처 분포:", dict(Counter(r["source"] for r in rows)))
    vers = set(r.get("schema_version") for r in rows)
    if len(vers) > 1:
        print(f"  ⚠ 스키마 버전 섞임: {vers} — 과거분 재생성 필요")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="플라이휠 누적 데이터셋 append")
    ap.add_argument("features", nargs="?", help="features.py 출력 CSV (한 번의 수집분)")
    ap.add_argument("--answer", help="정답지 CSV (attack_id,src,start,end,type 또는 ip,label,type)")
    ap.add_argument("--source", help="이 수집분의 출처 태그 (예: real_juiceshop_2026-10-24)")
    ap.add_argument("--dataset", default="data/dataset_web.csv", help="누적 데이터셋 경로")
    ap.add_argument("--window", type=float, default=5, help="구간 길이(분) — features.py와 같게")
    ap.add_argument("--stats", action="store_true", help="누적 현황만 출력")
    args = ap.parse_args()

    if args.stats:
        read_stats(args.dataset)
        return

    if not (args.features and args.answer and args.source):
        ap.error("features, --answer, --source 가 모두 필요하다 (또는 --stats)")

    win = timedelta(minutes=args.window)
    attacks = load_answer(args.answer)
    src_rows = list(csv.DictReader(open(args.features, encoding="utf-8")))
    if not src_rows:
        print("입력 피처가 비어있다", file=sys.stderr)
        sys.exit(1)

    feat_cols = list(src_rows[0].keys())  # ip, window_start, <features...>
    out_cols = feat_cols + META_COLS
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 누적셋 스키마 검증 (있으면 열이 같아야 함)
    exists = os.path.exists(args.dataset)
    if exists:
        with open(args.dataset, encoding="utf-8") as f:
            have = next(csv.reader(f))
        if have != out_cols:
            print("⚠ 스키마 불일치 — append 중단.", file=sys.stderr)
            print(f"  누적셋 : {have}", file=sys.stderr)
            print(f"  입력   : {out_cols}", file=sys.stderr)
            print("  피처를 바꿨다면 SCHEMA_VERSION 올리고 과거분을 재생성해 새 파일로 쌓아라.", file=sys.stderr)
            sys.exit(2)

    added = Counter()
    os.makedirs(os.path.dirname(args.dataset) or ".", exist_ok=True)
    with open(args.dataset, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(out_cols)
        for r in src_rows:
            lab = label_type(r["ip"], parse_utc(r["window_start"]), attacks, win)
            added[lab] += 1
            w.writerow([r[c] for c in feat_cols] + [lab, args.source, SCHEMA_VERSION, now])

    print(f"append {sum(added.values())}행 → {args.dataset}  (source={args.source})")
    print("  이번 라벨 분포:", dict(added))
    print()
    read_stats(args.dataset)


if __name__ == "__main__":
    main()
