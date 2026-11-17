#!/usr/bin/env python3
"""attack.sh 가 남긴 실행 기록(runs/*.json) → 정답지 answer.csv (ml_detection 형식).

출력: attack_id,src,start,end,type   (evaluate.py / supervised.py / accumulate.py 가 읽는 시간구간형)
라벨은 '출발지(src) AND 시각(start~end)' 교집합으로만 붙는다(실제 라벨링은 소비 스크립트가 수행).

사용:
  python build_answer.py                       # runs/ → answer.csv
  python build_answer.py --runs runs --out answer.csv
"""
import argparse, csv, glob, json, os, sys

ap = argparse.ArgumentParser()
ap.add_argument("--runs", default="runs")
ap.add_argument("--out", default="answer.csv")
a = ap.parse_args()

files = sorted(glob.glob(os.path.join(a.runs, "*.json")))
if not files:
    sys.exit(f"기록 없음: {a.runs}/*.json — attack.sh 를 먼저 돌려라")

rows = []
for i, p in enumerate(files):
    r = json.load(open(p, encoding="utf-8"))
    # subtype(bola_slow 등)을 type 으로 그대로 쓰면 변주까지 구분된다.
    rows.append({"attack_id": f"{r['scenario']}#{i}", "src": r["src"],
                 "start": r["start"], "end": r["end"], "type": r["scenario"]})

with open(a.out, "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=["attack_id", "src", "start", "end", "type"])
    w.writeheader(); w.writerows(rows)

print(f"정답지 {len(rows)}건 → {a.out}")
for r in rows:
    print(f"  {r['type']:12} src={r['src']:15} {r['start']} ~ {r['end']}")
