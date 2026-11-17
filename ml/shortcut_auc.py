#!/usr/bin/env python3
"""지름길 진단 — 피처 하나만으로 정상/공격이 갈리는지 (단일 피처 AUC, 방향 무관).  (docs/33 §2)

AUC ≥ 0.99 인 피처가 있으면 데이터가 너무 쉬운 상태일 수 있다: 모델 성능이 '행동을 배워서'인지
'그 피처 하나(생성 방식의 흔적)'인지 구분이 안 된다. 공격 종류별 열도 함께 본다.
numpy 만 사용 (sklearn 불필요). 정답지 형식은 evaluate.py 와 같음.

사용 (저장소 루트에서):
  python ml/shortcut_auc.py datasets/real_web/real_canon_features.csv datasets/real_web/real_canon_answer.csv
"""
import csv
import os
import sys
from datetime import timedelta
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evaluate import load_answer
from supervised import label_windows

def auc(x, y):  # Mann-Whitney, 동점은 평균 순위
    order = np.argsort(x, kind="mergesort"); r = np.empty(len(x)); xs = x[order]
    i = 0
    while i < len(x):
        j = i
        while j + 1 < len(x) and xs[j + 1] == xs[i]: j += 1
        r[order[i:j + 1]] = (i + j) / 2 + 1; i = j + 1
    n1, n0 = y.sum(), len(y) - y.sum()
    if n1 == 0 or n0 == 0:
        return float("nan")
    return (r[y == 1].sum() - n1 * (n1 + 1) / 2) / (n1 * n0)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if len(sys.argv) != 3:
    sys.exit("사용: python ml/shortcut_auc.py <피처CSV> <정답지CSV>")
feat, ans = sys.argv[1], sys.argv[2]
if not os.path.exists(feat) or not os.path.exists(ans):
    sys.exit("파일 없음")
rows = list(csv.DictReader(open(feat, encoding="utf-8")))
labs = label_windows(rows, load_answer(ans), timedelta(minutes=5))
y = np.array([l is not None for l in labs], dtype=int)
types = sorted({l[1] for l in labs if l})
cols = [c for c in rows[0] if c not in ("ip", "window_start")]
X = {c: np.array([float(r[c] or 0) for r in rows]) for c in cols}
print(f"{feat}: 정상 {int((y==0).sum())} / 공격 {int(y.sum())} 구간\n")
print(f"{'피처':<20}{'전체':>7}" + "".join(f"{t[:11]:>12}" for t in types))
for c in cols:
    if np.ptp(X[c]) == 0:
        print(f"{c:<20}{'상수':>7}"); continue
    a = auc(X[c], y); line = f"{c:<20}{max(a,1-a):>7.3f}"
    for t in types:
        m = np.array([(l is None) or l[1] == t for l in labs])
        yt = y[m]; a = auc(X[c][m], yt); line += f"{max(a,1-a):>12.3f}"
    flag = "  ← 혼자서 거의 완벽" if max(auc(X[c], y), 1 - auc(X[c], y)) >= 0.99 else ""
    print(line + flag)
