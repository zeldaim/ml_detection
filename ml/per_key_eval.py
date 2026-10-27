#!/usr/bin/env python3
"""통합 모델 vs 키(호스트)별 기준선 모델 — 같은 피처로 둘을 나란히 채점.  (docs/27 §3-3)

호스트 지표는 호스트마다 '평소'가 다르다(DB 서버의 평소 송신 = 앱 서버의 유출 수준).
모든 호스트를 한 모델로 학습하면 한 호스트의 이상이 다른 호스트의 정상 범위에 묻힌다.
→ 키별로 따로 학습하면 잡히나? 를 데이터로 확인한다. (웹 UEBA §K 의 '자기 대비' 원리를 모델 단위로 적용)

분할(둘 다 동일): 각 키의 정상 구간 시간순 앞 --normal-train 비율 = 학습, 나머지 정상 + 공격 = 평가.
통합 모델은 모든 키의 학습분을 합쳐 1개, 키별 모델은 키마다 1개.

사용:
  python ml/per_key_eval.py data/host_features.csv --answer data/host_answer.csv
"""
import argparse
import csv
import os
import sys
import warnings
from collections import defaultdict
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evaluate import load_answer  # noqa: E402
from supervised import label_windows  # noqa: E402

MODELS = ["IF", "LOF", "AE", "IF|LOF|AE"]


def fit_predict(X, train, test_sets, contamination):
    """정상 train 으로 IF·LOF·AE 학습 → test_sets 각각의 플래그 dict."""
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.neural_network import MLPRegressor
    from sklearn.preprocessing import StandardScaler

    sc = StandardScaler().fit(X[train])
    Xs = sc.transform(X[train])
    iso = IsolationForest(n_estimators=300, contamination=contamination, random_state=0).fit(X[train])
    lof = LocalOutlierFactor(n_neighbors=max(2, min(20, len(train) - 1)),
                             contamination=contamination, novelty=True).fit(Xs)
    ae = MLPRegressor(hidden_layer_sizes=(max(2, X.shape[1] // 2),), activation="relu",
                      max_iter=1500, random_state=0).fit(Xs, Xs)
    thr = np.quantile(((ae.predict(Xs) - Xs) ** 2).mean(axis=1), 1 - contamination)
    out = []
    for idx in test_sets:
        if not idx:
            out.append({m: np.zeros(0, bool) for m in MODELS})
            continue
        Z = sc.transform(X[idx])
        a, l = iso.predict(X[idx]) == -1, lof.predict(Z) == -1
        e = ((ae.predict(Z) - Z) ** 2).mean(axis=1) >= thr
        out.append({"IF": a, "LOF": l, "AE": e, "IF|LOF|AE": a | l | e})
    return out


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    warnings.filterwarnings("ignore", category=UserWarning)
    from sklearn.exceptions import ConvergenceWarning
    warnings.filterwarnings("ignore", category=ConvergenceWarning)
    ap = argparse.ArgumentParser(description="통합 vs 키별 기준선 모델 비교")
    ap.add_argument("features")
    ap.add_argument("--answer", required=True)
    ap.add_argument("--window", type=float, default=5)
    ap.add_argument("--normal-train", type=float, default=0.7)
    ap.add_argument("--contamination", type=float, default=0.05)
    ap.add_argument("--drop", nargs="*", default=[], help="뺄 피처 (예: rel_ 로 시작하는 열)")
    ap.add_argument("--min-train", type=int, default=5, help="키별 모델에 필요한 최소 정상 학습 구간")
    args = ap.parse_args()

    import numpy as np

    rows = list(csv.DictReader(open(args.features, encoding="utf-8")))
    cols = [c for c in rows[0] if c not in ("ip", "window_start") and c not in args.drop]
    X = np.array([[float(r[c] or 0) for c in cols] for r in rows])
    labels = label_windows(rows, load_answer(args.answer), timedelta(minutes=args.window))

    split, skipped = {}, []
    for key in sorted({r["ip"] for r in rows}):
        idx = [i for i, r in enumerate(rows) if r["ip"] == key]
        normal = sorted((i for i in idx if labels[i] is None), key=lambda i: rows[i]["window_start"])
        cut = int(len(normal) * args.normal_train)
        if cut < args.min_train:   # 평소가 없는 키(공격 전용 IP 등)는 키별 기준선을 못 만든다
            skipped.append((key, cut, sum(labels[i] is not None for i in idx)))
            continue
        split[key] = (normal[:cut], normal[cut:], [i for i in idx if labels[i] is not None])
    if not split:
        sys.exit(f"정상 학습 구간이 {args.min_train}개 이상인 키가 없음 — 키별 비교 불가(웹 정본처럼 공격 전용 IP 데이터엔 맞지 않음)")
    print(f"피처 {len(cols)}개 · 키 {len(split)}개 · contamination {args.contamination}")
    if skipped:
        print(f"제외한 키 {len(skipped)}개 (정상 학습 < {args.min_train}, 공격 구간 {sum(s[2] for s in skipped)}개는 비교에서 빠짐): "
              + ", ".join(k for k, _, _ in skipped[:8]) + (" …" if len(skipped) > 8 else ""))
    print()

    if not any(at for _, _, at in split.values()):
        sys.exit("남은 키에 공격 구간이 없음 — 공격이 '평소가 있는 키'에서 일어난 데이터여야 비교 가능")
    all_train = [i for tr, _, _ in split.values() for i in tr]
    all_test = [i for _, te, _ in split.values() for i in te]
    all_att = [i for _, _, at in split.values() for i in at]
    pooled_a, pooled_n = fit_predict(X, all_train, [all_att, all_test], args.contamination)

    per_a, per_n = defaultdict(list), defaultdict(list)   # 모델 → 키별 플래그를 all_att/all_test 순서로 이어붙임
    for key, (tr, te, at) in split.items():
        fa, fn = fit_predict(X, tr, [at, te], args.contamination)
        for m in MODELS:
            per_a[m].append(fa[m])
            per_n[m].append(fn[m])
    per_a = {m: np.concatenate(v) for m, v in per_a.items()}
    per_n = {m: np.concatenate(v) for m, v in per_n.items()}

    types = sorted({labels[i][1] for i in all_att})
    print(f"{'공격 종류':<16}{'구간':>5}  " + "".join(f"{'통합 ' + m:>16}{'키별 ' + m:>16}" for m in ("LOF", "IF|LOF|AE")))
    for t in types:
        sel = np.array([labels[i][1] == t for i in all_att])
        line = f"{t:<16}{int(sel.sum()):>5}  "
        for m in ("LOF", "IF|LOF|AE"):
            line += f"{int(pooled_a[m][sel].sum()):>16}{int(per_a[m][sel].sum()):>16}"
        print(line)
    print("\n── 합계 ──")
    for m in MODELS:
        print(f"{m:<10} 통합: 탐지 {pooled_a[m].mean():.2f} ({int(pooled_a[m].sum())}/{len(all_att)}) · "
              f"오탐 {pooled_n[m].mean():.2f} ({int(pooled_n[m].sum())}/{len(all_test)})   |   "
              f"키별: 탐지 {per_a[m].mean():.2f} ({int(per_a[m].sum())}/{len(all_att)}) · "
              f"오탐 {per_n[m].mean():.2f} ({int(per_n[m].sum())}/{len(all_test)})")


if __name__ == "__main__":
    main()
