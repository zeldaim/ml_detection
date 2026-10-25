#!/usr/bin/env python3
"""피처 소거(drop-one) 실험 — 피처셋 확정의 근거.  (docs/27)

비지도 모델(IF·LOF·AE)은 정상만으로 학습하므로, 정상 앞쪽 --normal-train 비율로 한 번 학습하고
나머지 정상 + 모든 공격 구간으로 평가한다(supervised.py 비지도 열과 같은 분할).
피처를 하나씩 빼서 탐지율이 떨어지면 그 피처가 일을 한다는 뜻.

AE·IF 는 초기값(seed)에 따라 몇 구간씩 흔들린다 → --seeds 개 seed 평균±표준편차로 낸다.
AE 은닉층 크기는 전체 피처셋 기준으로 고정한다(피처를 빼며 용량까지 바뀌면 피처 효과와 섞임).
(전체) 설정은 경보 등급 조합(LOF&AE 등)과 공격 종류별 탐지도 낸다 — MODEL_CARD §4 의 출처.
(seed 하나로 0.97 vs 0.88 을 비교하면 피처 효과와 초기값 운을 구분 못 한다.)

사용:
  python ml/ablation.py data/c_rel.csv --answer datasets/real_web/real_canon_answer.csv --feature-set web_v1
  python ml/ablation.py data/c_rel.csv --answer ... --groups "rel_req_count rel_max_req_1min"
"""
import argparse
import csv
import os
import sys
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evaluate import load_answer  # noqa: E402
from supervised import label_windows  # noqa: E402


COMBOS = {"IF": lambda a, l, e: a, "LOF": lambda a, l, e: l, "AE": lambda a, l, e: e,
          "IF|LOF|AE": lambda a, l, e: a | l | e, "LOF&AE": lambda a, l, e: l & e,
          "IF&LOF&AE": lambda a, l, e: a & l & e}


def run(X, normal_train, normal_test, attack, contamination, seed, hidden):
    """한 seed 로 IF·LOF·AE 를 학습해 조합별 (공격 플래그 배열, 오탐 수)를 돌려준다."""
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.neural_network import MLPRegressor
    from sklearn.preprocessing import StandardScaler

    Xn = X[normal_train]
    scaler = StandardScaler().fit(Xn)
    Xsn = scaler.transform(Xn)
    iso = IsolationForest(n_estimators=300, contamination=contamination, random_state=seed).fit(Xn)
    lof = LocalOutlierFactor(n_neighbors=max(2, min(20, len(Xn) - 1)),
                             contamination=contamination, novelty=True).fit(Xsn)
    ae = MLPRegressor(hidden_layer_sizes=(hidden,), activation="relu",
                      max_iter=1500, random_state=seed).fit(Xsn, Xsn)
    thr = np.quantile(((ae.predict(Xsn) - Xsn) ** 2).mean(axis=1), 1 - contamination)

    def flags(idx):
        Xs = scaler.transform(X[idx])
        f = (iso.predict(X[idx]) == -1, lof.predict(Xs) == -1,
             ((ae.predict(Xs) - Xs) ** 2).mean(axis=1) >= thr)
        return {k: fn(*f) for k, fn in COMBOS.items()}

    fa, fn = flags(attack), flags(normal_test)
    return {k: (fa[k], int(fn[k].sum())) for k in fa}


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="피처 drop-one 소거 실험 (seed 평균)")
    ap.add_argument("features")
    ap.add_argument("--answer", required=True)
    ap.add_argument("--window", type=float, default=5)
    ap.add_argument("--normal-train", type=float, default=0.7)
    ap.add_argument("--contamination", type=float, default=0.05)
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--feature-set", help="ml/feature_spec.py 의 셋(예: web_v1)으로 열을 제한")
    ap.add_argument("--groups", nargs="*", default=[],
                    help="함께 뺄 피처 묶음(공백 구분 문자열 하나가 한 묶음)")
    args = ap.parse_args()

    import numpy as np

    rows = list(csv.DictReader(open(args.features, encoding="utf-8")))
    all_cols = [c for c in rows[0] if c not in ("ip", "window_start")]
    if args.feature_set:
        from feature_spec import columns
        all_cols = columns(args.feature_set)
    labels = label_windows(rows, load_answer(args.answer), timedelta(minutes=args.window))
    normal = sorted((i for i, l in enumerate(labels) if l is None), key=lambda i: rows[i]["window_start"])
    cut = int(len(normal) * args.normal_train)
    normal_train, normal_test = normal[:cut], normal[cut:]
    attack = [i for i, l in enumerate(labels) if l is not None]
    print(f"피처 {len(all_cols)}개 · 정상 학습 {len(normal_train)} / 평가 {len(normal_test)} · "
          f"공격 구간 {len(attack)} · seed {args.seeds}개 · contamination {args.contamination}\n")

    configs = [("(전체)", [])] + [(c, [c]) for c in all_cols] + [(g, g.split()) for g in args.groups]
    models = ["IF", "LOF", "AE", "IF|LOF|AE"]
    hidden = max(2, len(all_cols) // 2)
    full = None
    print(f"{'뺀 피처':<36}" + "".join(f"{m + ' 탐지':>18}" for m in models) + f"{'앙상블 오탐':>12}")
    for name, drop in configs:
        cols = [c for c in all_cols if c not in drop]
        X = np.array([[float(r[c] or 0) for c in cols] for r in rows])
        res = [run(X, normal_train, normal_test, attack, args.contamination, s, hidden) for s in range(args.seeds)]
        if not drop:
            full = res
        line = f"{name[:35]:<36}"
        for m in models:
            rec = np.array([r[m][0].sum() for r in res]) / len(attack)
            line += f"{rec.mean():>12.2f}±{rec.std():.2f}"
        fpr = np.array([r["IF|LOF|AE"][1] for r in res]) / len(normal_test)
        line += f"{fpr.mean():>12.3f}"
        print(line)
    print("\n읽는 법: (전체) 대비 탐지율이 떨어지면 그 피처가 기여. ±는 seed 간 표준편차(LOF는 결정적이라 0).")

    print(f"\n── (전체) 경보 등급 조합 (seed {args.seeds}개) ──")
    for k in COMBOS:
        rec = np.array([r[k][0].sum() for r in full]) / len(attack)
        fp = np.array([r[k][1] for r in full])
        print(f"  {k:<11} 탐지 {rec.mean():.2f}±{rec.std():.2f} · 정상 오탐 평균 {fp.mean():.1f}/{len(normal_test)}")
    print("\n── (전체) 공격 종류별 탐지 구간 수 (seed 평균) ──")
    for t in sorted({labels[i][1] for i in attack}):
        sel = np.array([labels[i][1] == t for i in attack])
        cells = "  ".join(f"{k} {np.mean([r[k][0][sel].sum() for r in full]):.1f}" for k in ("IF|LOF|AE", "LOF", "IF"))
        print(f"  {t:<14} n={int(sel.sum()):<3} {cells}")


if __name__ == "__main__":
    main()
