#!/usr/bin/env python3
"""저장된 모델(.joblib)을 불러 새 피처에 판정을 매긴다.  (train_export.py가 만든 묶음을 씀)

학습 과정 없이 저장된 모델만 불러 쓴다 → 배포/실시간에 가까운 사용 예.

사용:
  python ml/predict.py models/model.joblib data/features_new.csv
  python ml/predict.py models/model.joblib data/features_new.csv --out data/pred.csv
"""
import argparse
import csv
import os
import sys


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="저장된 모델로 새 피처 판정")
    ap.add_argument("model", help="train_export.py가 만든 .joblib")
    ap.add_argument("features", help="판정할 피처 CSV")
    ap.add_argument("--out", help="판정 결과 CSV 저장(선택)")
    args = ap.parse_args()

    import joblib
    import numpy as np

    b = joblib.load(args.model)
    cols = b["features"]
    rows = list(csv.DictReader(open(args.features, encoding="utf-8")))
    missing = [c for c in cols if c not in rows[0]]
    if missing:
        sys.exit(f"피처 CSV에 없는 열: {missing} — 학습 때와 같은 피처가 필요")
    X = np.array([[float(r[c] or 0) for c in cols] for r in rows])

    Xs = b["scaler"].transform(X)
    if_flag = b["iforest"].predict(X) == -1
    lof_flag = b["lof"].predict(Xs) == -1
    # Autoencoder: 재구성 오차 > 저장된 경계면 이상 (구버전 번들엔 없을 수 있어 방어적으로)
    if b.get("autoencoder") is not None:
        ae_err = ((b["autoencoder"].predict(Xs) - Xs) ** 2).mean(axis=1)
        ae_flag = ae_err >= b["ae_threshold"]
    else:
        ae_flag = [False] * len(rows)
    rf_pred = b["rf"].predict(X) if b["rf"] is not None else [""] * len(rows)

    print(f"모델: {args.model} (학습 {b['trained_at']}, 정상 {b['n_normal']}구간, contamination {b['contamination']})")
    hdr = f"{'ip':<16}{'window_start':<22}{'IF':>5}{'LOF':>5}{'AE':>5}{'합집합':>8}"
    if b["rf"] is not None:
        hdr += f"{'RF 분류':>12}"
    print(hdr)
    out = []
    for i, r in enumerate(rows):
        a, l, e = bool(if_flag[i]), bool(lof_flag[i]), bool(ae_flag[i])
        anom = a or l or e            # 비지도 셋 중 하나라도 이상
        mark = lambda x: "이상" if x else "·"
        line = f"{r['ip']:<16}{r['window_start']:<22}{mark(a):>5}{mark(l):>5}{mark(e):>5}{mark(anom):>8}"
        if b["rf"] is not None:
            line += f"{rf_pred[i]:>12}"
        print(line)
        out.append({"ip": r["ip"], "window_start": r["window_start"],
                    "iforest": int(a), "lof": int(l), "autoencoder": int(e),
                    "anomaly": int(anom), "rf_class": rf_pred[i]})

    n_anom = sum(o["anomaly"] for o in out)
    print(f"\n구간 {len(out)}개 중 IF|LOF|AE 이상 {n_anom}개")
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        with open(args.out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(out[0]))
            w.writeheader()
            w.writerows(out)
        print(f"저장: {args.out}")


if __name__ == "__main__":
    main()
