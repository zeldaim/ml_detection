#!/usr/bin/env python3
"""두 모델 번들(.joblib)이 같은 모델인지 비교 — 재학습이 원본을 재현했는지 확인용.

파일 바이트가 아니라 내용을 본다: 피처 순서 · 학습 정상 구간 수 · AE 경계 ·
같은 피처 CSV 에 대한 IF/LOF/AE/RF 예측이 모두 같으면 OK.

  python tools/compare_bundles.py models/model_web_v3.1.joblib /tmp/rt/model_web_v3.1.joblib /tmp/c_rel.csv
"""
import csv
import os
import sys
import warnings

import joblib
import numpy as np

warnings.filterwarnings("ignore")


def main():
    if len(sys.argv) != 4:
        sys.exit("사용법: compare_bundles.py <원본.joblib> <재학습.joblib> <피처 CSV>")
    orig, new, csv_path = sys.argv[1:4]
    a, b = joblib.load(orig), joblib.load(new)
    rows = list(csv.DictReader(open(csv_path, encoding="utf-8")))
    X = np.array([[float(r.get(c) or 0) for c in a["features"]] for r in rows])
    Xa, Xb = a["scaler"].transform(X), b["scaler"].transform(X)

    rf_same = (a.get("rf") is None and b.get("rf") is None) or (
        a.get("rf") is not None and b.get("rf") is not None
        and (a["rf"].predict(X) == b["rf"].predict(X)).all())
    checks = {
        "features": a["features"] == b["features"],
        "n_normal": a["n_normal"] == b["n_normal"],
        "ae_threshold": np.isclose(a["ae_threshold"], b["ae_threshold"]),
        "IF": (a["iforest"].predict(X) == b["iforest"].predict(X)).all(),
        "LOF": (a["lof"].predict(Xa) == b["lof"].predict(Xb)).all(),
        "AE": np.allclose(a["autoencoder"].predict(Xa), b["autoencoder"].predict(Xb)),
        "RF": rf_same,
    }
    bad = [k for k, ok in checks.items() if not ok]
    name = os.path.basename(orig)
    if bad:
        print(f"DIFF {name}  다른 항목: {bad}  (정상 구간 {a['n_normal']} vs {b['n_normal']})")
        sys.exit(1)
    print(f"OK   {name}")


if __name__ == "__main__":
    main()
