#!/usr/bin/env python3
"""학습된 모델을 파일로 저장 — 매번 새로 학습하지 않고, 저장한 모델을 불러 바로 판정한다.  (배포·인수인계용)

지금까지(models.py·supervised.py)는 실행할 때마다 모델을 새로 fit하고 버렸다.
여기서는 정상(+라벨) 데이터로 한 번 학습한 모델을 .joblib 파일로 묶어 저장한다.
묶음 하나에: IF · LOF · (정답지 있으면 RF 다중분류) + 스케일러 + 피처 순서 + 설정.

저장:
  python ml/train_export.py data/features_combined.csv --answer data/answer.csv --out models/model.joblib
  python ml/train_export.py data/features_normal.csv --out models/baseline.joblib   # 정상만(이상탐지용)

불러 쓰기:
  python ml/predict.py models/model.joblib data/new_features.csv
"""
import argparse
import csv
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def load_features(path, drop):
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    cols = [c for c in rows[0] if c not in ("ip", "window_start") and c not in drop]
    import numpy as np
    X = np.array([[float(r[c] or 0) for c in cols] for r in rows])
    return rows, cols, X


def main():
    ap = argparse.ArgumentParser(description="학습된 모델을 .joblib로 저장")
    ap.add_argument("features", help="학습에 쓸 피처 CSV (이상탐지는 정상만, 분류는 정상+공격)")
    ap.add_argument("--answer", help="정답지 — 주면 RF 다중분류 모델도 함께 학습")
    ap.add_argument("--window", type=float, default=5)
    ap.add_argument("--contamination", type=float, default=0.05, help="IF·LOF 이상 비율 (정상 로그로 정한 값)")
    ap.add_argument("--drop", nargs="*", default=[])
    ap.add_argument("--out", default="models/model.joblib")
    args = ap.parse_args()

    import joblib
    import numpy as np
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.neural_network import MLPRegressor
    from sklearn.preprocessing import StandardScaler

    rows, cols, X = load_features(args.features, args.drop)

    # 이상탐지 모델: 정답지가 있으면 '정상'으로 라벨된 구간만으로 학습(기준=평소), 없으면 전체를 정상으로 간주
    normal_mask = np.ones(len(rows), dtype=bool)
    labels = None
    if args.answer:
        from datetime import timedelta
        from evaluate import load_answer, parse_utc
        attacks = load_answer(args.answer)
        win = timedelta(minutes=args.window)
        labels = []
        for i, r in enumerate(rows):
            ws = parse_utc(r["window_start"])
            typ = "normal"
            for src, start, end, t in attacks:
                if src == r["ip"] and start and ws < end and ws + win > start:
                    typ = t or "attack"
                    break
            labels.append(typ)
            normal_mask[i] = (typ == "normal")

    Xn = X[normal_mask]
    if len(Xn) < 5:
        sys.exit(f"정상 구간이 {len(Xn)}개뿐 — 학습 불가")

    scaler = StandardScaler().fit(Xn)               # LOF는 거리 기반 → 정상 기준 스케일
    iso = IsolationForest(n_estimators=300, contamination=args.contamination, random_state=0).fit(Xn)
    lof = LocalOutlierFactor(n_neighbors=max(2, min(20, len(Xn) - 1)),
                             contamination=args.contamination, novelty=True).fit(scaler.transform(Xn))
    # Autoencoder(MLP): 정상을 압축→복원 학습. 재구성 오차 > 임계값이면 이상 (docs/16 §0 IF 외삽 한계 보완)
    Xsn = scaler.transform(Xn)
    ae = MLPRegressor(hidden_layer_sizes=(max(2, Xn.shape[1] // 2),), activation="relu",
                      max_iter=1500, random_state=0).fit(Xsn, Xsn)
    ae_threshold = float(np.quantile(((ae.predict(Xsn) - Xsn) ** 2).mean(axis=1), 1 - args.contamination))

    bundle = {
        "features": cols,                 # 입력 피처 순서 (예측 때 똑같이 맞춰야 함)
        "contamination": args.contamination,
        "scaler": scaler,
        "iforest": iso,
        "lof": lof,
        "autoencoder": ae,            # v2 추가: 오토인코더
        "ae_threshold": ae_threshold,  # 재구성 오차 경계(정상 기준)
        "rf": None,
        "classes": None,
        "trained_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "trained_on": os.path.basename(args.features),
        "n_normal": int(normal_mask.sum()),
        "sklearn": __import__("sklearn").__version__,
    }

    if labels is not None and len(set(labels)) >= 2:   # 공격 라벨이 있으면 RF 다중분류도 학습
        rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0)
        rf.fit(X, labels)
        bundle["rf"] = rf
        bundle["classes"] = sorted(set(labels))
        bundle["importances"] = dict(sorted(zip(cols, rf.feature_importances_),
                                            key=lambda t: -t[1]))

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    joblib.dump(bundle, args.out)
    size = os.path.getsize(args.out)
    print(f"저장: {args.out} ({size/1024:.1f} KB)")
    print(f"  피처 {len(cols)}개: {', '.join(cols)}")
    print(f"  학습 정상 구간 {bundle['n_normal']}개 · contamination {args.contamination}")
    print(f"  이상탐지: IsolationForest, LOF, Autoencoder(+스케일러, 오차경계 {ae_threshold:.4f})")
    if bundle["rf"] is not None:
        print(f"  분류: RandomForest, 종류 {bundle['classes']}")
    print(f"  학습 시각(UTC) {bundle['trained_at']} · scikit-learn {bundle['sklearn']}")
    print(f"\n불러 쓰기: python ml/predict.py {args.out} <새 피처 CSV>")


if __name__ == "__main__":
    main()
