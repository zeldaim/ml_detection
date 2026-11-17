#!/usr/bin/env python3
"""세션 단위 분할 Random Forest — PentAGI 탐지 (계획서 §5-6).

계획서 §5-3 의 세션 단위 분할(Session-based Split)로 데이터 누수를 막고, §6 의 4대 지표를 낸다:
  ① 탐지율(Recall)  ② 정상 오탐률(FPR)  ③ 최초 탐지 소요 시간(Time-to-Detect)  ④ 특징 중요도

입력: pentagi_features.py 출력 CSV (ip,window_start,session_id,label, 8피처).
분할: 세션 id 를 정렬해 뒤쪽 --test-frac(기본 0.25)을 라벨별로 테스트로 뺀다. --test-sessions 로 지정도 가능.

사용:
  python ml/pentagi_rf.py data/features_pentagi.csv --out models/pentagi_rf.joblib
  python ml/pentagi_rf.py data/features_pentagi.csv --test-sessions S09 S10 S21 S22
"""
import argparse
import sys

FEATURES = ["req_count", "interval_mean", "interval_std", "error_404_ratio",
            "unique_url_count", "unique_ua_count", "bytes_mean", "new_path_ratio"]


def pick_test_sessions(df, test_frac):
    """라벨별로 세션 id 를 정렬해 뒤쪽 test_frac 을 테스트로 (계획서: 9~10회차 = 마지막 세션들)."""
    test = []
    for label in (0, 1):
        sids = sorted(df[df["label"] == label]["session_id"].unique())
        k = max(1, round(len(sids) * test_frac))
        test += sids[-k:]
    return test


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="세션분할 RF — 계획서 §5-6")
    ap.add_argument("features")
    ap.add_argument("--test-frac", type=float, default=0.25, help="라벨별 뒤쪽 세션 비율을 테스트로")
    ap.add_argument("--test-sessions", nargs="*", default=None, help="테스트 세션 id 직접 지정")
    ap.add_argument("--out", default="models/pentagi_rf.joblib")
    ap.add_argument("--importance-png", default="data/pentagi_feature_importance.png")
    args = ap.parse_args()

    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report, confusion_matrix

    df = pd.read_csv(args.features)
    if df["label"].nunique() < 2:
        sys.exit("라벨이 한 종류뿐 — 정상/공격 세션이 모두 필요")

    test_sessions = args.test_sessions or pick_test_sessions(df, args.test_frac)
    df_test = df[df["session_id"].isin(test_sessions)]
    df_train = df[~df["session_id"].isin(test_sessions)]
    if df_train.empty or df_test.empty:
        sys.exit(f"분할 실패 — test_sessions={test_sessions}")

    X_train, y_train = df_train[FEATURES], df_train["label"]
    X_test, y_test = df_test[FEATURES], df_test["label"]

    print(f"학습 세션 {df_train['session_id'].nunique()}개 ({len(df_train)}창) · "
          f"테스트 세션 {df_test['session_id'].nunique()}개 ({len(df_test)}창)")
    print(f"테스트 세션: {sorted(test_sessions)}\n")

    model = RandomForestClassifier(n_estimators=100, max_depth=10,
                                   class_weight="balanced", random_state=42)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    recall = tp / (tp + fn) if (tp + fn) else 0.0          # ① 탐지율
    fpr = fp / (fp + tn) if (fp + tn) else 0.0             # ② 정상 오탐률

    print("혼동행렬 [실제 0/1 × 예측 0/1]:")
    print(f"            예측0   예측1")
    print(f"  정상(0)  {tn:>6} {fp:>6}")
    print(f"  공격(1)  {fn:>6} {tp:>6}\n")
    print(classification_report(y_test, y_pred, target_names=["정상(0)", "PentAGI(1)"], zero_division=0))

    # ③ 최초 탐지 소요 시간 (Time-to-Detect): 공격 테스트 세션별 첫 예측1 창의 세션시작 대비 초
    dft = df_test.copy()
    dft["_ts"] = pd.to_datetime(dft["window_start"])
    dft["_pred"] = y_pred
    ttds = []
    for sid, g in dft[dft["label"] == 1].groupby("session_id"):
        g = g.sort_values("_ts")
        hits = g[g["_pred"] == 1]
        if not hits.empty:
            ttds.append((hits["_ts"].iloc[0] - g["_ts"].iloc[0]).total_seconds())
    print("── 4대 지표 (계획서 §6) ──")
    print(f"① 탐지율(Recall)          {recall:.3f}   (목표 ≥ 0.80)")
    print(f"② 정상 오탐률(FPR)        {fpr:.3f}   (목표 < 0.025, 최대 0.05)")
    if ttds:
        print(f"③ 최초 탐지 시간(TTD)     중앙 {np.median(ttds):.0f}s · 평균 {np.mean(ttds):.0f}s "
              f"({len(ttds)}/{dft[dft['label']==1]['session_id'].nunique()} 공격세션 탐지, 목표 30~60s)")
    else:
        print("③ 최초 탐지 시간(TTD)     공격 세션 미탐 — 측정 불가")

    # ④ 특징 중요도
    imp = sorted(zip(FEATURES, model.feature_importances_), key=lambda t: -t[1])
    print("④ 특징 중요도(Top):")
    for c, v in imp:
        print(f"     {c:<18}{v:.3f}")

    import os
    import joblib
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    joblib.dump({"model": model, "features": FEATURES}, args.out)
    print(f"\n모델 저장 → {args.out}")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        names = [c for c, _ in imp][::-1]
        vals = [v for _, v in imp][::-1]
        plt.figure(figsize=(9, 5))
        plt.barh(names, vals, color="#2563EB")
        plt.title("Feature Importance — PentAGI Detection (Session Split)")
        plt.xlabel("Importance")
        plt.tight_layout()
        os.makedirs(os.path.dirname(os.path.abspath(args.importance_png)) or ".", exist_ok=True)
        plt.savefig(args.importance_png)
        print(f"중요도 그래프 → {args.importance_png}")
    except Exception as e:
        print(f"(matplotlib 없음 — 그래프 생략: {e})")


if __name__ == "__main__":
    main()
