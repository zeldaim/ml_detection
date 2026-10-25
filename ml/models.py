#!/usr/bin/env python3
"""피처 표 → 룰 비교군 + 비지도 이상탐지 비교: 룰 · Z-score · Isolation Forest · LOF · One-Class SVM.
(docs/10 §3-1·3-2, docs/07 §6 ①②)

  학습(fit) : --train-until 이전 구간 = 정상 수집 기간(docs/08 §3). 없으면 전체로 fit하고 같은 데이터에 점수
  점수     : 모든 방법을 "클수록 이상"으로 통일해 detections CSV에 쓴다

  rule    : ML이 아닌 비교군 (docs/07 ①). 웹 피처가 있으면 레이트리밋 "1분에 N회 이상",
            alerts 피처가 있으면 Wazuh 룰 레벨 --rule-level(기본 10) 이상 (docs/03 §3-1). 둘 다 있으면 어느 하나
            N은 --rule-rpm, 없으면 정상 기간 1분 최대 요청 수 × 1.5 (학습 구간이 전체면 60)
  zscore  : 정상 기간의 중앙값·MAD로 robust Z, 피처 중 최대 |z| ≥ --z 이면 이상
  iforest : 무작위 분할로 빨리 고립되는 점 (스케일링 불필요)
  lof     : 이웃보다 밀도가 낮은 점 (스케일링 필요)
  ocsvm   : 정상 데이터를 감싸는 경계 밖의 점 (스케일링 필요)
  autoencoder : 정상을 압축→복원하도록 학습한 신경망. 복원이 안 되는(재구성 오차 큰) 점이 이상.
            IF가 못 보는 "본 적 없는 값"도 오차로 드러난다(docs/16 §0 — IF 외삽 한계 보완). sklearn MLP로 구현

사용:
  python ml/models.py data/features_alerts.csv --out data/detections.csv
  python ml/models.py data/features.csv --train-until 2026-11-03T00:00:00Z --out data/detections.csv
  python ml/models.py data/features.csv --methods iforest lof --contamination 0.15 --drop ssh_fail
"""
import argparse
import csv
import os
import sys
from datetime import datetime

METHODS = ["rule", "zscore", "iforest", "lof", "ocsvm", "autoencoder"]


def parse_utc(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def robust_z(X_train, X):
    """정상 기간 중앙값·MAD 기준 z. MAD가 0이면 표준편차, 그것도 0이면 1로 나눈다."""
    import numpy as np
    med = np.median(X_train, axis=0)
    mad = np.median(np.abs(X_train - med), axis=0) * 1.4826
    std = X_train.std(axis=0)
    denom = np.where(mad > 0, mad, np.where(std > 0, std, 1.0))
    return np.abs((X - med) / denom).max(axis=1)


def run_rule(rows, in_train, train_is_all, args):
    """룰 비교군. (점수: 임계값 대비 비율, 이상 여부, 설명) 반환."""
    import math
    import numpy as np
    scores, notes = np.zeros(len(rows)), []
    if "max_req_1min" in rows[0]:
        rpm = np.array([float(r["max_req_1min"] or 0) for r in rows])
        if args.rule_rpm:
            limit = args.rule_rpm
        elif train_is_all:
            limit = 60
        else:
            limit = max(1, math.ceil(rpm[in_train].max() * 1.5))
        scores = np.maximum(scores, rpm / limit)
        notes.append(f"레이트리밋 1분 {limit:g}회 이상")
    if "rule_level_max" in rows[0]:
        lvl = np.array([float(r["rule_level_max"] or 0) for r in rows])
        scores = np.maximum(scores, lvl / args.rule_level)
        notes.append(f"Wazuh 룰 레벨 {args.rule_level} 이상")
    if not notes:
        return None
    return scores, scores >= 1.0, " 또는 ".join(notes)


def run(method, X_train, X, args, train_is_all):
    """(점수: 클수록 이상, 이상 여부) 반환."""
    import numpy as np
    from sklearn.preprocessing import StandardScaler

    if method == "zscore":
        s = robust_z(X_train, X)
        return s, s >= args.z
    if method == "iforest":
        from sklearn.ensemble import IsolationForest
        m = IsolationForest(n_estimators=300, contamination=args.contamination, random_state=0)
        m.fit(X_train)
        return -m.decision_function(X), m.predict(X) == -1

    scaler = StandardScaler().fit(X_train)
    Xs_train, Xs = scaler.transform(X_train), scaler.transform(X)
    if method == "lof":
        from sklearn.neighbors import LocalOutlierFactor
        k = max(2, min(20, len(X_train) - 1))
        if train_is_all:  # 같은 데이터에 점수 → novelty=False (자기 자신을 이웃으로 세지 않음)
            m = LocalOutlierFactor(n_neighbors=k, contamination=args.contamination)
            pred = m.fit_predict(Xs)
            return -m.negative_outlier_factor_, pred == -1
        m = LocalOutlierFactor(n_neighbors=k, contamination=args.contamination, novelty=True)
        m.fit(Xs_train)
        return -m.decision_function(Xs), m.predict(Xs) == -1
    if method == "ocsvm":
        from sklearn.svm import OneClassSVM
        m = OneClassSVM(nu=args.nu, gamma="scale").fit(Xs_train)
        return -m.decision_function(Xs), m.predict(Xs) == -1
    if method == "autoencoder":
        from sklearn.neural_network import MLPRegressor
        # 정상 데이터를 입력=출력으로 복원 학습(압축 병목 hidden). 재구성 오차(MSE)가 이상 점수.
        bottleneck = max(2, Xs_train.shape[1] // 2)
        ae = MLPRegressor(hidden_layer_sizes=(bottleneck,), activation="relu",
                          max_iter=1500, random_state=0)
        ae.fit(Xs_train, Xs_train)
        err = ((ae.predict(Xs) - Xs) ** 2).mean(axis=1)
        err_train = ((ae.predict(Xs_train) - Xs_train) ** 2).mean(axis=1)
        thr = np.quantile(err_train, 1 - args.contamination)  # 정상 오차 상위 contamination%를 경계로
        return err, err >= thr
    raise ValueError(method)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="비지도 이상탐지 모델 비교")
    ap.add_argument("features", help="ml/features.py 출력 CSV")
    ap.add_argument("--methods", nargs="+", choices=METHODS, default=METHODS)
    ap.add_argument("--train-until", help="이 시각 이전 구간으로만 fit (정상 수집 기간 끝, ISO8601)")
    ap.add_argument("--contamination", type=float, default=0.1, help="iforest·lof·autoencoder 이상 비율 (기본 0.1)")
    ap.add_argument("--nu", type=float, default=0.1, help="ocsvm 경계 밖 허용 비율 (기본 0.1)")
    ap.add_argument("--z", type=float, default=3.0, help="zscore 임계값 (기본 3)")
    ap.add_argument("--rule-rpm", type=float, help="rule: 1분 요청 수 임계값 (기본: 정상 기간 최대 × 1.5)")
    ap.add_argument("--rule-level", type=int, default=10, help="rule: Wazuh 룰 레벨 임계값 (기본 10)")
    ap.add_argument("--drop", nargs="*", default=[], help="모델에서 뺄 피처")
    ap.add_argument("--out", default="data/detections.csv")
    args = ap.parse_args()

    import numpy as np

    import os
    if not os.path.isfile(args.features):
        sys.exit(f"입력 피처 파일 없음: {args.features}")
    rows = list(csv.DictReader(open(args.features, encoding="utf-8")))
    if not rows:
        sys.exit(f"피처 표가 비어 있음: {args.features}")
    if "window_start" not in rows[0]:
        sys.exit(f"피처 표에 'window_start' 열이 없음(형식 확인): {args.features}")
    cols = [c for c in rows[0] if c not in ("ip", "window_start") and c not in args.drop]
    X = np.array([[float(r[c] or 0) for c in cols] for r in rows])

    if args.train_until:
        cut = parse_utc(args.train_until)
        in_train = np.array([parse_utc(r["window_start"]) < cut for r in rows])
    else:
        in_train = np.ones(len(rows), dtype=bool)
    train_is_all = bool(in_train.all())
    if in_train.sum() < 5:
        sys.exit(f"학습 구간이 {in_train.sum()}행뿐 — --train-until을 확인")

    print(f"피처 {len(cols)}개: {', '.join(cols)}")
    print(f"전체 {len(rows)}행 · 학습 {int(in_train.sum())}행"
          + (" (전체로 fit, 같은 데이터에 점수)" if train_is_all else f" (~{args.train_until})") + "\n")

    out = []
    for method in args.methods:
        if method == "rule":
            res = run_rule(rows, in_train, train_is_all, args)
            if res is None:
                print("[rule   ] 룰에 쓸 피처(max_req_1min / rule_level_max)가 없어 건너뜀")
                continue
            scores, flags, note = res
            print(f"[rule   ] 기준: {note}")
        else:
            scores, flags = run(method, X[in_train], X, args, train_is_all)
        flagged = [(float(s), r["ip"], r["window_start"]) for s, f, r in zip(scores, flags, rows) if f]
        ips = sorted({ip for _, ip, _ in flagged})
        print(f"[{method:<7}] 이상 구간 {len(flagged)}개 · IP {len(ips)}개: {', '.join(ips) or '-'}")
        for s, f, r, t in zip(scores, flags, rows, in_train):
            out.append([method, r["ip"], r["window_start"], round(float(s), 4), int(f), int(t)])

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["method", "ip", "window_start", "score", "is_anomaly", "in_train"])
        w.writerows(out)
    print(f"\n결과 저장: {args.out}")


if __name__ == "__main__":
    main()
