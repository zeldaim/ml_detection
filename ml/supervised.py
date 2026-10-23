#!/usr/bin/env python3
"""지도(Random Forest) vs 비지도(Isolation Forest · LOF) — 같이 쓸 근거를 만드는 비교 실험.  (docs/12)

같은 피처 표·같은 정답지로, 공격 묶음(group)을 하나씩 빼 가며 평가한다(leave-one-group-out).
  --group-by attack : 묶음 = 공격 사건 하나 → "학습한 종류의 다른 사건"을 잡나 (아는 공격)
  --group-by type   : 묶음 = 공격 종류 하나 → "학습에 없던 종류"를 잡나 (처음 보는 공격)

각 회차(fold)
  학습 : 정상 구간 앞쪽 --normal-train 비율 + 뺀 묶음을 제외한 공격 구간
  평가 : 정상 구간 나머지 + 뺀 묶음의 공격 구간
  RF  : 학습 데이터(정상+공격 라벨)로 학습 → 확률 ≥ 0.5면 공격
  IF  : 학습 데이터 중 정상만으로 학습 (공격 라벨 미사용) — 전체에서 동떨어진 점
  LOF : IF와 같은 정상 데이터로 학습 (스케일링 후, novelty) — 이웃보다 밀도가 낮은 점(국소 이상치)
  조합: IF|LOF (하나라도), IF&LOF (둘 다), RF|IF, RF|IF|LOF, RF|(IF&LOF)
  IF가 놓치고 LOF가 잡은 공격 구간 수를 따로 센다 → "LOF가 IF를 보완한다"(H5)의 직접 근거

정답지는 evaluate.py와 같은 형식 (시간 구간형 attack_id,src,start,end,type / IP형 ip,label,type).

사용:
  python ml/supervised.py data/features_alerts.csv --answer samples/sample_answer_if.csv --group-by type
"""
import argparse
import csv
import os
import sys
from collections import defaultdict
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evaluate import load_answer, parse_utc  # noqa: E402


def label_windows(rows, attacks, win):
    """각 구간 → (공격 사건 id, 종류) 또는 None. IP형 정답지는 IP를 사건 id로 쓴다."""
    out = []
    for r in rows:
        ws = parse_utc(r["window_start"])
        hit = None
        for i, (src, start, end, typ) in enumerate(attacks):
            if src == r["ip"] and (start is None or (ws < end and ws + win > start)):
                hit = (f"{src}#{i}" if start is not None else src, typ or "attack")
                break
        out.append(hit)
    return out


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="RF vs IF leave-one-group-out 비교")
    ap.add_argument("features")
    ap.add_argument("--answer", required=True)
    ap.add_argument("--group-by", choices=["attack", "type"], default="type")
    ap.add_argument("--window", type=float, default=5, help="구간 길이(분) — features.py와 같게")
    ap.add_argument("--normal-train", type=float, default=0.7, help="정상 구간 중 학습에 쓸 앞쪽 비율")
    ap.add_argument("--contamination", type=float, default=0.1, help="IF·LOF 이상 비율")
    ap.add_argument("--drop", nargs="*", default=[], help="뺄 피처")
    args = ap.parse_args()

    import numpy as np
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import StandardScaler

    rows = list(csv.DictReader(open(args.features, encoding="utf-8")))
    cols = [c for c in rows[0] if c not in ("ip", "window_start") and c not in args.drop]
    X = np.array([[float(r[c] or 0) for c in cols] for r in rows])
    labels = label_windows(rows, load_answer(args.answer), timedelta(minutes=args.window))

    normal = sorted((i for i, l in enumerate(labels) if l is None), key=lambda i: rows[i]["window_start"])
    cut = int(len(normal) * args.normal_train)
    normal_train, normal_test = normal[:cut], normal[cut:]
    groups = defaultdict(list)
    for i, l in enumerate(labels):
        if l is not None:
            groups[l[0] if args.group_by == "attack" else l[1]].append(i)
    if len(groups) < 2:
        sys.exit(f"공격 묶음이 {len(groups)}개 — 하나를 빼고 학습하려면 2개 이상 필요")
    if len(normal_train) < 5 or not normal_test:
        sys.exit("정상 구간이 너무 적음")

    print(f"피처 {len(cols)}개 · 정상 구간 학습 {len(normal_train)} / 평가 {len(normal_test)} · "
          f"공격 묶음 {len(groups)}개 ({args.group_by} 기준)\n")
    names = ["RF", "IF", "LOF", "IF|LOF", "IF&LOF", "RF|IF", "RF|IF|LOF", "RF|(IF&LOF)"]
    print(f"{'뺀 묶음(평가 대상)':<26}{'공격구간':>6}  " + "".join(f"{n:>12}" for n in names))
    total = defaultdict(int)
    importances = np.zeros(len(cols))
    k = max(2, min(20, len(normal_train) - 1))
    for g, test_attack in groups.items():
        train_attack = [i for h, idx in groups.items() if h != g for i in idx]
        tr = normal_train + train_attack
        y = np.array([0] * len(normal_train) + [1] * len(train_attack))
        rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0)
        rf.fit(X[tr], y)
        importances += rf.feature_importances_
        iso = IsolationForest(n_estimators=300, contamination=args.contamination, random_state=0)
        iso.fit(X[normal_train])
        scaler = StandardScaler().fit(X[normal_train])  # LOF는 거리 기반 → 정상 기간 기준 스케일링
        lof = LocalOutlierFactor(n_neighbors=k, contamination=args.contamination, novelty=True)
        lof.fit(scaler.transform(X[normal_train]))

        def flags(idx):
            p_rf = rf.predict_proba(X[idx])[:, 1] >= 0.5
            p_if = iso.predict(X[idx]) == -1
            p_lof = lof.predict(scaler.transform(X[idx])) == -1
            return [p_rf, p_if, p_lof, p_if | p_lof, p_if & p_lof, p_rf | p_if,
                    p_rf | p_if | p_lof, p_rf | (p_if & p_lof)]

        fa, fn = flags(test_attack), flags(normal_test)
        a, n = [int(f.sum()) for f in fa], [int(f.sum()) for f in fn]
        for name, v, w in zip(names, a, n):
            total[name + "_tp"] += v
            total[name + "_fp"] += w
        total["lof_only"] += int((fa[2] & ~fa[1]).sum())  # IF가 놓치고 LOF가 잡음
        total["if_only"] += int((fa[1] & ~fa[2]).sum())
        total["attack"] += len(test_attack)
        total["normal"] += len(normal_test)
        print(f"{g[:25]:<26}{len(test_attack):>6}  " + "".join(f"{v:>12}" for v in a))
        print(f"{'  └ 정상 오탐 (정상 ' + str(len(normal_test)) + ')':<32}  " + "".join(f"{w:>12}" for w in n))

    print("\n── 합계 (회차 전체) ──")
    for name in names:
        tp, fp = total[name + "_tp"], total[name + "_fp"]
        rec = tp / total["attack"] if total["attack"] else 0
        fpr = fp / total["normal"] if total["normal"] else 0
        print(f"{name:<12} 공격 구간 탐지율 {rec:.2f} ({tp}/{total['attack']}) · "
              f"정상 구간 오탐률 {fpr:.2f} ({fp}/{total['normal']})")
    print(f"\nIF가 놓치고 LOF가 잡은 공격 구간 {total['lof_only']}개 · "
          f"LOF가 놓치고 IF가 잡은 공격 구간 {total['if_only']}개  (H5)")

    print("\n── RF 피처 중요도 (회차 평균, 상위 5) ──")
    for c, v in sorted(zip(cols, importances / len(groups)), key=lambda t: -t[1])[:5]:
        print(f"  {c:<18}{v:.3f}")
    print("\n주의: 같은 정상 평가 구간이 회차마다 반복 집계된다. 공격 묶음이 적으면 한 건에 수치가 크게 흔들린다.")


if __name__ == "__main__":
    main()
