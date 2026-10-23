#!/usr/bin/env python3
"""지도(Random Forest) vs 비지도(Isolation Forest) — 같이 쓸 근거를 만드는 비교 실험.  (docs/12)

같은 피처 표·같은 정답지로, 공격 묶음(group)을 하나씩 빼 가며 평가한다(leave-one-group-out).
  --group-by attack : 묶음 = 공격 사건 하나 → "학습한 종류의 다른 사건"을 잡나 (아는 공격)
  --group-by type   : 묶음 = 공격 종류 하나 → "학습에 없던 종류"를 잡나 (처음 보는 공격)

각 회차(fold)
  학습 : 정상 구간 앞쪽 --normal-train 비율 + 뺀 묶음을 제외한 공격 구간
  평가 : 정상 구간 나머지 + 뺀 묶음의 공격 구간
  RF  : 학습 데이터(정상+공격 라벨)로 학습 → 확률 ≥ 0.5면 공격
  IF  : 학습 데이터 중 정상만으로 학습 (공격 라벨 미사용)
  OR  : 둘 중 하나라도 이상 → 함께 쓸 때

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
    ap.add_argument("--contamination", type=float, default=0.1, help="IF 이상 비율")
    ap.add_argument("--drop", nargs="*", default=[], help="뺄 피처")
    args = ap.parse_args()

    import numpy as np
    from sklearn.ensemble import IsolationForest, RandomForestClassifier

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
    print(f"{'뺀 묶음(평가 대상)':<34}{'공격구간':>6}  {'RF 탐지':>8}{'IF 탐지':>8}{'OR 탐지':>8}"
          f"  │ 정상 오탐 RF / IF / OR")
    total = defaultdict(int)
    importances = np.zeros(len(cols))
    for g, test_attack in groups.items():
        train_attack = [i for h, idx in groups.items() if h != g for i in idx]
        tr = normal_train + train_attack
        y = np.array([0] * len(normal_train) + [1] * len(train_attack))
        rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0)
        rf.fit(X[tr], y)
        importances += rf.feature_importances_
        iso = IsolationForest(n_estimators=300, contamination=args.contamination, random_state=0)
        iso.fit(X[normal_train])

        def flags(idx):
            p_rf = rf.predict_proba(X[idx])[:, 1] >= 0.5
            p_if = iso.predict(X[idx]) == -1
            return p_rf, p_if, p_rf | p_if

        a = [f.sum() for f in flags(test_attack)]
        n = [f.sum() for f in flags(normal_test)]
        for k, v in zip(("rf_tp", "if_tp", "or_tp"), a):
            total[k] += int(v)
        for k, v in zip(("rf_fp", "if_fp", "or_fp"), n):
            total[k] += int(v)
        total["attack"] += len(test_attack)
        total["normal"] += len(normal_test)
        print(f"{g[:33]:<34}{len(test_attack):>6}  {a[0]:>8}{a[1]:>8}{a[2]:>8}  │ "
              f"{n[0]} / {n[1]} / {n[2]}  (정상 {len(normal_test)})")

    print("\n── 합계 (회차 전체) ──")
    for name, tp, fp in (("RF", "rf_tp", "rf_fp"), ("IF", "if_tp", "if_fp"), ("RF+IF(OR)", "or_tp", "or_fp")):
        rec = total[tp] / total["attack"] if total["attack"] else 0
        fpr = total[fp] / total["normal"] if total["normal"] else 0
        print(f"{name:<10} 공격 구간 탐지율 {rec:.2f} ({total[tp]}/{total['attack']}) · "
              f"정상 구간 오탐률 {fpr:.2f} ({total[fp]}/{total['normal']})")

    print("\n── RF 피처 중요도 (회차 평균, 상위 5) ──")
    for c, v in sorted(zip(cols, importances / len(groups)), key=lambda t: -t[1])[:5]:
        print(f"  {c:<18}{v:.3f}")
    print("\n주의: 같은 정상 평가 구간이 회차마다 반복 집계된다. 공격 묶음이 적으면 한 건에 수치가 크게 흔들린다.")


if __name__ == "__main__":
    main()
