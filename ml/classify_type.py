#!/usr/bin/env python3
"""RF 다중 분류 — 공격 종류(normal / brute_fast / bola …)를 이름까지 맞히나?  (docs/12 §6-2)

supervised.py가 "공격이냐 아니냐"(2지선다)를 봤다면, 여기서는 RF가 "어떤 공격이냐"(다지선다)를
맞히는지 본다. 비지도(IF·LOF)는 "이상하다"까지만 말하고 종류는 모른다 — 종류를 붙이는 건 RF의 역할.

방법: 사건 하나씩 빼고(leave-one-attack-event-out) 학습 → 뺀 사건 구간의 종류를 예측.
  학습에 같은 종류의 다른 사건이 있을 때, 새 사건의 종류를 이름까지 맞히는지를 본다.
  (정상 구간은 학습·평가 양쪽에 그대로 둔다 — "정상"도 한 종류로 분류)

지표: 종류 정확도 + 혼동행렬(무엇을 무엇으로 헷갈렸나) + RF 피처 중요도.

사용 (저장소 루트에서):
  python ml/classify_type.py data/features_combined.csv --answer data/answer.csv
  python ml/classify_type.py data/features_combined.csv --answer data/answer.csv --window 5
"""
import argparse
import csv
import os
import sys
from collections import Counter, defaultdict
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from evaluate import load_answer, parse_utc  # noqa: E402


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="RF 공격 종류 다중 분류")
    ap.add_argument("features")
    ap.add_argument("--answer", required=True, help="시간 구간형 정답지 attack_id,src,start,end,type")
    ap.add_argument("--window", type=float, default=5, help="구간 길이(분) — features.py와 같게")
    ap.add_argument("--drop", nargs="*", default=[], help="뺄 피처")
    args = ap.parse_args()

    import numpy as np
    from sklearn.ensemble import RandomForestClassifier

    rows = list(csv.DictReader(open(args.features, encoding="utf-8")))
    cols = [c for c in rows[0] if c not in ("ip", "window_start") and c not in args.drop]
    X = np.array([[float(r[c] or 0) for c in cols] for r in rows])
    attacks = load_answer(args.answer)
    win = timedelta(minutes=args.window)

    # 각 구간 → (사건 id, 종류). 공격이 아니면 ("", "normal")
    lab = []
    for r in rows:
        ws = parse_utc(r["window_start"])
        hit = ("", "normal")
        for i, (src, start, end, typ) in enumerate(attacks):
            if src == r["ip"] and start and ws < end and ws + win > start:
                hit = (f"{src}#{i}", typ or "attack")
                break
        lab.append(hit)

    events = defaultdict(list)
    for i, (eid, typ) in enumerate(lab):
        if typ != "normal":
            events[eid].append(i)
    if len(events) < 2:
        sys.exit(f"공격 사건이 {len(events)}개 — leave-one-event-out에는 2개 이상 필요")

    classes = sorted({t for _, t in lab})
    n_normal = sum(1 for _, t in lab if t == "normal")
    print(f"구간 {len(rows)} (정상 {n_normal}, 공격 사건 {len(events)}개) · 종류: {', '.join(classes)}\n")
    print(f"{'뺀 사건':<16}{'실제 종류':<12}{'구간수':>5}  예측 결과")

    conf = defaultdict(int)
    total = correct = 0
    importances = np.zeros(len(cols))
    for eid, test in events.items():
        typ = lab[test[0]][1]
        train = [i for i in range(len(rows)) if i not in test]
        rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0)
        rf.fit(X[train], [lab[i][1] for i in train])
        importances += rf.feature_importances_
        pred = rf.predict(X[test])
        for p in pred:
            conf[(typ, p)] += 1
            total += 1
            correct += (p == typ)
        print(f"{eid:<16}{typ:<12}{len(test):>5}  → " +
              ", ".join(f"{k}×{v}" for k, v in Counter(pred).items()))

    print(f"\n종류 정확도: {correct}/{total} = {correct / total:.2f}")
    print("\n혼동행렬 (행=실제, 열=예측):")
    print(f"{'실제\\예측':<12}" + "".join(f"{c:>12}" for c in classes))
    for a in classes:
        print(f"{a:<12}" + "".join(f"{conf.get((a, b), 0):>12}" for b in classes))

    print("\nRF 피처 중요도 (사건 평균, 상위 5):")
    for c, v in sorted(zip(cols, importances / len(events)), key=lambda t: -t[1])[:5]:
        print(f"  {c:<18}{v:.3f}")
    print("\n주의: 공격 사건이 적으면 한 사건에 정확도가 크게 흔들린다. 종류당 사건 2개 이상 권장.")


if __name__ == "__main__":
    main()
