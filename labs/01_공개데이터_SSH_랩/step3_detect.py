#!/usr/bin/env python3
"""3단계: 룰 기반 vs Isolation Forest — 같은 피처 표로 비교.

  룰  : "2분 안에 실패 5회 이상" (Wazuh 상관 룰과 같은 발상: 짧은 시간에 몰린 실패)
  ML  : Isolation Forest — 정답 없이, '혼자 떨어뜨리기 쉬운' IP를 이상으로

사용:
  python step3_detect.py data/features_mixed.csv --answer data/answer.csv
  python step3_detect.py data/features_mixed.csv --answer data/answer.csv --drop accepted
  python step3_detect.py data/features_mixed.csv --contamination 0.2
"""
import argparse
import csv
import json
import sys

FEATURES = ["events", "fail", "invalid_user", "uniq_users", "root_fail",
            "accepted", "active_min", "max_fail_2min", "interval_cv"]
RULE_THRESHOLD = 5  # 2분 안에 실패 N회 이상이면 룰 알럿


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("features")
    ap.add_argument("--answer", help="정답지 CSV (step2 출력)")
    ap.add_argument("--contamination", type=float, default=0.1,
                    help="전체 중 이상으로 볼 비율 (기본 0.1)")
    ap.add_argument("--drop", nargs="*", default=[], help="모델에서 뺄 피처")
    ap.add_argument("--out", default="data/results.json", help="4단계(LLM)용 결과 파일")
    args = ap.parse_args()

    from sklearn.ensemble import IsolationForest

    rows = list(csv.DictReader(open(args.features, encoding="utf-8")))
    use = [f for f in FEATURES if f not in args.drop]
    X = [[float(r[f]) for f in use] for r in rows]

    model = IsolationForest(n_estimators=300, contamination=args.contamination,
                            random_state=0)
    model.fit(X)
    scores = model.decision_function(X)  # 낮을수록 이상
    preds = model.predict(X)             # -1 = 이상

    answer = {}
    if args.answer:
        answer = {a["ip"]: a for a in csv.DictReader(open(args.answer, encoding="utf-8"))}

    results = []
    for r, s, p in zip(rows, scores, preds):
        results.append({
            "ip": r["ip"],
            "score": round(float(s), 4),
            "ml_alert": bool(p == -1),
            "rule_alert": int(r["max_fail_2min"]) >= RULE_THRESHOLD,
            "features": {f: float(r[f]) for f in FEATURES},
            "usernames": r.get("usernames", ""),
            "truth": answer.get(r["ip"], {}).get("label", ""),
            "truth_type": answer.get(r["ip"], {}).get("type", ""),
        })
    results.sort(key=lambda x: x["score"])

    print(f"사용 피처: {', '.join(use)}")
    print(f"IP {len(results)}개 · ML 이상 {sum(r['ml_alert'] for r in results)}개 · "
          f"룰 알럿 {sum(r['rule_alert'] for r in results)}개\n")
    print(f"{'순위':<4}{'IP':<17}{'점수':>8}  {'ML':<3}{'룰':<3} 정답(우리가 넣은 것)")
    for i, r in enumerate(results, 1):
        tag = f"{r['truth']}: {r['truth_type']}" if r["truth"] else ""
        print(f"{i:<4}{r['ip']:<17}{r['score']:>8.3f}  "
              f"{'🚨' if r['ml_alert'] else '·':<3}{'🔔' if r['rule_alert'] else '·':<3}{tag}")

    if answer:
        print("\n── 우리가 넣은 사건 채점 ──")
        for ip, a in answer.items():
            r = next((x for x in results if x["ip"] == ip), None)
            if r is None:
                print(f"  {ip:<16} (피처 표에 없음)")
                continue
            rank = results.index(r) + 1
            if a["label"] == "attack":
                ml = "탐지 ✅" if r["ml_alert"] else "놓침 ❌"
                rule = "탐지 ✅" if r["rule_alert"] else "침묵 ❌"
            else:
                ml = "오탐 ❌" if r["ml_alert"] else "정상 ✅"
                rule = "오탐 ❌" if r["rule_alert"] else "정상 ✅"
            print(f"  {ip:<16} {a['label']:<7} ML={ml}  룰={rule}  순위 {rank}/{len(results)}  ({a['type']})")

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=1)
    print(f"\n결과 저장: {args.out}")


if __name__ == "__main__":
    main()
