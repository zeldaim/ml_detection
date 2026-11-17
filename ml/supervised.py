#!/usr/bin/env python3
"""지도(Random Forest) vs 비지도(Isolation Forest · LOF) — 같이 쓸 근거를 만드는 비교 실험.  (docs/12)

같은 피처 표·같은 정답지로, 공격 묶음(group)을 하나씩 빼 가며 평가한다(leave-one-group-out).
  --group-by attack : 묶음 = 공격 사건 하나 → "학습한 종류의 다른 사건"을 잡나 (아는 공격)
  --group-by type   : 묶음 = 공격 종류 하나 → "학습에 없던 종류"를 잡나 (처음 보는 공격)

분할 (--split)
  ip (기본) : 출발지 단위. 정상 출발지 중 --normal-test 비율을 통째로 평가용으로 떼고,
              뺀 묶음에 나온 출발지는 그 회차 학습에서 완전히 뺀다(다른 공격·정상 구간 포함).
              → 같은 출발지의 창이 학습과 평가에 동시에 들어가지 않는다(모델이 출발지를 외워 맞히는 누수 방지).
              공격 출발지의 '공격 시간 밖' 구간은 정상 오탐 평가에 쓰지 않는다(그 출발지는 공격자라서).
  time      : 이전 방식. 정상 구간을 시각순 앞쪽 --normal-train 학습 / 나머지 평가.
              같은 출발지가 양쪽에 들어가므로 낙관적. 예전 결과 재현용.

각 회차(fold)
  학습 : 학습용 정상 구간 + 뺀 묶음을 제외한 공격 구간
  평가 : 평가용 정상 구간 + 뺀 묶음의 공격 구간
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
    ap.add_argument("--split", choices=["ip", "time"], default="ip",
                    help="ip=출발지 단위 분할(기본) / time=정상 구간 시각순 분할(이전 방식)")
    ap.add_argument("--normal-test", type=float, default=0.3,
                    help="[--split ip] 정상 출발지 중 평가로 뗄 비율 (최소 1개)")
    ap.add_argument("--seed", type=int, default=0, help="[--split ip] 평가용 정상 출발지 고르는 시드")
    ap.add_argument("--normal-train", type=float, default=0.7,
                    help="[--split time] 정상 구간 중 학습에 쓸 앞쪽 비율")
    ap.add_argument("--contamination", type=float, default=0.1, help="IF·LOF 이상 비율")
    ap.add_argument("--drop", nargs="*", default=[], help="뺄 피처")
    ap.add_argument("--train-only-prefix", default=None,
                    help="[--split ip] 이 접두어 IP 는 평가 후보에서 빼고 항상 정상 학습에만 (예: 10.30. = OTTO 재생 출발지)")
    ap.add_argument("--test-only-prefix", default=None,
                    help="[--split ip] 이 접두어 IP 는 학습에 안 쓰고 항상 정상 평가에만 (생성기로 학습 → 재생 정상 오탐 측정)")
    ap.add_argument("--exclude-prefix", default=None, help="이 접두어 IP 의 행을 통째로 뺀다 (기준선용)")
    args = ap.parse_args()

    import numpy as np
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.neural_network import MLPRegressor
    from sklearn.preprocessing import StandardScaler

    rows = list(csv.DictReader(open(args.features, encoding="utf-8")))
    if args.exclude_prefix:
        rows = [r for r in rows if not r["ip"].startswith(args.exclude_prefix)]
    cols = [c for c in rows[0] if c not in ("ip", "window_start") and c not in args.drop]
    X = np.array([[float(r[c] or 0) for c in cols] for r in rows])
    labels = label_windows(rows, load_answer(args.answer), timedelta(minutes=args.window))

    groups = defaultdict(list)
    for i, l in enumerate(labels):
        if l is not None:
            groups[l[0] if args.group_by == "attack" else l[1]].append(i)
    if len(groups) < 2:
        sys.exit(f"공격 묶음이 {len(groups)}개 — 하나를 빼고 학습하려면 2개 이상 필요")

    normal = sorted((i for i, l in enumerate(labels) if l is None), key=lambda i: rows[i]["window_start"])
    if args.split == "time":
        cut = int(len(normal) * args.normal_train)
        normal_train, normal_test = normal[:cut], normal[cut:]
        split_note = f"time (정상 구간 앞 {args.normal_train:.0%} 학습)"
    else:
        attacker_ips = {rows[i]["ip"] for idx in groups.values() for i in idx}
        all_benign = sorted({rows[i]["ip"] for i in normal} - attacker_ips)
        fixed_train = {ip for ip in all_benign if args.train_only_prefix and ip.startswith(args.train_only_prefix)}
        fixed_test = {ip for ip in all_benign if args.test_only_prefix and ip.startswith(args.test_only_prefix)}
        # 평가 후보 = 고정 지정이 없는 정상 출발지. 접두어 출발지를 더해도 후보 목록이 같으면 같은 시드 = 같은 평가셋(기준선과 공정 비교)
        benign_ips = [ip for ip in all_benign if ip not in fixed_train and ip not in fixed_test]
        if len(benign_ips) < 2:
            sys.exit(f"정상 출발지가 {len(benign_ips)}개 — 출발지 단위 분할에는 2개 이상 필요 (--split time 으로 이전 방식)")
        rng = np.random.RandomState(args.seed)
        n_test = min(len(benign_ips) - 1, max(1, round(len(benign_ips) * args.normal_test)))
        test_ips = set(rng.choice(benign_ips, n_test, replace=False))
        normal_train = [i for i in normal if rows[i]["ip"] not in attacker_ips and rows[i]["ip"] not in test_ips
                        and rows[i]["ip"] not in fixed_test]
        normal_test = [i for i in normal if rows[i]["ip"] in test_ips or rows[i]["ip"] in fixed_test]
        attacker_normal = [i for i in normal if rows[i]["ip"] in attacker_ips]  # 공격 출발지의 공격 시간 밖 구간
        split_note = (f"ip (정상 출발지 {len(benign_ips)}개 중 평가 {n_test}개: {', '.join(sorted(test_ips))})"
                      + (f" + 학습 전용 {len(fixed_train)}개({args.train_only_prefix}*)" if fixed_train else "")
                      + (f" + 평가 전용 {len(fixed_test)}개({args.test_only_prefix}*)" if fixed_test else ""))
    if len(normal_train) < 5 or not normal_test:
        sys.exit("정상 구간이 너무 적음")

    print(f"분할: {split_note}")
    print(f"피처 {len(cols)}개 · 정상 구간 학습 {len(normal_train)} / 평가 {len(normal_test)} · "
          f"공격 묶음 {len(groups)}개 ({args.group_by} 기준)\n")
    names = ["RF", "IF", "LOF", "IF|LOF", "IF&LOF", "RF|IF", "RF|IF|LOF", "RF|(IF&LOF)",
             "AE", "IF|LOF|AE"]   # AE(오토인코더) + 3비지도 OR 앙상블 추가 (docs/16: IF 외삽 한계 보완)
    print(f"{'뺀 묶음(평가 대상)':<26}{'공격구간':>6}  " + "".join(f"{n:>12}" for n in names))
    total = defaultdict(int)
    importances = np.zeros(len(cols))
    n_folds = 0
    for g, test_attack in groups.items():
        train_attack = [i for h, idx in groups.items() if h != g for i in idx]
        fold_normal = normal_train
        if args.split == "ip":
            # 뺀 묶음의 출발지는 이 회차 학습에서 통째로 제외 (같은 IP 가 다른 공격도 했으면 그것까지)
            test_src = {rows[i]["ip"] for i in test_attack}
            train_attack = [i for i in train_attack if rows[i]["ip"] not in test_src]
            # 공격 출발지의 '공격 시간 밖' 구간: 이번 평가 대상이 아니면 정상 학습에 써도 됨 (attack 라벨 없음)
            fold_normal = normal_train + [i for i in attacker_normal if rows[i]["ip"] not in test_src]
        if not train_attack:
            print(f"{g[:25]:<26}  건너뜀 — 이 묶음을 빼면 학습할 공격 구간이 없음 (같은 출발지가 다른 묶음 전부에도 있음)")
            continue
        # LOF 는 같은 점이 이웃 수보다 많으면 밀도가 무한대가 되어 판정이 깨진다(sklearn 문서) → LOF 학습은 고유 행만 (docs/35 §2)
        lof_train = np.unique(X[fold_normal], axis=0)
        k = max(2, min(20, len(lof_train) - 1))
        tr = fold_normal + train_attack
        y = np.array([0] * len(fold_normal) + [1] * len(train_attack))
        rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=0)
        rf.fit(X[tr], y)
        importances += rf.feature_importances_
        n_folds += 1
        iso = IsolationForest(n_estimators=300, contamination=args.contamination, random_state=0)
        iso.fit(X[fold_normal])
        scaler = StandardScaler().fit(X[fold_normal])  # LOF는 거리 기반 → 정상 기간 기준 스케일링
        lof = LocalOutlierFactor(n_neighbors=k, contamination=args.contamination, novelty=True)
        lof.fit(scaler.transform(lof_train))
        # Autoencoder: 정상을 압축→복원 학습, 재구성 오차 큰 점이 이상 (sklearn MLP로 구현)
        bottleneck = max(2, X.shape[1] // 2)
        ae = MLPRegressor(hidden_layer_sizes=(bottleneck,), activation="relu",
                          max_iter=1500, random_state=0)
        Xs_norm = scaler.transform(X[fold_normal])
        ae.fit(Xs_norm, Xs_norm)
        ae_thr = np.quantile(((ae.predict(Xs_norm) - Xs_norm) ** 2).mean(axis=1),
                             1 - args.contamination)

        def flags(idx):
            p_rf = rf.predict_proba(X[idx])[:, 1] >= 0.5
            p_if = iso.predict(X[idx]) == -1
            p_lof = lof.predict(scaler.transform(X[idx])) == -1
            Xs = scaler.transform(X[idx])
            p_ae = ((ae.predict(Xs) - Xs) ** 2).mean(axis=1) >= ae_thr
            return [p_rf, p_if, p_lof, p_if | p_lof, p_if & p_lof, p_rf | p_if,
                    p_rf | p_if | p_lof, p_rf | (p_if & p_lof),
                    p_ae, p_if | p_lof | p_ae]

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
    for c, v in sorted(zip(cols, importances / max(n_folds, 1)), key=lambda t: -t[1])[:5]:
        print(f"  {c:<18}{v:.3f}")
    print("\n주의: 같은 정상 평가 구간이 회차마다 반복 집계된다. 공격 묶음이 적으면 한 건에 수치가 크게 흔들린다.")


if __name__ == "__main__":
    main()
