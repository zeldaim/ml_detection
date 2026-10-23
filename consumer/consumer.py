#!/usr/bin/env python3
"""ML 소비자 (단순/엣지 없음) — 로그 파일을 주기적으로 읽어 저장 모델로 자동 판정한다.

지금까지 수동으로 하던 features.py → predict.py 를 반복 실행으로 감싼 것.
한 호스트(분석 PC)에서 돈다. 로그를 통째로 읽어 피처를 만들고, 저장된 모델(.joblib)로 점수를 매긴다.
"엣지 피처 추출"은 하지 않는다 — 원본 로그 전체를 이 프로세스가 읽는다. (엣지 버전은 ../edge/ 참고)

사용:
  python consumer/consumer.py --nginx data/attack_access.log --model models/model.joblib --once
  python consumer/consumer.py --nginx /var/log/nginx/juiceshop_access.log --model models/model.joblib --interval 60
"""
import argparse
import csv
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "ml"))
from features import Window, WEB_FEATURES, add_nginx  # noqa: E402


def build_vectors(paths, win_sec):
    """로그 파일들 → {(ip, window_start): 피처 dict}. features.py의 Window 로직 재사용."""
    windows = defaultdict(Window)
    for p in paths:
        if os.path.exists(p):
            add_nginx(p, windows, win_sec)
    out = {}
    for (ip, ws), w in windows.items():
        out[(ip, ws)] = dict(zip(WEB_FEATURES, w.web_row()))
    return out


def main():
    ap = argparse.ArgumentParser(description="ML 소비자 (단순) — 로그 → 저장모델 판정 반복")
    ap.add_argument("--nginx", action="append", default=[], required=True, help="감시할 nginx 로그(.gz 가능)")
    ap.add_argument("--model", required=True, help="train_export.py가 만든 .joblib")
    ap.add_argument("--window", type=float, default=5, help="구간 길이(분) — 학습 때와 같게")
    ap.add_argument("--interval", type=float, default=60, help="재확인 주기(초)")
    ap.add_argument("--once", action="store_true", help="한 번만 돌고 종료")
    ap.add_argument("--alert-out", help="이상 구간을 이어붙일 CSV(선택)")
    args = ap.parse_args()

    import joblib
    import numpy as np

    bundle = joblib.load(args.model)
    cols = bundle["features"]
    win_sec = int(args.window * 60)
    seen = set()  # 이미 경보한 (ip, window_start) — 중복 방지
    print(f"소비자 시작 · 모델 {args.model} (학습 {bundle['trained_at']}, contamination {bundle['contamination']})")
    print(f"감시: {args.nginx} · 주기 {args.interval:g}s · 구간 {args.window:g}분\n")

    while True:
        vectors = build_vectors(args.nginx, win_sec)
        now = datetime.now(timezone.utc).timestamp()
        new_alerts = []
        for (ip, ws), feat in sorted(vectors.items(), key=lambda kv: kv[0][1]):
            if (ip, ws) in seen:
                continue
            if ws + win_sec > now:
                continue  # 아직 안 끝난 구간은 건너뜀(다음 주기에 완성되면 처리)
            X = np.array([[float(feat.get(c, 0)) for c in cols]])
            if_flag = bundle["iforest"].predict(X)[0] == -1
            lof_flag = bundle["lof"].predict(bundle["scaler"].transform(X))[0] == -1
            seen.add((ip, ws))
            if if_flag or lof_flag:
                rf = bundle["rf"].predict(X)[0] if bundle["rf"] is not None else ""
                wstart = datetime.fromtimestamp(ws, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                models = "+".join([m for m, f in (("IF", if_flag), ("LOF", lof_flag)) if f])
                msg = f"🚨 {wstart} {ip:<16} 이상({models})" + (f" · RF분류={rf}" if rf else "")
                print(msg, flush=True)
                new_alerts.append({"window_start": wstart, "ip": ip, "models": models,
                                   "rf_class": rf, **feat})
        if new_alerts and args.alert_out:
            exists = os.path.exists(args.alert_out)
            with open(args.alert_out, "a", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=list(new_alerts[0]))
                if not exists:
                    w.writeheader()
                w.writerows(new_alerts)
        if not new_alerts:
            print(f"  {datetime.now(timezone.utc).strftime('%H:%M:%S')}Z · 새 이상 없음 "
                  f"(구간 {len(vectors)}개 확인)", flush=True)
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
