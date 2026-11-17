#!/usr/bin/env python3
"""출발지 귀속 해결 — 옵션 C(DB 티어 전체) / 옵션 A(웹-DB 시간 상관).  (docs/14 §4)

실제 MySQL은 '앱 서버 하나'만 봐서 쿼리를 공격자별로 못 나눈다. 두 가지로 우회한다.

  --mode tier  (옵션 C): DB 로그의 모든 쿼리를 '한 티어'로 묶어 구간별 1행 → "DB 티어 전체가 공격받나".
                         --answer를 주면 src를 티어 id로 바꾼 정답지(--answer-out)도 같이 만든다.
  --mode join  (옵션 A): 웹 피처(IP×구간)에 같은 구간의 DB 티어 집계를 db_* 열로 붙인다 → 웹 IP에
                         "그 시간대 DB가 뭘 했나"를 더해 판정(시간 상관으로 귀속).

출력 CSV는 ml/ 파이프라인이 그대로 받는 형식(ip,window_start,피처...).

사용:
  # 옵션 C
  python edge/correlate.py --mode tier --db data/general_real.log \
      --out data/features_tier.csv --answer data/answer_db.csv --answer-out data/answer_tier.csv
  python ml/supervised.py data/features_tier.csv --answer data/answer_tier.csv --group-by type --contamination 0.05

  # 옵션 A
  python edge/correlate.py --mode join --web data/attack_access.log --db data/general_real.log \
      --out data/features_webdb.csv
  python ml/supervised.py data/features_webdb.csv --answer data/answer.csv --group-by type --contamination 0.05
"""
import argparse
import csv
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "ml"))
sys.path.insert(0, HERE)
from features import Window as WebWindow, WEB_FEATURES, add_nginx  # noqa: E402
from db_features import DB_FEATURES, parse as db_parse            # noqa: E402


def _iso(ws):
    return datetime.fromtimestamp(ws, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_csv(path, header, rows):
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def mode_tier(args, win_sec):
    """옵션 C: DB 로그 전체를 티어 하나로 → 구간별 1행."""
    windows = db_parse(args.db, win_sec, force_host=args.tier_id)
    rows = []
    for (host, ws), w in sorted(windows.items(), key=lambda kv: kv[0][1]):
        rows.append([host, _iso(ws)] + w.row())
    write_csv(args.out, ["ip", "window_start"] + DB_FEATURES, rows)
    print(f"[tier] {args.out} · {len(rows)}행 (티어 '{args.tier_id}', DB 피처 {len(DB_FEATURES)}개)")

    if args.answer:  # 정답지 src를 티어 id로 바꿔 매칭되게
        src_rows = list(csv.DictReader(open(args.answer, encoding="utf-8")))
        out = [[r["attack_id"], args.tier_id, r["start"], r["end"], r.get("type", "")] for r in src_rows]
        ao = args.answer_out or args.answer.replace(".csv", "_tier.csv")
        write_csv(ao, ["attack_id", "src", "start", "end", "type"], out)
        print(f"[tier] 정답지 src→'{args.tier_id}': {ao} ({len(out)}건)")
        print("  주의: 티어 단위라 같은 구간에 공격·정상이 섞이면 그 구간은 공격으로 라벨된다.")


def mode_join(args, win_sec):
    """옵션 A: 웹 피처(IP×구간) + 같은 구간 DB 티어 집계(db_*)."""
    web = defaultdict(WebWindow)
    add_nginx(args.web, web, win_sec)
    web_rows = {(ip, ws): w.web_row() for (ip, ws), w in web.items()}

    db = db_parse(args.db, win_sec, force_host="_tier")
    db_by_ws = {ws: w.row() for (_, ws), w in db.items()}  # 구간 → DB 피처(티어 전체)
    zero_db = [0] * len(DB_FEATURES)

    header = ["ip", "window_start"] + WEB_FEATURES + ["db_" + c for c in DB_FEATURES]
    rows = []
    matched = 0
    for (ip, ws), wrow in sorted(web_rows.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        dbrow = db_by_ws.get(ws)
        if dbrow is not None:
            matched += 1
        rows.append([ip, _iso(ws)] + wrow + (dbrow if dbrow is not None else zero_db))
    write_csv(args.out, header, rows)
    print(f"[join] {args.out} · {len(rows)}행 (웹 {len(WEB_FEATURES)} + db_{len(DB_FEATURES)} 피처)")
    print(f"[join] DB 집계가 붙은 구간 {matched}/{len(rows)} (나머지는 db_* = 0; 웹·DB 로그 시간이 겹쳐야 함)")
    print("  정답지는 웹 것(공격자 IP 기준)을 그대로 쓴다: --answer data/answer.csv")
    print("  해석: 웹 IP 행에 '그 시간대 DB 티어가 뭘 했나'가 더해진다 → 시간 상관으로 귀속.")


def main():
    ap = argparse.ArgumentParser(description="출발지 귀속 — 티어 집계 / 웹-DB 시간 상관")
    ap.add_argument("--mode", required=True, choices=["tier", "join"])
    ap.add_argument("--db", required=True, help="MySQL general query log")
    ap.add_argument("--web", help="nginx access log (join 모드 필수)")
    ap.add_argument("--window", type=float, default=5)
    ap.add_argument("--tier-id", default="db-tier", help="티어 식별자(tier 모드)")
    ap.add_argument("--answer", help="정답지(tier 모드: src를 티어 id로 바꿔 복사)")
    ap.add_argument("--answer-out", help="바뀐 정답지 저장 경로")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    win_sec = int(args.window * 60)
    if args.mode == "tier":
        mode_tier(args, win_sec)
    else:
        if not args.web:
            ap.error("join 모드는 --web 이 필요")
        mode_join(args, win_sec)


if __name__ == "__main__":
    main()
