#!/usr/bin/env python3
"""mitm_label.py 의 요청 단위 라벨 → 정답지 CSV 2개 (ml/evaluate.py 시간 구간형: attack_id,src,start,end,type).

  answer_user.csv : bola 를 **사용자** 기준으로        → hybrid_features.py --out-user 표 채점용
  answer_ip.csv   : bola + 로그인 실패를 **IP** 기준으로 → --out-ip 표 채점용

묶는 법: 같은 (출발지, 종류)의 공격 요청을 시간순으로 보고, 간격이 --gap 분을 넘으면 다른 회차로 끊는다.
  로그인 실패 회차는 --min-fails 건 이상만 공격으로 친다(오타 몇 번은 정상).
  그 회차에 시도된 계정이 --stuffing-accounts 개 이상이면 cred_stuffing, 아니면 brute_force
  (계정명은 요청 본문에만 있다 — mitmproxy 라서 알 수 있는 것)

사용:
  python waf_gateway/mitm_answer.py data/mitm_labels.jsonl --out data/mitm_answer
"""
import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def episodes(recs, gap_sec):
    """시간순 레코드 → 간격 gap_sec 초과마다 끊은 묶음 목록."""
    out = []
    for r in sorted(recs, key=lambda r: r["ts"]):
        if out and r["ts"] - out[-1][-1]["ts"] <= gap_sec:
            out[-1].append(r)
        else:
            out.append([r])
    return out


def build(recs, gap_sec, min_fails, stuffing_accounts):
    """레코드 → (사용자 정답 행, IP 정답 행). 행 = (src, start_ts, end_ts, type, 건수)."""
    groups = defaultdict(list)   # (표, src, 종류) → 레코드
    for r in recs:
        if r["label"] == "bola":
            groups[("user", r["user"], "bola")].append(r)
            groups[("ip", r["ip"], "bola")].append(r)
        elif r["label"] == "auth_fail":
            groups[("ip", r["ip"], "auth_fail")].append(r)
    rows = {"user": [], "ip": []}
    for (table, src, kind), rs in groups.items():
        for ep in episodes(rs, gap_sec):
            typ = kind
            if kind == "auth_fail":
                if len(ep) < min_fails:
                    continue
                tried = {r.get("tried") for r in ep if r.get("tried")}
                typ = "cred_stuffing" if len(tried) >= stuffing_accounts else "brute_force"
            rows[table].append((src, ep[0]["ts"], ep[-1]["ts"] + 1, typ, len(ep)))
    return rows


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="mitmproxy 라벨 → 정답지 CSV (사용자·IP)")
    ap.add_argument("labels", nargs="+", help="mitm_label.py 출력 JSONL")
    ap.add_argument("--out", required=True, help="출력 폴더 (answer_user.csv · answer_ip.csv)")
    ap.add_argument("--gap", type=float, default=10, help="같은 회차로 볼 최대 간격(분), 기본 10")
    ap.add_argument("--min-fails", type=int, default=5, help="로그인 실패 회차를 공격으로 칠 최소 건수, 기본 5")
    ap.add_argument("--stuffing-accounts", type=int, default=3,
                    help="회차 안 서로 다른 시도 계정이 이 수 이상이면 cred_stuffing, 기본 3")
    args = ap.parse_args()

    recs = []
    for p in args.labels:
        with open(p, encoding="utf-8") as f:
            recs += [json.loads(line) for line in f if line.strip()]
    rows = build(recs, args.gap * 60, args.min_fails, args.stuffing_accounts)

    os.makedirs(args.out, exist_ok=True)
    counts = defaultdict(int)
    for r in recs:
        counts[r["label"]] += 1
    print("요청 라벨: " + " · ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    for table in ("user", "ip"):
        path = os.path.join(args.out, f"answer_{table}.csv")
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["attack_id", "src", "start", "end", "type"])
            seq = defaultdict(int)
            for src, start, end, typ, n in sorted(rows[table], key=lambda x: x[1]):
                w.writerow([f"{typ}#{seq[typ]}", src, iso(start), iso(end), typ])
                print(f"  [{table}] {typ}#{seq[typ]} {src} {iso(start)} ~ {iso(end)} ({n}건)")
                seq[typ] += 1
        print(f"→ {path} ({len(rows[table])}회차)")
    if not counts.get("bola") and counts.get("own", 0) == 0:
        print("⚠ 소유 자원 판정이 0건 — owner_field·user_claim 이 앱 응답/토큰 구조와 맞는지 확인 (README §7-2)")


if __name__ == "__main__":
    main()
