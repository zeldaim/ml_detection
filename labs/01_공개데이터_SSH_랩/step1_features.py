#!/usr/bin/env python3
"""1단계: sshd 로그 → 출발지 IP별 피처 표(CSV).

로그 한 줄은 평범하다. IP별로 "묶어야" 행동이 보인다.

사용:
  python step1_features.py data/OpenSSH_2k.log data/features_original.csv
  python step1_features.py data/mixed.log      data/features_mixed.csv
"""
import csv
import re
import statistics
import sys
from collections import defaultdict
from datetime import datetime

LINE = re.compile(r"^(\w{3})\s+(\d+)\s+(\d\d:\d\d:\d\d)\s+\S+\s+sshd\[\d+\]:\s+(.*)$")
IP = re.compile(r"(?:from|rhost=|\[)\s*(\d{1,3}(?:\.\d{1,3}){3})")
FAILED = re.compile(r"Failed (?:password|none) for (?:invalid user )?(\S+) from")
INVALID = re.compile(r"Invalid user (\S+) from")
ACCEPTED = re.compile(r"Accepted \S+ for (\S+) from")

FEATURES = [
    "events",          # 이 IP가 등장한 줄 수
    "fail",            # 로그인 실패 수
    "invalid_user",    # 없는 계정 시도 수
    "uniq_users",      # 시도한 서로 다른 계정 수
    "root_fail",       # root 계정 실패 수
    "accepted",        # 로그인 성공 수
    "active_min",      # 처음~마지막 등장 사이 시간(분)
    "max_fail_2min",   # 2분 안에 몰린 최대 실패 수 (룰 기반 탐지가 보는 값)
    "interval_cv",     # 실패 간격의 변동계수: 0에 가까울수록 기계처럼 일정
]


def parse_ts(mon, day, hms):
    # 로그에 연도가 없으므로 임의의 연도를 붙인다(상대 시간만 쓰면 충분)
    return datetime.strptime(f"2000 {mon} {day} {hms}", "%Y %b %d %H:%M:%S")


def build(path):
    acc = defaultdict(lambda: {"events": 0, "fail_ts": [], "invalid_user": 0,
                               "users": set(), "root_fail": 0, "accepted": 0, "ts": []})
    for raw in open(path, encoding="utf-8", errors="replace"):
        m = LINE.match(raw.strip())
        if not m:
            continue
        ts, msg = parse_ts(*m.groups()[:3]), m.group(4)
        ipm = IP.search(msg)
        if not ipm:
            continue  # IP가 없는 줄(pam check pass 등)은 이번 랩에선 건너뜀
        a = acc[ipm.group(1)]
        a["events"] += 1
        a["ts"].append(ts)
        if fm := FAILED.search(msg):
            a["fail_ts"].append(ts)
            a["users"].add(fm.group(1))
            if fm.group(1) == "root":
                a["root_fail"] += 1
        elif im := INVALID.search(msg):
            a["invalid_user"] += 1
            a["users"].add(im.group(1))
        elif am := ACCEPTED.search(msg):
            a["accepted"] += 1
            a["users"].add(am.group(1))

    rows = []
    for ip, a in acc.items():
        fails = sorted(a["fail_ts"])
        gaps = [(b - x).total_seconds() for x, b in zip(fails, fails[1:])]
        if len(gaps) >= 2 and statistics.mean(gaps) > 0:
            cv = statistics.pstdev(gaps) / statistics.mean(gaps)
        else:
            cv = 1.0  # 판단할 표본이 부족하면 '보통'으로 둔다
        j = 0
        max2 = 0
        for i, t in enumerate(fails):  # 2분 슬라이딩 윈도
            while (t - fails[j]).total_seconds() > 120:
                j += 1
            max2 = max(max2, i - j + 1)
        rows.append({
            "ip": ip,
            "events": a["events"],
            "fail": len(fails),
            "invalid_user": a["invalid_user"],
            "uniq_users": len(a["users"]),
            "root_fail": a["root_fail"],
            "accepted": a["accepted"],
            "active_min": round((max(a["ts"]) - min(a["ts"])).total_seconds() / 60, 1),
            "max_fail_2min": max2,
            "interval_cv": round(cv, 3),
            "usernames": " ".join(sorted(a["users"]))[:200],  # LLM 단계 참고용(모델 입력 아님)
        })
    return rows


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    rows = build(sys.argv[1])
    with open(sys.argv[2], "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ip"] + FEATURES + ["usernames"])
        w.writeheader()
        w.writerows(rows)
    print(f"IP {len(rows)}개 → {sys.argv[2]}")
    for r in sorted(rows, key=lambda r: -r["events"])[:5]:
        print(f"  {r['ip']:<16} events={r['events']:<4} fail={r['fail']:<4} "
              f"users={r['uniq_users']:<3} max2m={r['max_fail_2min']:<3} cv={r['interval_cv']}")


if __name__ == "__main__":
    main()
