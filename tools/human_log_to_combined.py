#!/usr/bin/env python3
"""실제 사람 수집 로그(human_collect, 첫 칸 = 참가자 ID) → features.py 가 읽는 nginx combined 형식.  (docs/36)

nginx 는 실제 IP 대신 기본 인증 아이디(p01 …)만 남긴다. features.py 는 첫 칸이 IP 모양이어야 하므로
참가자 pNN → 가상 IP 10.40.0.NN 으로 바꾼다 (재생 10.30.*, 생성기 10.16.1.1xx, 공격 10.16.1.2xx 와 겹치지 않음).
아이디가 '-' 인 줄(로그인 창이 뜨기 전 401)과 Juice Shop 까지 가지 않은 줄(마지막 칸 upstream '-' = 기본 인증 실패)은
사람의 쇼핑 행동이 아니므로 뺀다. 출력에서는 upstream 칸을 지운다(combined 형식).

사용:
  python tools/human_log_to_combined.py human_collect/logs/access.log --out data/human_s1.log
  → 평가: supervised.py ... --test-only-prefix 10.40.   (실제 사람은 평가에만)
"""
import argparse
import re
import sys
from collections import Counter

LINE = re.compile(r'^(?P<user>\S+) (?P<rest>\[[^\]]+\] ".*") (?P<upstream>\S+)$')
PID = re.compile(r"^p(\d{1,3})$")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="참가자 ID 로그 → combined (가상 IP 10.40.0.N)")
    ap.add_argument("src", nargs="+", help="human_collect/logs/access.log (여러 개 가능)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--ip-prefix", default="10.40.0")
    args = ap.parse_args()

    kept, skipped, per = 0, Counter(), Counter()
    with open(args.out, "w", encoding="utf-8", newline="\n") as out:
        for path in args.src:
            for line in open(path, encoding="utf-8", errors="replace"):
                m = LINE.match(line.rstrip("\n"))
                if not m:
                    skipped["형식 다름"] += 1
                    continue
                if m["upstream"] == "-":
                    skipped["Juice Shop 까지 안 감(기본 인증 실패 등)"] += 1
                    continue
                pm = PID.match(m["user"])
                if not pm:
                    skipped[f"아이디 '{m['user']}'"] += 1
                    continue
                n = int(pm[1])
                if not 1 <= n <= 250:
                    skipped["번호 범위 밖"] += 1
                    continue
                out.write(f"{args.ip_prefix}.{n} - - {m['rest']}\n")
                kept += 1
                per[m["user"]] += 1
    print(f"{kept}줄 → {args.out}")
    for u, c in sorted(per.items()):
        print(f"  {u} → {args.ip_prefix}.{int(u[1:])}  {c}줄")
    if skipped:
        print("뺀 줄:", dict(skipped))


if __name__ == "__main__":
    main()
