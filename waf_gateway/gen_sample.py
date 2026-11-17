#!/usr/bin/env python3
"""WAF + Gateway 합성 로그 — "IP 키로는 안 보이고 사용자 키로 보이는 것 / 그 반대"를 한 번에 재현.

토폴로지 (README §1):  클라이언트 ─▶ LB 10.16.1.2(XFF 붙임) ─▶ WAF(nginx+ModSecurity) ─▶ Gateway(토큰 검증) ─▶ 앱
  WAF 로그 첫 칸은 전부 LB IP → --trusted-proxy 10.16.1.2 로 XFF 에서 원래 IP 복원

등장인물 (앞 --normal-hours 시간은 정상만, 마지막 1시간에 공격)
  NAT 203.0.113.10 : alice·bob·carol·dave 로그인 사용자 + mallory(공격 시간에 느린 BOLA — 남의 장바구니 열람)
  개인 IP 4개      : erin·frank·grace·heidi 로그인 사용자 (각자 IP)
  익명 IP 여러 개  : 로그인 없이 상품만 구경
  198.51.100.66    : 공격 시간에 크리덴셜 스터핑(로그인 실패 연속, 사용자 ID 없음). XFF 왼쪽에 가짜 IP 위조

출력: <out>/waf_access.log · gw_access.jsonl · answer_user.csv · answer_ip.csv
사용:
  python waf_gateway/gen_sample.py --out data/waf_gw_demo
"""
import argparse
import csv
import json
import os
import random
import uuid
from datetime import datetime, timedelta, timezone

LB = "10.16.1.2"
NAT = "203.0.113.10"
STUFFER = "198.51.100.66"
KST = timezone(timedelta(hours=9))
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36"


def browse(r, basket):
    """정상 사용자 한 번의 요청: 상품 위주, 가끔 자기 장바구니·담기."""
    x = r.random()
    if x < 0.55:
        return "GET", f"/api/Products/{r.randint(1, 40)}", 200
    if x < 0.75:
        return "GET", "/rest/products/search?q=" + r.choice(["apple", "juice", "mug", "shirt"]), 200
    if x < 0.92 and basket:
        return "GET", f"/rest/basket/{basket}", 200
    if basket:
        return "POST", "/api/BasketItems/", 201
    return "GET", "/api/Products", 200


def main():
    ap = argparse.ArgumentParser(description="WAF + Gateway 합성 로그")
    ap.add_argument("--out", required=True)
    ap.add_argument("--normal-hours", type=int, default=3, help="공격 전 정상 시간 (학습 구간)")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    r = random.Random(args.seed)

    t0 = datetime(2026, 10, 27, 9, 0, tzinfo=KST)
    t_attack = t0 + timedelta(hours=args.normal_hours)
    t_end = t_attack + timedelta(hours=1)

    users = {"alice": NAT, "bob": NAT, "carol": NAT, "dave": NAT, "mallory": NAT,
             "erin": "198.51.100.21", "frank": "198.51.100.22",
             "grace": "198.51.100.23", "heidi": "198.51.100.24"}
    baskets = {u: i + 1 for i, u in enumerate(users)}
    events = []   # (시각, IP, XFF 위조 접두, user|None, 메서드, 경로, 상태)

    for u, ip in users.items():
        t = t0 + timedelta(seconds=r.uniform(0, 60))
        while t < t_end:
            m, p, s = browse(r, baskets[u])
            events.append((t, ip, "", u, m, p, s))
            t += timedelta(seconds=r.uniform(15, 75))
    for i in range(6):   # 익명 구경꾼 — 사용자 ID 없음
        ip = f"192.0.2.{50 + i}"
        t = t0 + timedelta(minutes=r.uniform(0, 30))
        while t < t_end:
            m, p, s = browse(r, None)
            events.append((t, ip, "", None, m, p, s))
            t += timedelta(seconds=r.uniform(20, 90))

    # mallory: 공격 시간에 느린 BOLA — 남의 장바구니 id 를 30~60초마다 (요청 수는 정상 수준, 레이트리밋 통과)
    t = t_attack
    while t < t_end:
        events.append((t, NAT, "", "mallory", "GET", f"/rest/basket/{r.randint(20, 400)}", 200))
        t += timedelta(seconds=r.uniform(30, 60))
    # 스터핑: 로그인 실패 연속 (인증 전이라 Gateway 사용자 없음, 401). XFF 왼쪽 위조로 출발지 숨기기 시도
    t = t_attack + timedelta(minutes=10)
    while t < t_attack + timedelta(minutes=40):
        fake = f"8.8.{r.randint(0, 255)}.{r.randint(1, 254)}, "
        events.append((t, STUFFER, fake, None, "POST", "/rest/user/login", 401))
        t += timedelta(seconds=r.uniform(1, 4))

    events.sort(key=lambda e: e[0])
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "waf_access.log"), "w", encoding="utf-8") as waf, \
         open(os.path.join(args.out, "gw_access.jsonl"), "w", encoding="utf-8") as gw:
        for t, ip, fake, user, method, path, status in events:
            rid = uuid.UUID(int=r.getrandbits(128)).hex
            xff = fake + ip   # LB 가 진짜 IP 를 오른쪽에 덧붙임
            waf.write(f'{LB} - - [{t.strftime("%d/%b/%Y:%H:%M:%S %z")}] "{method} {path} HTTP/1.1" '
                      f'{status} {r.randint(200, 3000)} "-" "{UA}" "{xff}" {rid}\n')
            gw.write(json.dumps({"time": t.isoformat(), "request_id": rid, "client_ip": ip,
                                 "user_id": user, "method": method, "path": path, "status": status}) + "\n")

    iso = lambda d: d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
    answers = {"answer_user.csv": [("bola_slow#0", "mallory", t_attack, t_end, "bola_slow")],
               "answer_ip.csv": [("bola_slow#0", NAT, t_attack, t_end, "bola_slow"),
                                 ("cred_stuffing#0", STUFFER, t_attack + timedelta(minutes=10),
                                  t_attack + timedelta(minutes=40), "cred_stuffing")]}
    for name, rows in answers.items():
        with open(os.path.join(args.out, name), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["attack_id", "src", "start", "end", "type"])
            w.writerows([(a, s, iso(st), iso(en), ty) for a, s, st, en, ty in rows])
    print(f"요청 {len(events)}건 → {args.out}/  (학습 구간 끝 = {iso(t_attack)})")


if __name__ == "__main__":
    main()
