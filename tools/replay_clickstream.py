#!/usr/bin/env python3
"""OTTO 세션 → Juice Shop 재생 → nginx combined 형식 접근 로그.  (docs/34 §4, docs/35)

정상 출발지를 생성기 대신 '실제 사람의 행동 순서·간격'으로 만든다.

방식 = 가상 시간 재생
  - 요청은 **실제 Juice Shop 에 보낸다** → 상태 코드·응답 크기·장바구니/주문 ID 는 서버가 준 진짜 값.
  - 로그 시각은 **OTTO 이벤트의 실제 시각(밀리초)을 옮긴 가상 시각**으로 쓴다.
    4주치 사용자를 실시간으로 기다릴 수 없고, 간격이 이 실험의 핵심이라 압축하지 않는다.
  - 출발지 IP 도 로그에만 쓰는 가상 값(--ip-prefix). 서버 쪽 nginx 로그가 아니라 이 스크립트가 쓴 로그를 features.py 에 넣는다.
  - 한 사용자의 요청 묶음(페이지 로드 등)은 가상 시각 0.05~0.3초 간격으로 붙인다(브라우저가 연달아 보내는 모양).

OTTO → Juice Shop 매핑 (docs/34 §4)
  방문 시작(첫 이벤트, 또는 30분 넘게 쉰 뒤) : GET / (+정적 파일은 첫 방문만) + 설정 API 4개 + 상품 목록 (+로그인 상태면 whoami)
  clicks : GET /rest/products/{pid}/reviews  (방문 안에서 같은 상품 연속 클릭은 한 번으로)
  carts  : (비로그인이면 로그인/가입) → GET /rest/basket/{bid} → 새 상품 POST /api/BasketItems, 담긴 상품 PUT 수량+1 → GET /rest/basket/{bid}
  orders : (비로그인이면 로그인) → 장바구니 비었으면 그 상품 담기 → 주소·카드(처음 한 번 생성) → GET 주소·카드·배송 → POST checkout
  상품 id : pid = 상품목록[crc32(aid) % 상품 수] — 같은 aid 는 항상 같은 상품(재방문 패턴 유지)
  OTTO 에 없는 검색·리뷰·오류는 만들지 않는다(목록 로드의 search?q= 만).

사용자 계정(replayNNN@lab.test)을 새로 가입시키므로 **실행마다 새 Juice Shop 컨테이너**에서 돌린다(이미 있으면 가입이 4xx).

사용 (Juice Shop 이 127.0.0.1:3000):
  python tools/replay_clickstream.py --sessions datasets/public/otto/sample_sessions.jsonl.gz \
      --base http://127.0.0.1:3000 --users 40 --seed 0 --out data/otto_replay.log
"""
import argparse
import gzip
import json
import random
import sys
import zlib
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
from gen_normal_traffic import USER_AGENTS, Client  # noqa: E402

VISIT_GAP_MS = 30 * 60 * 1000
PASSWORD = "ReplayUser!2026"
CONFIG_PATHS = ("/rest/admin/application-version", "/rest/admin/application-configuration",
                "/rest/languages", "/api/Quantitys/")


class LogClient(Client):
    """요청은 실제로 보내고, 로그 줄은 가상 시각·가상 IP 로 쓴다."""

    def __init__(self, base, ip, ua, out, rng):
        super().__init__(base, None, ua)
        self.ip, self.out, self.rng = ip, out, rng
        self.vt = None  # 현재 가상 시각 (datetime, UTC)
        self.status_count = {}

    def at(self, ms):
        self.vt = datetime.fromtimestamp(ms / 1000, timezone.utc)

    def req(self, method, path, body=None):
        status, res = super().req(method, path, body)
        size = len(json.dumps(res)) if isinstance(res, (dict, list)) else len(res or b"")
        t = self.vt.strftime("%d/%b/%Y:%H:%M:%S +0000")
        self.out.write(f'{self.ip} - - [{t}] "{method} {path} HTTP/1.1" {status} {size} '
                       f'"{self.referer}" "{self.ua}"\n')
        self.status_count[status] = self.status_count.get(status, 0) + 1
        self.vt += timedelta(seconds=self.rng.uniform(0.05, 0.3))  # 다음 요청은 조금 뒤
        return status, res


class ReplayUser:
    def __init__(self, idx, session, products, args, out, rng):
        self.idx, self.events, self.products, self.rng = idx, session["events"], products, rng
        self.email = f"replay{idx:03d}@lab.test"
        ip = f"{args.ip_prefix}.{idx // 250}.{idx % 250 + 1}"
        self.c = LogClient(args.base, ip, rng.choice(USER_AGENTS), out, rng)
        self.shift_ms = args.anchor_ms + int(rng.uniform(0, args.spread_hours * 3600_000)) - self.events[0]["ts"]
        self.assets_cached = self.registered = False
        self.bid = self.address_id = self.card_id = None

    def pid(self, aid):
        return self.products[zlib.crc32(str(aid).encode()) % len(self.products)]["id"]

    def page_load(self):
        status, html = self.c.req("GET", "/")
        if not self.assets_cached and isinstance(html, bytes):
            import re
            for a in re.findall(rb'(?:src|href)="([^":]+\.(?:js|css))"', html):
                self.c.req("GET", "/" + a.decode().lstrip("/"))
        for p in CONFIG_PATHS:
            self.c.req("GET", p)
        self.c.req("GET", "/rest/products/search?q=")
        if not self.assets_cached:
            for p in self.rng.sample(self.products, min(12, len(self.products))):
                self.c.req("GET", "/assets/public/images/products/" + quote(p["image"]))
            self.assets_cached = True
        if self.c.token:
            self.c.req("GET", "/rest/user/whoami")

    def login(self):
        if self.c.token:
            return True
        cred = {"email": self.email, "password": PASSWORD}
        if not self.registered:  # 신규 사용자는 실패한 로그인 없이 바로 가입 (가짜 401 을 만들지 않음)
            self.c.req("POST", "/api/Users", {**cred, "passwordRepeat": PASSWORD})
            self.registered = True
        status, res = self.c.req("POST", "/rest/user/login", cred)
        if status == 200 and isinstance(res, dict):
            auth = res.get("authentication", {})
            self.c.token, self.bid = auth.get("token"), auth.get("bid")
            self.c.req("GET", "/rest/user/whoami")
            return True
        return False

    def basket_items(self):
        status, res = self.c.req("GET", f"/rest/basket/{self.bid}")
        if status == 200 and isinstance(res, dict):
            return {p["id"]: p["BasketItem"] for p in res.get("data", {}).get("Products", [])}
        return {}

    def add_to_cart(self, pid):
        items = self.basket_items()
        if pid in items:
            self.c.req("PUT", f"/api/BasketItems/{items[pid]['id']}", {"quantity": items[pid]["quantity"] + 1})
        else:
            self.c.req("POST", "/api/BasketItems", {"ProductId": pid, "BasketId": str(self.bid), "quantity": 1})
        self.c.req("GET", f"/rest/basket/{self.bid}")

    def order(self, pid):
        if not self.basket_items():
            self.add_to_cart(pid)
        if self.address_id is None:  # 테스트용 가짜 주소·카드 (로컬 Juice Shop 전용)
            s, r = self.c.req("POST", "/api/Addresss", {
                "fullName": f"Replay User {self.idx}", "mobileNum": 1000000000 + self.idx, "zipCode": "12345",
                "streetAddress": "1 Test Street", "city": "Testville", "state": "TS", "country": "Testland"})
            self.address_id = (r or {}).get("data", {}).get("id") if isinstance(r, dict) else None
            s, r = self.c.req("POST", "/api/Cards", {
                "fullName": f"Replay User {self.idx}", "cardNum": 1234567812345678, "expMonth": 12, "expYear": 2090})
            self.card_id = (r or {}).get("data", {}).get("id") if isinstance(r, dict) else None
        self.c.req("GET", "/api/Addresss")
        self.c.req("GET", "/api/Cards")
        self.c.req("GET", "/api/Deliverys")
        self.c.req("POST", f"/rest/basket/{self.bid}/checkout", {
            "couponData": "bnVsbA==", "orderDetails": {
                "paymentId": str(self.card_id), "addressId": str(self.address_id), "deliveryMethodId": "1"}})
        self.c.req("GET", f"/rest/basket/{self.bid}")

    def run(self):
        prev_ts, last_click = None, None
        for e in self.events:
            self.c.at(e["ts"] + self.shift_ms)
            if prev_ts is None or e["ts"] - prev_ts > VISIT_GAP_MS:
                self.page_load()
                last_click = None
            prev_ts = e["ts"]
            pid = self.pid(e["aid"])
            if e["type"] == "clicks":
                if pid != last_click:
                    self.c.req("GET", f"/rest/products/{pid}/reviews")
                last_click = pid
            elif self.login():
                (self.add_to_cart if e["type"] == "carts" else self.order)(pid)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="OTTO 세션 → Juice Shop 가상 시간 재생 → 접근 로그")
    ap.add_argument("--sessions", required=True, help="sample_sessions.jsonl.gz")
    ap.add_argument("--base", default="http://127.0.0.1:3000")
    ap.add_argument("--users", type=int, default=40, help="재생할 사용자(=OTTO 세션 = 출발지) 수")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--max-events", type=int, default=400, help="이보다 이벤트가 많은 세션은 제외(재생 시간 상한)")
    ap.add_argument("--ip-prefix", default="10.30", help="가상 출발지 IP 앞 두 자리")
    ap.add_argument("--anchor", default="2026-10-23T06:15:00Z", help="사용자 첫 이벤트를 놓을 기준 시각(UTC)")
    ap.add_argument("--spread-hours", type=float, default=11, help="기준 시각부터 이 시간 안에 첫 이벤트를 흩뿌림")
    ap.add_argument("--out", required=True, help="출력 접근 로그 (nginx combined)")
    args = ap.parse_args()
    args.anchor_ms = int(datetime.fromisoformat(args.anchor.replace("Z", "+00:00")).timestamp() * 1000)

    sessions = [json.loads(l) for l in gzip.open(args.sessions, "rt", encoding="utf-8")]
    sessions = [s for s in sessions if len(s["events"]) <= args.max_events]
    rng = random.Random(args.seed)
    picked = rng.sample(sessions, args.users)

    probe = Client(args.base, None, USER_AGENTS[0])
    status, res = probe.req("GET", "/api/Products")
    if status != 200 or not isinstance(res, dict):
        sys.exit(f"상품 목록을 못 받음 (status {status}) — Juice Shop 이 {args.base} 에 떠 있나?")
    products = res["data"]

    lines = []
    total = {}
    for i, s in enumerate(picked):
        buf = __import__("io").StringIO()
        u = ReplayUser(i, s, products, args, buf, random.Random(args.seed * 100003 + i))
        u.run()
        lines += buf.getvalue().splitlines(keepends=True)
        for k, v in u.c.status_count.items():
            total[k] = total.get(k, 0) + v
        types = {t: sum(1 for e in s["events"] if e["type"] == t) for t in ("clicks", "carts", "orders")}
        print(f"  {u.c.ip:<14} OTTO 세션 {s['session']:<9} 이벤트 {len(s['events']):>3} {types} → 요청 {sum(u.c.status_count.values())}")

    # 로그는 시각순 (features.py 는 순서 무관하지만 사람이 읽기 쉽게)
    lines.sort(key=lambda l: datetime.strptime(l.split("[", 1)[1].split("]", 1)[0], "%d/%b/%Y:%H:%M:%S %z"))
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        f.writelines(lines)
    print(f"\n사용자 {len(picked)}명 · 요청 {len(lines)}줄 → {args.out}")
    print("상태 코드:", dict(sorted(total.items())))


if __name__ == "__main__":
    main()
