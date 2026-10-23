#!/usr/bin/env python3
"""Juice Shop 정상 트래픽 생성기 — nginx 접근 로그의 "정상 기간"을 자동으로 쌓는다.  (docs/08 §8-5)

가상 사용자 여러 명이 사람처럼 불규칙한 간격으로 둘러보기·검색·상품 보기·로그인·자기 장바구니를 쓴다.
공격 요청은 만들지 않는다. 표준 라이브러리만 사용 (Rocky 기본 python3에서 바로 실행).

⚠️ ML 피처는 출발지 IP 단위다. 출발지가 하나면 모든 사용자가 "한 사람"으로 합쳐진다.
   → 생성기를 돌리는 머신에 보조 IP를 붙이고 --sources로 사용자마다 다른 IP를 쓰게 한다.
     예) 타겟 VM에서:  nmcli con mod ens160 +ipv4.addresses "10.16.1.101/24,10.16.1.102/24" && nmcli con up ens160

사용:
  python3 tools/gen_normal_traffic.py --base http://10.16.1.10 --users 6 --minutes 180 \
      --sources 10.16.1.101,10.16.1.102,10.16.1.103 --log normal_sessions.csv
  python3 tools/gen_normal_traffic.py --base http://10.16.1.10 --minutes 2 --speed 10   # 빠른 동작 확인

끝나면 정상 기간 시작·끝 시각(UTC)을 출력한다 → ml/models.py --train-until 에 쓴다.
"""
import argparse
import csv
import http.client
import json
import random
import re
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
]
SEARCH_TERMS = ["apple", "juice", "banana", "lemon", "melon", "orange", "shirt", "sticker",
                "owasp", "mug", "cookie", "water", "carrot", "fruit", "coaster", "hoodie"]
REVIEWS = ["Tastes great!", "Arrived quickly, would buy again.", "A bit too sweet for me.",
           "Good value for the price.", "My kids love it.", "Nice design."]
PASSWORD = "NormalUser!2026"

print_lock = threading.Lock()


def utcnow():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class Client:
    """사용자 한 명의 HTTP 연결. 출발지 IP 고정, 쿠키처럼 토큰 유지."""

    def __init__(self, base, source, ua):
        u = urlsplit(base)
        self.host, self.port = u.hostname, u.port or 80
        self.source, self.ua = source, ua
        self.token = None
        self.referer = base.rstrip("/") + "/"
        self.requests = 0
        self.errors = Counter()  # (메서드, 경로 템플릿, 상태) → 횟수. 4xx·5xx·연결 실패만
        self.conn = None

    def _connect(self):
        src = (self.source, 0) if self.source else None
        self.conn = http.client.HTTPConnection(self.host, self.port, timeout=20, source_address=src)

    def req(self, method, path, body=None):
        headers = {"User-Agent": self.ua, "Accept": "application/json, text/plain, */*",
                   "Referer": self.referer}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
            headers["Cookie"] = "token=" + self.token
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        for attempt in (1, 2):  # keep-alive 연결이 끊겼으면 한 번 다시 연결
            try:
                if self.conn is None:
                    self._connect()
                self.conn.request(method, path, body=data, headers=headers)
                resp = self.conn.getresponse()
                raw = resp.read()
                self.requests += 1
                if resp.status >= 400:
                    self.errors[(method, re.sub(r"/\d+", "/{id}", path.split("?")[0]), resp.status)] += 1
                try:
                    return resp.status, json.loads(raw)
                except ValueError:
                    return resp.status, raw
            except (OSError, http.client.HTTPException):
                self.conn = None
                if attempt == 2:
                    self.errors[(method, "연결 실패", 0)] += 1
                    return 0, None


class User(threading.Thread):
    def __init__(self, idx, args, source, end_at, rng, writer):
        super().__init__(daemon=True)
        self.idx, self.args, self.end_at, self.rng, self.writer = idx, args, end_at, rng, writer
        self.email = f"normal{idx:02d}@lab.test"
        # 둘러보기만 하는 사람 / 로그인해서 장바구니 쓰는 사람
        self.persona = "shopper" if rng.random() < args.shopper_ratio else "browser"
        self.c = Client(args.base, source, rng.choice(USER_AGENTS))
        self.assets_cached = False
        self.products = []
        self.bid = None

    def think(self, lo=2.0, hi=45.0):
        # 사람의 클릭 간격: 대부분 짧고 가끔 길다 (로그정규)
        s = min(max(self.rng.lognormvariate(2.0, 0.8), lo), hi)
        self.sleep(s)

    def sleep(self, s):
        time.sleep(s / self.args.speed)

    def alive(self):
        return utcnow() < self.end_at

    # --- 행동들 ---
    def page_load(self):
        status, html = self.c.req("GET", "/")
        if not self.assets_cached and isinstance(html, bytes):
            for a in re.findall(rb'(?:src|href)="([^":]+\.(?:js|css))"', html):
                self.c.req("GET", "/" + a.decode().lstrip("/"))
        for p in ("/rest/admin/application-version", "/rest/admin/application-configuration",
                  "/rest/languages", "/api/Quantitys/"):
            self.c.req("GET", p)
        status, res = self.c.req("GET", "/rest/products/search?q=")
        if status == 200 and isinstance(res, dict):
            self.products = res.get("data", []) or self.products
        if not self.assets_cached:
            for p in self.rng.sample(self.products, min(12, len(self.products))):
                self.c.req("GET", "/assets/public/images/products/" + quote(p["image"]))
            self.assets_cached = True  # 브라우저 캐시: 다음 방문부터 정적 파일은 다시 안 받음

    def search(self):
        term = self.rng.choice(SEARCH_TERMS)
        self.c.req("GET", "/rest/products/search?q=" + quote(term))

    def view_product(self):
        if not self.products:
            return None
        p = self.rng.choice(self.products)
        self.c.req("GET", f"/rest/products/{p['id']}/reviews")
        return p

    def login(self):
        cred = {"email": self.email, "password": PASSWORD}
        status, res = self.c.req("POST", "/rest/user/login", cred)
        if status == 401:  # 처음이면 가입 후 로그인
            self.c.req("POST", "/api/Users", {**cred, "passwordRepeat": PASSWORD})
            self.think(3, 15)
            status, res = self.c.req("POST", "/rest/user/login", cred)
        if status == 200 and isinstance(res, dict):
            auth = res.get("authentication", {})
            self.c.token, self.bid = auth.get("token"), auth.get("bid")
            self.c.req("GET", "/rest/user/whoami")
            return True
        return False

    def basket(self):
        status, res = self.c.req("GET", f"/rest/basket/{self.bid}")
        if status == 200 and isinstance(res, dict):
            return [p["BasketItem"] for p in res.get("data", {}).get("Products", [])]
        return []

    def basket_action(self):
        items = self.basket()
        self.think(2, 20)
        in_basket = {i["ProductId"]: i for i in items}
        r = self.rng.random()
        if items and r < 0.25:
            item = self.rng.choice(items)
            self.c.req("PUT", f"/api/BasketItems/{item['id']}", {"quantity": item["quantity"] + 1})
        elif items and r < 0.40:
            self.c.req("DELETE", f"/api/BasketItems/{self.rng.choice(items)['id']}")
        else:
            p = self.view_product()
            if p and p["id"] not in in_basket:  # 이미 담긴 상품을 또 POST하면 500이 난다
                self.think(2, 15)
                self.c.req("POST", "/api/BasketItems",
                           {"ProductId": p["id"], "BasketId": str(self.bid), "quantity": 1})
        self.c.req("GET", f"/rest/basket/{self.bid}")

    def post_review(self):
        p = self.view_product()
        if p:
            self.think(10, 40)
            self.c.req("PUT", f"/rest/products/{p['id']}/reviews",
                       {"message": self.rng.choice(REVIEWS), "author": self.email})

    def session(self):
        self.page_load()
        logged_in = self.persona == "shopper" and self.rng.random() < 0.85 and self.login()
        for _ in range(self.rng.randint(3, 15)):
            if not self.alive():
                break
            self.think()
            r = self.rng.random()
            if logged_in and r < 0.30:
                self.basket_action()
            elif logged_in and r < 0.33:
                self.post_review()
            elif r < 0.65:
                self.view_product()
            else:
                self.search()
        self.c.token = None  # 세션 끝 = 탭 닫기

    def run(self):
        # 사용자마다 시작 시각을 흩뜨린다
        self.sleep(self.rng.uniform(0, 120))
        while self.alive():
            start, before = utcnow(), self.c.requests
            self.session()
            end = utcnow()
            with print_lock:
                self.writer.writerow([self.email, self.c.source or "", self.persona, iso(start), iso(end),
                                      self.c.requests - before])
                print(f"{iso(end)} {self.email:<18} {self.c.source or '-':<15} {self.persona:<7} "
                      f"세션 끝, 요청 {self.c.requests - before}개", flush=True)
            # 다음 방문까지 쉬는 시간 (1~15분)
            gap = self.rng.uniform(60, 900)
            while gap > 0 and self.alive():
                step = min(gap, 5 * self.args.speed)
                self.sleep(step)
                gap -= step


def main():
    ap = argparse.ArgumentParser(description="Juice Shop 정상 트래픽 생성기")
    ap.add_argument("--base", required=True, help="nginx 주소, 예: http://10.16.1.10")
    ap.add_argument("--users", type=int, default=6, help="가상 사용자 수 (기본 6)")
    ap.add_argument("--minutes", type=float, default=60, help="실행 시간(분, 실제 시간 기준)")
    ap.add_argument("--sources", default="", help="출발지 IP 목록(쉼표). 사용자에게 돌아가며 배정")
    ap.add_argument("--shopper-ratio", type=float, default=0.6, help="로그인·장바구니 사용자 비율")
    ap.add_argument("--speed", type=float, default=1.0, help="대기 시간 배속 (테스트용, 실험엔 1)")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--log", default="normal_sessions.csv", help="세션 기록 CSV")
    args = ap.parse_args()

    sources = [s.strip() for s in args.sources.split(",") if s.strip()]
    if len(sources) < args.users:
        print(f"⚠️ 출발지 IP {len(sources) or 1}개에 사용자 {args.users}명 → 같은 IP 사용자는 "
              f"피처에서 한 사람으로 합쳐진다", file=sys.stderr)
    if args.speed != 1.0:
        print(f"⚠️ --speed {args.speed}: 간격이 실제보다 빠르다. 실험용 정상 로그엔 쓰지 말 것", file=sys.stderr)

    rng = random.Random(args.seed)
    start = utcnow()
    end_at = datetime.fromtimestamp(start.timestamp() + args.minutes * 60, timezone.utc)
    with open(args.log, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if f.tell() == 0:
            w.writerow(["user", "src", "persona", "session_start_utc", "session_end_utc", "requests"])
        users = [User(i + 1, args, sources[i % len(sources)] if sources else None, end_at,
                      random.Random(rng.random()), w) for i in range(args.users)]
        print(f"정상 트래픽 시작 {iso(start)} → 예정 종료 {iso(end_at)}  (사용자 {args.users}, "
              f"shopper {sum(u.persona == 'shopper' for u in users)})", flush=True)
        for u in users:
            u.start()
        try:
            for u in users:
                while u.is_alive():
                    u.join(1)
        except KeyboardInterrupt:
            print("중단됨 (Ctrl+C)", file=sys.stderr)
    stop = utcnow()
    total = sum(u.c.requests for u in users)
    print(f"\n정상 기간 시작(UTC): {iso(start)}\n정상 기간 끝(UTC):   {iso(stop)}   ← ml/models.py --train-until"
          f"\n총 요청 {total}개, 세션 기록: {args.log}")
    errors = sum((u.c.errors for u in users), Counter())
    if errors:
        print("오류 응답 (첫 로그인 401은 가입 전이라 정상):")
        for (method, path, status), n in errors.most_common():
            print(f"  {status} {method} {path}  ×{n}")


if __name__ == "__main__":
    main()
