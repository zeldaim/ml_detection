#!/usr/bin/env python3
"""MySQL general query log 합성기 — DB 모델 학습용 정상+공격 쿼리 로그와 정답지를 만든다.

실제 MySQL 티어가 아직 없어 틀을 완성하기 위한 합성 데이터 (웹의 gen_normal/gen_attack과 같은 역할).
정상: 상품 조회(공개) + 자기 주문/장바구니 조회(소유). 공격: BOLA 열거, SQLi, 대량 수집.
출발지(client ip)별로 Connect 줄을 찍어 db_features.py가 ip 단위로 묶게 한다.

사용:
  python tools/gen_db_traffic.py --out data/general_lab.log --answer data/answer_db.csv
"""
import argparse
import csv
import os
import random
from datetime import datetime, timedelta, timezone

PRODUCTS = list(range(1, 60))        # 공개: 상품 id
USERS = list(range(1, 200))          # 소유: 회원/주문 id


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class LogWriter:
    def __init__(self):
        self.lines = []
        self.cid = 0

    def connect(self, ip, t):
        self.cid += 1
        self.lines.append((t, f"{self.cid:>6} Connect\tapp@{ip} on shop using TCP/IP"))
        return self.cid

    def query(self, cid, t, sql):
        self.lines.append((t, f"{self.cid if cid is None else cid:>6} Query\t{sql}"))

    def dump(self, path):
        self.lines.sort(key=lambda x: x[0])
        with open(path, "w", encoding="utf-8") as f:
            for t, rest in self.lines:
                f.write(f"{ts(t)}\t{rest}\n")


def normal_session(w, ip, t, rng):
    cid = w.connect(ip, t)
    uid = rng.choice(USERS)                 # 이 사람의 user_id (자기 것만 봄)
    for _ in range(rng.randint(4, 12)):
        t += timedelta(seconds=rng.uniform(2, 30))
        r = rng.random()
        if r < 0.55:                        # 상품 구경 (공개 테이블 → BOLA 신호 아님)
            w.query(cid, t, f"SELECT * FROM products WHERE id = {rng.choice(PRODUCTS)}")
        elif r < 0.80:                      # 자기 주문/장바구니 (소유, 자기 id)
            w.query(cid, t, f"SELECT * FROM orders WHERE user_id = {uid}")
        elif r < 0.90:
            w.query(cid, t, f"SELECT * FROM basket WHERE user_id = {uid}")
        else:                               # 가끔 주문 생성
            w.query(cid, t, f"INSERT INTO orders (user_id, total) VALUES ({uid}, {rng.randint(1,9)})")
    return t


def attack_bola(w, ip, t, rng, slow):
    """BOLA/열거: 남의 주문 id를 순차/무작위로 훑음 → distinct_where_ids 급증."""
    cid = w.connect(ip, t)
    ids = rng.sample(USERS, 40)
    gap = 20 if slow else 0.3
    for uid in ids:
        t += timedelta(seconds=gap if slow else rng.uniform(0.1, 0.5))
        w.query(cid, t, f"SELECT * FROM orders WHERE user_id = {uid}")
    return t


def attack_sqli(w, ip, t, rng):
    """SQLi 탐침: UNION, information_schema, OR 1=1, sleep 등 → sqli_token_hits."""
    cid = w.connect(ip, t)
    payloads = [
        "SELECT * FROM users WHERE name = 'x' UNION SELECT user, authentication_string FROM mysql.user -- ",
        "SELECT * FROM products WHERE id = 1 OR 1=1",
        "SELECT * FROM products WHERE id = 1 AND sleep(5)",
        "SELECT table_name FROM information_schema.tables",
        "SELECT * FROM users WHERE id = 1 UNION SELECT 1,2,3 -- ",
        "SELECT * FROM orders WHERE id = 0x4142 OR benchmark(1000000,md5(1))",
    ]
    for p in payloads:
        t += timedelta(seconds=rng.uniform(1, 4))
        w.query(cid, t, p)
    return t


def attack_scrape(w, ip, t, rng):
    """대량 수집: 전체 테이블을 빠르게 긁음 → q_count·template 다양성↑ (소유 id 접근은 적음)."""
    cid = w.connect(ip, t)
    tables = ["products", "categories", "reviews", "products", "orders"]
    for i in range(60):
        t += timedelta(seconds=rng.uniform(0.1, 0.4))
        tbl = rng.choice(tables)
        w.query(cid, t, f"SELECT * FROM {tbl} LIMIT 100 OFFSET {i*100}")
    return t


def main():
    ap = argparse.ArgumentParser(description="MySQL general log 합성 (정상+공격)")
    ap.add_argument("--out", default="data/general_lab.log")
    ap.add_argument("--answer", default="data/answer_db.csv")
    ap.add_argument("--normal-hosts", type=int, default=6)
    ap.add_argument("--minutes", type=int, default=40, help="정상 트래픽 길이(분)")
    ap.add_argument("--seed", type=int, default=11)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    w = LogWriter()
    base = datetime(2026, 10, 23, 6, 0, 0, tzinfo=timezone.utc)
    answer = []

    # 정상: 호스트별로 여러 세션
    for h in range(args.normal_hosts):
        ip = f"10.16.2.{10+h}"
        t = base + timedelta(seconds=rng.uniform(0, 120))
        while t < base + timedelta(minutes=args.minutes):
            t = normal_session(w, ip, t, rng)
            t += timedelta(seconds=rng.uniform(30, 240))

    # 공격: 종류 2개 이상, 종류마다 사건 2개 (E1/E2 가능). 정상 뒤 시간대에.
    at = base + timedelta(minutes=args.minutes + 5)
    events = [
        ("10.16.2.101", "bola", lambda ww, ip, t: attack_bola(ww, ip, t, rng, slow=False)),
        ("10.16.2.102", "bola", lambda ww, ip, t: attack_bola(ww, ip, t, rng, slow=True)),
        ("10.16.2.103", "sqli", lambda ww, ip, t: attack_sqli(ww, ip, t, rng)),
        ("10.16.2.104", "sqli", lambda ww, ip, t: attack_sqli(ww, ip, t, rng)),
        ("10.16.2.105", "scrape", lambda ww, ip, t: attack_scrape(ww, ip, t, rng)),
        ("10.16.2.106", "scrape", lambda ww, ip, t: attack_scrape(ww, ip, t, rng)),
    ]
    for ip, typ, fn in events:
        start = at
        end = fn(w, ip, start)
        answer.append([f"{typ}_{ip.split('.')[-1]}", ip, ts(start)[:19] + "Z", ts(end)[:19] + "Z", typ])
        at = end + timedelta(seconds=90)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    w.dump(args.out)
    with open(args.answer, "w", newline="", encoding="utf-8") as f:
        cw = csv.writer(f)
        cw.writerow(["attack_id", "src", "start", "end", "type"])
        cw.writerows(answer)
    print(f"로그: {args.out} ({len(w.lines)}줄)")
    print(f"정답지: {args.answer} (공격 {len(answer)}건: " + ", ".join(sorted({a[4] for a in answer})) + ")")
    for a in answer:
        print("  " + ",".join(a))


if __name__ == "__main__":
    main()
