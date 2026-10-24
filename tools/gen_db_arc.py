#!/usr/bin/env python3
"""DB 아크용 합성 general log — 하드네거티브·UEBA 케이스 포함. (docs/22)

db_features.py 가 읽는 MySQL general log 형식으로 직접 찍는다. 시나리오:
  정상앱(.12~.17)     : products 중심 다양 쿼리, 보통 속도
  scrape(.201, 공격)  : SELECT * FROM products 반복(한 템플릿·한 테이블), 고속  → q_count↑ uniq_templates↓
  report(.202, 정상)  : 하드네거티브 — 여러 테이블/집계 쿼리, scrape 와 같은 고속 → q_count↑ 지만 uniq_templates↑
  ueba_spike(.203)    : orders 조회 느림→급증(탈취형)  → rel_q_count 로 잡음
  fast_legit(.204,정상): 항상 고속·다양(UEBA 대조, 평소가 빠름)
  bola(.205,공격)     : SELECT * FROM orders WHERE id=N 열거  → distinct_where_ids↑
  sqli(.206,공격)     : UNION/sleep 토큰  → sqli_token_hits↑
"""
import argparse, csv, random
from datetime import datetime, timedelta, timezone

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/db_arc.log")
    ap.add_argument("--answer", default="data/db_arc_answer.csv")
    ap.add_argument("--minutes", type=int, default=40)
    ap.add_argument("--seed", type=int, default=5)
    a = ap.parse_args()
    r = random.Random(a.seed)
    base = datetime(2026, 10, 25, 0, 0, 0, tzinfo=timezone.utc)
    end = base + timedelta(minutes=a.minutes)
    events = []  # (ts, cid, cmd, arg)
    cid = {}
    def conn(ip):
        c = 10 + len(cid); cid[ip] = c
        events.append((base, c, "Connect", f"app@{ip} on shop using TCP/IP"))
        return c

    PROD = lambda: f"SELECT * FROM products WHERE id = {r.randint(1,50)}"
    REPORT = lambda: r.choice([
        "SELECT COUNT(*) FROM orders", "SELECT * FROM categories",
        f"SELECT * FROM reviews WHERE product_id = {r.randint(1,40)}",
        "SELECT SUM(total) FROM payments", "SELECT * FROM inventory",
        f"SELECT name FROM products WHERE id = {r.randint(1,50)}"])
    ORDER = lambda i: f"SELECT * FROM orders WHERE id = {i}"
    SQLI = lambda: r.choice([
        "SELECT * FROM products WHERE id = 1 UNION SELECT username,password FROM users",
        "SELECT * FROM products WHERE id = 1 OR 1=1 -- ",
        "SELECT * FROM products WHERE id = sleep(5)"])

    def stream(ip, gap, make, t0=None, t1=None):
        c = conn(ip); t = t0 or base; stop = t1 or end
        while t < stop:
            events.append((t, c, "Query", make()))
            t += timedelta(seconds=gap)

    # 정상 앱 6개 (보통 속도, 다양)
    for i in range(12, 18):
        stream(f"10.16.2.{i}", r.uniform(20, 45),
               lambda: r.choice([PROD(), REPORT(), PROD()]))
    # scrape 공격 (고속, 한 템플릿)
    stream("10.16.2.201", 3, PROD)
    # report 정상(하드네거티브, 고속·다양)
    stream("10.16.2.202", 3, REPORT)
    # ueba: 느림(앞 절반) → 급증(뒤 절반)
    mid = base + timedelta(minutes=a.minutes//2)
    stream("10.16.2.203", 40, lambda: ORDER(r.randint(1,5)), base, mid)       # 평소 느림(자기 주문)
    stream("10.16.2.203", 3,  lambda: ORDER(r.randint(1,500)), mid, end)      # 급증(남의 주문 열거)
    # fast_legit 정상(항상 빠름·다양)
    stream("10.16.2.204", 3, REPORT)
    # bola 공격
    stream("10.16.2.205", 4, lambda: ORDER(r.randint(1,300)))
    # sqli 공격
    stream("10.16.2.206", 6, SQLI)

    events.sort(key=lambda e: e[0])
    import os; os.makedirs("data", exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        for ts, c, cmd, arg in events:
            f.write(f"{ts.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]}Z\t{c:>6} {cmd}\t{arg}\n")
    # 정답지(IP형): 공격 전용. ueba .203 은 급증 구간만 공격 → 시간형으로.
    with open(a.answer, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["ip", "label", "type"])
        for ip, ty in [("10.16.2.201","scrape"),("10.16.2.205","bola"),("10.16.2.206","sqli")]:
            w.writerow([ip, "attack", ty])
    # ueba 시간형 정답(급증 구간)은 별도 파일
    with open(a.answer.replace(".csv","_ueba.csv"), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["attack_id","src","start","end","type"])
        w.writerow(["ueba#0","10.16.2.203", mid.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    end.strftime("%Y-%m-%dT%H:%M:%SZ"), "takeover"])
    print(f"로그 {len(events)}줄 → {a.out}")
    print(f"정답지(IP형) → {a.answer} · UEBA(시간형) → {a.answer.replace('.csv','_ueba.csv')}")

if __name__ == "__main__":
    main()
