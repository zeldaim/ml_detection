#!/usr/bin/env python3
"""합성 nginx access.log 직접 생성기 — 인프라 없이 '상황을 연출'해 대량 데이터셋을 만든다.  (docs/20)

ML은 nginx 로그의 '필드'(출발지·경로·상태·시각)만 본다. 그래서 실제 트래픽을 쏘지 않고
로그 줄을 직접 찍으면, IP·공격종류·속도를 무제한으로 연출할 수 있다(인프라 0).
⚠ 합성이다 → 학습 '넓이' 보강용. 검증은 반드시 실제 로그(held-out)로 (docs/19 합성 함정).

여러 정상 사용자 + 여러 공격 변주를 한 파일에 섞어 찍고, 정답지(answer.csv)도 같이 만든다.
출력 로그는 features.py --nginx 가 그대로 읽는 combined 형식.

사용:
  python tools/gen_synth_log.py --out data/synth_access.log --answer data/synth_answer.csv \
      --minutes 240 --normal-users 8 --seed 7
  python tools/gen_synth_log.py --only bola_slow brute_fast --minutes 60   # 일부만
"""
import argparse
import random
from datetime import datetime, timedelta, timezone

# ── 경로 헬퍼 ────────────────────────────────────────────────────────────────
PRODUCTS = lambda r: f"/rest/products/search?q={r.choice(['apple','juice','banana','cola',''])}"
REVIEW = lambda r: f"/rest/products/{r.randint(1,40)}/reviews"
OWN_BASKET = lambda r: f"/rest/basket/{r.randint(1,3)}"           # 자기 장바구니(정상)
MISSING = lambda r: f"/{r.choice(['admin','backup','old','.git','config','phpmyadmin'])}/{r.randint(1,999)}"

UA_NORMAL = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (X11; Linux x86_64)",
             "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)"]
UA_BOT = "python-requests/2.x"


def line(ip, dt, method, path, status, ua, nbytes):
    ts = dt.strftime("%d/%b/%Y:%H:%M:%S %z")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {nbytes} "-" "{ua}"'


# ── 정상 사용자 ──────────────────────────────────────────────────────────────
def gen_normal(ip, start, minutes, r):
    """한 정상 사용자의 세션. 랜덤 간격(사람처럼), 대부분 200, 가끔 404."""
    out = []
    t = start + timedelta(seconds=r.uniform(0, 60))
    end = start + timedelta(minutes=minutes)
    shopper = r.random() < 0.6
    ua = r.choice(UA_NORMAL)
    while t < end:
        k = r.random()
        if k < 0.4:
            p, m, st, b = PRODUCTS(r), "GET", 200, r.randint(400, 2000)
        elif k < 0.6:
            p, m, st, b = "/api/Products", "GET", 200, r.randint(800, 3000)
        elif k < 0.75:
            p, m, st, b = REVIEW(r), "GET", 200, r.randint(200, 1200)
        elif k < 0.85:
            p, m, st, b = "/", "GET", 200, r.randint(1000, 4000)
        elif k < 0.92 and shopper:
            p, m, st, b = OWN_BASKET(r), "GET", 200, r.randint(200, 900)
        else:
            p, m, st, b = MISSING(r), "GET", 404, 150          # 정상도 가끔 오타/깨진 링크
        out.append((t, ip, m, p, st, ua, b))
        t += timedelta(seconds=r.uniform(2, 12))
    return out


# ── 공격 시나리오 (각각 다른 출발지, 시작/끝 기록) ──────────────────────────────
def atk_brute(ip, start, r, count, gap, emails_pool=1):
    out, t = [], start
    emails = [f"user{i}@lab.test" for i in range(emails_pool)] or ["admin@juice-sh.op"]
    for i in range(count):
        out.append((t, ip, "POST", "/rest/user/login", 401, UA_BOT, 120))
        t += timedelta(seconds=gap)
    return out, t


def atk_bola(ip, start, r, rng_n, gap):
    out, t = [], start
    ids = list(range(1, rng_n + 1)); r.shuffle(ids)
    for bid in ids:
        out.append((t, ip, "GET", f"/rest/basket/{bid}", 200, UA_BOT, r.randint(200, 900)))
        out.append((t, ip, "GET", f"/api/BasketItems/{bid}", 200, UA_BOT, r.randint(100, 500)))
        t += timedelta(seconds=gap)
    return out, t


def atk_user_enum(ip, start, r, rng_n, gap):
    out, t = [], start
    for uid in range(1, rng_n + 1):
        st = 200 if r.random() < 0.7 else 401
        out.append((t, ip, "GET", f"/api/Users/{uid}", st, UA_BOT, r.randint(150, 600)))
        t += timedelta(seconds=gap)
    return out, t


def atk_harvest(ip, start, r, count, gap):
    out, t = [], start
    for i in range(count):
        out.append((t, ip, "GET", "/api/Products", 200, UA_BOT, r.randint(2000, 6000)))
        out.append((t, ip, "GET", REVIEW(r), 200, UA_BOT, r.randint(200, 1200)))
        t += timedelta(seconds=gap)
    return out, t


def atk_data_exposure(ip, start, r, count, gap):
    out, t = [], start
    for i in range(count):
        out.append((t, ip, "GET", "/api/Products?limit=99999", 200, UA_BOT, r.randint(50000, 200000)))
        t += timedelta(seconds=gap)
    return out, t


def atk_bfla(ip, start, r, count, gap):
    """관리자 전용 기능 접근(단발형). 대조군 — 행위가 거의 안 튄다."""
    out, t = [], start
    for i in range(count):
        out.append((t, ip, "GET", "/rest/admin/application-version", r.choice([401, 403]), UA_BOT, 120))
        t += timedelta(seconds=gap)
    return out, t


def atk_scanning(ip, start, r, count, gap):
    out, t = [], start
    for i in range(count):
        out.append((t, ip, "GET", MISSING(r), 404, UA_BOT, 150))
        t += timedelta(seconds=gap)
    return out, t


# (이름 → (함수, kwargs, type)). fast/slow 변주는 gap 으로.
SCENARIOS = {
    "brute_fast":    (lambda ip, s, r: atk_brute(ip, s, r, 150, 0.4),                 "brute_fast"),
    "brute_slow":    (lambda ip, s, r: atk_brute(ip, s, r, 40, 18),                   "brute_slow"),
    "cred_stuffing": (lambda ip, s, r: atk_brute(ip, s, r, 120, 0.6, emails_pool=60), "cred_stuffing"),
    "bola_fast":     (lambda ip, s, r: atk_bola(ip, s, r, 50, 0.3),                   "bola_fast"),
    "bola_slow":     (lambda ip, s, r: atk_bola(ip, s, r, 40, 16),                    "bola_slow"),
    "user_enum":     (lambda ip, s, r: atk_user_enum(ip, s, r, 60, 0.5),              "user_enum"),
    "harvest":       (lambda ip, s, r: atk_harvest(ip, s, r, 150, 0.4),              "harvest"),
    "data_exposure": (lambda ip, s, r: atk_data_exposure(ip, s, r, 40, 1.5),          "data_exposure"),
    "bfla":          (lambda ip, s, r: atk_bfla(ip, s, r, 5, 3),                      "bfla"),
    "scanning":      (lambda ip, s, r: atk_scanning(ip, s, r, 80, 0.5),               "scanning"),
}


def main():
    ap = argparse.ArgumentParser(description="합성 nginx 로그 + 정답지 생성")
    ap.add_argument("--out", default="data/synth_access.log")
    ap.add_argument("--answer", default="data/synth_answer.csv")
    ap.add_argument("--minutes", type=int, default=240, help="전체 기간(분)")
    ap.add_argument("--normal-users", type=int, default=8)
    ap.add_argument("--normal-base", default="10.16.1.", help="정상 IP 접두어 (101~)")
    ap.add_argument("--attack-base", default="10.16.2.", help="공격 IP 접두어 (각 사건 다른 IP)")
    ap.add_argument("--only", nargs="*", choices=list(SCENARIOS), help="일부 시나리오만")
    ap.add_argument("--repeat", type=int, default=1, help="각 시나리오를 몇 번(다른 IP/시각) 반복할지")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    r = random.Random(args.seed)
    base = datetime(2026, 10, 25, 0, 0, 0, tzinfo=timezone.utc)
    events = []

    # 정상
    for u in range(args.normal_users):
        ip = f"{args.normal_base}{101 + u}"
        events += gen_normal(ip, base, args.minutes, r)

    # 공격: 각 시나리오를 기간 안 랜덤 시각에, 사건마다 다른 IP
    names = args.only or list(SCENARIOS)
    answer = []
    atk_i = 0
    for name in names:
        fn, typ = SCENARIOS[name]
        for _ in range(args.repeat):
            atk_i += 1
            ip = f"{args.attack_base}{10 + atk_i}"
            # 끝나기 전에 시작하도록 여유를 두고 배치
            start = base + timedelta(minutes=r.uniform(5, max(6, args.minutes - 20)))
            evs, end = fn(ip, start, r)
            events += evs
            answer.append((f"{name}#{atk_i}", ip, start, end, typ))

    events.sort(key=lambda e: e[0])
    import os
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for (t, ip, m, p, st, ua, b) in events:
            f.write(line(ip, t, m, p, st, ua, b) + "\n")

    import csv
    with open(args.answer, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f); w.writerow(["attack_id", "src", "start", "end", "type"])
        for aid, ip, s, e, typ in answer:
            w.writerow([aid, ip, s.strftime("%Y-%m-%dT%H:%M:%SZ"), e.strftime("%Y-%m-%dT%H:%M:%SZ"), typ])

    print(f"로그 {len(events)}줄 → {args.out}")
    print(f"정답지 {len(answer)}건 → {args.answer}")
    from collections import Counter
    print("공격 종류:", dict(Counter(a[4] for a in answer)))


if __name__ == "__main__":
    main()
