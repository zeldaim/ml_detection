"""IF 경로 검증용 합성 alerts: 정상 IP 14개 + 브루트포스 1 + slow 공격 1."""
import json, random, sys
from datetime import datetime, timedelta, timezone
random.seed(7)
KST = timezone(timedelta(hours=9))
t0 = datetime(2026, 10, 22, 13, 0, 0, tzinfo=KST)
out = []
def ev(ts, ip, rid, lvl, desc, groups, user=None, agent="rocky-web"):
    d = {"srcip": ip}
    if user: d["srcuser"] = user
    out.append({"timestamp": ts.isoformat(timespec="milliseconds"),
                "rule": {"id": rid, "level": lvl, "description": desc, "groups": groups},
                "agent": {"id": "001", "name": agent}, "data": d})
# 정상: 사람처럼 불규칙하게 가끔 로그인 성공, 가끔 오타 1회
for i in range(14):
    ip = f"192.168.1.{50+i}"
    t = t0
    for _ in range(random.randint(2, 4)):
        t += timedelta(seconds=random.uniform(30, 400))
        if random.random() < 0.25:
            ev(t, ip, "5716", 5, "sshd: authentication failed", ["authentication_failed"], f"user{i}")
        ev(t + timedelta(seconds=3), ip, "5715", 3, "sshd: authentication success", ["authentication_success"], f"user{i}")
# 빠른 브루트포스: 0.2초 간격, 다수 계정
t = t0
for k in range(60):
    t += timedelta(seconds=0.2)
    ev(t, "10.10.99.10", "5710", 5, "sshd: Failed password", ["authentication_failed"], random.choice(["root","admin","test","oracle","ubuntu"]))
# slow 공격: 40초 간격 기계적, 룰 임계치(짧은 시간 다수) 밑
t = t0
for k in range(20):
    t += timedelta(seconds=40)
    ev(t, "10.10.77.7", "5710", 5, "sshd: Failed password", ["authentication_failed"], random.choice(["root","admin","deploy"]), agent=random.choice(["rocky-web","rocky-db"]))
out.sort(key=lambda e: e["timestamp"])
with open(sys.argv[1], "w", encoding="utf-8") as f:
    for e in out: f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(len(out), "events")
