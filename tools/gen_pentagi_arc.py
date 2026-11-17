#!/usr/bin/env python3
"""계획서 포맷의 Wazuh archives 합성 + 세션표 생성 — 실제 랩 데이터 전 파이프라인 검증용.  (계획서 §4)

실제 PentAGI/정상 로그가 오기 전, `pentagi_features.py`·`pentagi_rf.py`가 계획서대로 도는지
end-to-end 로 확인하려고 쓴다. 출력은 계획서 §4-3 의 Wazuh 원천 필드(data.client_ip/method/
path/status/response_bytes/user_agent/timestamp)를 가진 JSON lines + 세션표 CSV.

세션(계획서 §4-2): 정상/PentAGI 각 n회(기본 12), 세션당 10분, 30초=20창.
  정상    : 사람스러운 불규칙 간격, 낮은 404, 브라우저 UA, 알려진 경로, 자기 id 만 조회
  PentAGI : 기계적 규칙 간격, 높은 404(숨은 경로 스캔), python-requests, IDOR id 스윕, 섀도우 API

주의: 합성은 "파이프라인이 도는지 + 경향"을 보는 용도다. 확정 수치는 실제 랩 로그로 (계획서 §2-2).

사용:
  python tools/gen_pentagi_arc.py --out data/pentagi_arc.json --sessions data/pentagi_sessions.csv
"""
import argparse
import json
import os
import random
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))

NORMAL_PATHS = ["/", "/index.php", "/products.php", "/product.php?id={pid}", "/cart.php",
                "/login.php", "/search.php?q={q}", "/mypage.php?id={own}", "/category.php?c={c}"]
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
]
# PentAGI가 찌르는 숨은/권한 경로 (계획서 §3-4 로직결함 3종 + 흔한 스캔)
HIDDEN_PATHS = ["/api/v1/internal/config.php", "/api/admin_stats.php", "/.env", "/admin.php",
                "/backup.sql", "/phpinfo.php", "/api/v1/users", "/config.bak", "/.git/config"]
TOOL_UA = "python-requests/2.32.3"


def emit(f, ts, ip, method, path, status, nbytes, ua, user_id):
    rec = {"timestamp": ts.isoformat(timespec="milliseconds"),
           "data": {"client_ip": ip, "method": method, "path": path, "status": status,
                    "response_bytes": nbytes, "duration_ms": round(random.uniform(1, 30), 1),
                    "user_agent": ua, "user_id": user_id}}
    f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def normal_session(f, ip, t0, dur_s, rng):
    t = t0
    end = t0 + timedelta(seconds=dur_s)
    own = rng.randint(10001, 10050)
    ua = rng.choice(BROWSER_UAS)
    while t < end:
        tmpl = rng.choice(NORMAL_PATHS)
        path = tmpl.format(pid=rng.randint(1, 200), q="shoes", own=own, c=rng.randint(1, 8))
        status = 200 if rng.random() > 0.03 else 404          # 낮은 404
        nbytes = rng.randint(800, 9000) if status == 200 else rng.randint(100, 400)
        emit(f, t, ip, "GET", path, status, nbytes, ua, f"user_{own}")
        t += timedelta(seconds=rng.uniform(2.0, 18.0))        # 사람스러운 불규칙 간격


def pentagi_session(f, ip, t0, dur_s, rng):
    t = t0
    end = t0 + timedelta(seconds=dur_s)
    victim = 10001
    while t < end:
        roll = rng.random()
        if roll < 0.45:                                       # IDOR id 스윕 (타인 id 연속 조회)
            path = f"/mypage.php?id={victim}"
            victim += 1
            status = 200 if rng.random() > 0.2 else 404
        elif roll < 0.8:                                      # 숨은 경로 무차별 탐색 (404 급증)
            path = rng.choice(HIDDEN_PATHS)
            status = rng.choices([404, 200, 403], weights=[0.7, 0.2, 0.1])[0]
        else:                                                 # 권한 API 직접 호출
            path = rng.choice(["/api/admin_stats.php", "/api/v1/internal/config.php"])
            status = rng.choices([200, 403, 404], weights=[0.4, 0.3, 0.3])[0]
        nbytes = rng.randint(50, 500) if status != 200 else rng.randint(300, 4000)
        emit(f, t, ip, "GET", path, status, nbytes, TOOL_UA, None)
        t += timedelta(seconds=rng.uniform(0.2, 1.3))         # 기계적 짧고 규칙적 간격


def main():
    ap = argparse.ArgumentParser(description="계획서 포맷 Wazuh archives 합성 + 세션표")
    ap.add_argument("--out", default="data/pentagi_arc.json")
    ap.add_argument("--sessions", default="data/pentagi_sessions.csv")
    ap.add_argument("--rounds", type=int, default=12, help="정상/공격 각 세션 수 (계획서 10~15)")
    ap.add_argument("--session-min", type=float, default=10, help="세션 길이(분)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    dur_s = int(args.session_min * 60)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)

    base = datetime(2026, 11, 3, 10, 0, 0, tzinfo=KST)
    sess = []   # (session_id, label, ip, start, end)
    slot = base
    with open(args.out, "w", encoding="utf-8") as f:
        for i in range(args.rounds):
            # 정상 세션
            sid = f"N{i+1:02d}"
            ip = f"192.168.80.{rng.randint(30, 90)}"
            normal_session(f, ip, slot, dur_s, rng)
            sess.append((sid, 0, ip, slot, slot + timedelta(seconds=dur_s)))
            slot += timedelta(seconds=dur_s + 120)
            # PentAGI 세션
            sid = f"P{i+1:02d}"
            ip = "192.168.80.135"
            pentagi_session(f, ip, slot, dur_s, rng)
            sess.append((sid, 1, ip, slot, slot + timedelta(seconds=dur_s)))
            slot += timedelta(seconds=dur_s + 120)

    import csv
    with open(args.sessions, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["session_id", "label", "ip", "start", "end"])
        for sid, label, ip, s, e in sess:
            w.writerow([sid, label, ip, s.isoformat(timespec="seconds"), e.isoformat(timespec="seconds")])

    print(f"세션 {len(sess)}개 (정상 {args.rounds} / PentAGI {args.rounds}) → {args.out}")
    print(f"세션표 → {args.sessions}")


if __name__ == "__main__":
    main()
