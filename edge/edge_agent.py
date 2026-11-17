#!/usr/bin/env python3
"""엣지 에이전트 — 호스트(웹 또는 DB 서버)에서 '피처 벡터만' 뽑아 중앙 collector로 보낸다.

단순 소비자(../consumer)와의 차이:
  소비자 : 중앙이 '원본 로그 전체'를 읽는다
  엣지   : 각 호스트가 로그를 '여기서' 피처로 요약하고, 원본은 내보내지 않는다 → 숫자 벡터만 전송

프로젝트 규모의 엣지 체험:
  - 웹 호스트 : nginx 로그 → 웹 피처 (ml/features.py 재사용)
  - DB 호스트 : MySQL general log → DB 피처 (db_features.py, 원본 쿼리는 호스트 밖으로 안 나감)

사용:
  # 웹 호스트에서
  python edge/edge_agent.py --kind web --log /var/log/nginx/juiceshop_access.log \
      --collector http://10.16.1.50:8000 --interval 60
  # DB 호스트에서
  python edge/edge_agent.py --kind db --log /var/lib/mysql/db.log \
      --collector http://10.16.1.50:8000 --interval 60
  # 보내지 않고 화면에만 (연결 전 확인)
  python edge/edge_agent.py --kind web --log data/attack_access.log --once --dry-run
"""
import argparse
import json
import os
import sys
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "ml"))
sys.path.insert(0, HERE)


def web_vectors(paths, win_sec):
    from features import Window, WEB_FEATURES, add_nginx
    windows = defaultdict(Window)
    for p in paths:
        if os.path.exists(p):
            add_nginx(p, windows, win_sec)
    return [{"id": ip, "window_start": _iso(ws), "features": dict(zip(WEB_FEATURES, w.web_row()))}
            for (ip, ws), w in windows.items()]


def db_vectors(paths, win_sec):
    from db_features import DB_FEATURES, parse
    out = []
    for p in paths:
        if os.path.exists(p):
            for (host, ws), w in parse(p, win_sec).items():
                out.append({"id": host, "window_start": _iso(ws),
                            "features": dict(zip(DB_FEATURES, w.row()))})
    return out


def _iso(ws):
    return datetime.fromtimestamp(ws, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def send(collector, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(collector.rstrip("/") + "/ingest", data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status


def main():
    ap = argparse.ArgumentParser(description="엣지 에이전트 — 피처 벡터만 중앙으로 전송")
    ap.add_argument("--kind", required=True, choices=["web", "db"])
    ap.add_argument("--log", action="append", default=[], required=True, help="원본 로그(.gz 가능)")
    ap.add_argument("--collector", help="중앙 collector 주소, 예: http://10.16.1.50:8000")
    ap.add_argument("--window", type=float, default=5)
    ap.add_argument("--interval", type=float, default=60)
    ap.add_argument("--host-id", default=os.uname().nodename if hasattr(os, "uname") else "host",
                    help="이 호스트 이름(전송 메타)")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="전송하지 않고 벡터만 출력")
    args = ap.parse_args()

    if not args.dry_run and not args.collector:
        ap.error("--collector 가 필요 (또는 --dry-run)")
    win_sec = int(args.window * 60)
    sent = set()
    build = web_vectors if args.kind == "web" else db_vectors
    print(f"엣지 에이전트({args.kind}) 시작 · 로그 {args.log} · "
          f"{'드라이런' if args.dry_run else args.collector} · 주기 {args.interval:g}s\n")

    while True:
        vecs = build(args.log, win_sec)
        now = datetime.now(timezone.utc).timestamp()
        batch = []
        for v in sorted(vecs, key=lambda x: x["window_start"]):
            key = (v["id"], v["window_start"])
            ws = datetime.strptime(v["window_start"], "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc).timestamp()
            if key in sent or ws + win_sec > now:   # 중복/미완성 구간 제외
                continue
            sent.add(key)
            batch.append({"role": args.kind, "host": args.host_id, **v})

        if args.dry_run:
            for b in batch:
                print(json.dumps(b, ensure_ascii=False))
        elif batch:
            try:
                send(args.collector, {"vectors": batch})
                print(f"  {datetime.now(timezone.utc).strftime('%H:%M:%S')}Z · 벡터 {len(batch)}개 전송", flush=True)
            except Exception as e:
                print(f"  전송 실패: {e} (다음 주기에 재시도)", flush=True)
                for b in batch:
                    sent.discard((b["id"], b["window_start"]))
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
