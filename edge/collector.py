#!/usr/bin/env python3
"""중앙 collector — 엣지 에이전트들이 보낸 피처 벡터를 받아 판정하고 쌓는다.

웹 벡터: 저장 모델(.joblib)로 IF·LOF·RF 판정 → 이상이면 경보.
DB 벡터: 아직 학습 모델이 없으므로 간단 규칙(SQLi 토큰>0, WHERE id 다수)으로 1차 경보 + 전부 스풀에 적재.
        쌓인 DB 벡터를 나중에 CSV로 모아 train_export.py로 DB 모델을 학습하면 된다(README).

원본 로그는 받지 않는다 — 각 호스트가 엣지에서 요약한 숫자 벡터만 온다.

사용:
  python edge/collector.py --model models/model.joblib --port 8000 --spool edge/spool.jsonl
  (에이전트: python edge/edge_agent.py --kind web --log <로그> --collector http://<이 호스트>:8000)
"""
import argparse
import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {}  # 런타임 설정 담는 곳


def score_web(bundle, feat):
    import numpy as np
    cols = bundle["features"]
    X = np.array([[float(feat.get(c, 0)) for c in cols]])
    if_flag = bool(bundle["iforest"].predict(X)[0] == -1)
    lof_flag = bool(bundle["lof"].predict(bundle["scaler"].transform(X))[0] == -1)
    rf = bundle["rf"].predict(X)[0] if bundle["rf"] is not None else ""
    return if_flag, lof_flag, rf


def flag_db(feat):
    """DB 벡터 1차 규칙(모델 학습 전 임시): SQLi 토큰이 있거나 WHERE id 접근 범위가 넓으면 의심."""
    reasons = []
    if feat.get("sqli_token_hits", 0) > 0:
        reasons.append(f"SQLi토큰 {int(feat['sqli_token_hits'])}")
    if feat.get("distinct_where_ids", 0) >= STATE["db_id_threshold"]:
        reasons.append(f"WHERE id {int(feat['distinct_where_ids'])}종(BOLA/열거 의심)")
    return reasons


def handle(payload):
    alerts = []
    for v in payload.get("vectors", []):
        role, host, ident, ws = v.get("role"), v.get("host"), v.get("id"), v.get("window_start")
        feat = v.get("features", {})
        rec = {"ts_recv": _now(), "role": role, "host": host, "id": ident,
               "window_start": ws, "features": feat}
        if role == "web" and STATE["bundle"] is not None:
            iff, lof, rf = score_web(STATE["bundle"], feat)
            rec["verdict"] = {"iforest": iff, "lof": lof, "rf_class": rf}
            if iff or lof:
                models = "+".join([m for m, f in (("IF", iff), ("LOF", lof)) if f])
                alerts.append(f"🚨 [web] {ws} {ident:<16} 이상({models})" +
                              (f" · RF={rf}" if rf else ""))
        elif role == "db":
            reasons = flag_db(feat)
            rec["verdict"] = {"rule_reasons": reasons}
            if reasons:
                alerts.append(f"🚨 [db]  {ws} {ident:<16} " + ", ".join(reasons))
        with open(STATE["spool"], "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    for a in alerts:
        print(a, flush=True)
    return len(payload.get("vectors", [])), len(alerts)


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # 기본 접근 로그 끔

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"status": "ok", "spool": STATE["spool"]})
        else:
            self._send(404, {"error": "use POST /ingest"})

    def do_POST(self):
        if self.path != "/ingest":
            return self._send(404, {"error": "POST /ingest"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(n) or b"{}")
            got, al = handle(payload)
            self._send(200, {"received": got, "alerts": al})
        except Exception as e:
            self._send(400, {"error": str(e)})

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    ap = argparse.ArgumentParser(description="중앙 collector — 엣지 벡터 수신·판정")
    ap.add_argument("--model", help="웹 벡터 판정용 .joblib (없으면 적재만)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--spool", default="edge/spool.jsonl", help="받은 벡터·판정 적재 파일")
    ap.add_argument("--db-id-threshold", type=int, default=15, help="DB WHERE id 종류 수 경보 임계값")
    args = ap.parse_args()

    STATE["bundle"] = None
    if args.model:
        import joblib
        STATE["bundle"] = joblib.load(args.model)
    STATE["spool"] = args.spool
    STATE["db_id_threshold"] = args.db_id_threshold
    os.makedirs(os.path.dirname(os.path.abspath(args.spool)) or ".", exist_ok=True)

    mdl = f"웹 모델 {args.model}" if args.model else "웹 모델 없음(적재만)"
    print(f"collector 시작 · http://{args.host}:{args.port}/ingest · {mdl} · 스풀 {args.spool}", flush=True)
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
