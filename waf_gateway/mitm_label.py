#!/usr/bin/env python3
"""mitmproxy 애드온 — 랩 트래픽을 요청·응답까지 보고 "진짜 공격이었나"를 요청 단위로 라벨링.  (README §7)

왜 mitmproxy 인가
  접근 로그는 "남의 장바구니 id 를 요청했다"까지만 안다. mitmproxy 는 **응답 본문**까지 보므로
  "실제로 남의 데이터를 받아갔다"를 확인할 수 있다 → 접근 로그 기반 모델을 채점할 정답지로 쓴다.
  랩 전용. 운영 경로에 끼우지 않는다 (TLS 복호화·지연·개인정보, README §7-3).

라벨 (요청 하나마다)
  bola      : 소유 자원 경로(OWNED_PREFIXES) 2xx 응답인데 응답의 주인(owner_field) ≠ 요청자(JWT user_claim)
  own       : 같은 경로, 주인 = 요청자 (정상)
  auth_fail : 로그인 경로에 401. 시도한 계정명(login_field)도 남김 → 스터핑/대입 구분은 mitm_answer.py
  normal    : 그 밖

사용 (리버스 프록시로 앱 앞에 — 클라이언트 IP 가 그대로 보인다):
  mitmdump -p 8081 --mode reverse:http://10.16.1.10:3000 -s waf_gateway/mitm_label.py \\
      --set label_out=data/mitm_labels.jsonl
  옵션: user_claim(기본 data.id) · owner_field(기본 data.UserId) · login_path(기본 /rest/user/login)
        login_field(기본 email)   — Juice Shop 기준. 다른 앱이면 바꾼다
"""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml"))
from features import is_owned, path_template  # noqa: E402
from wazuh_ml_detect import dig  # noqa: E402

DEFAULTS = {"label_out": "data/mitm_labels.jsonl", "user_claim": "data.id",
            "owner_field": "data.UserId", "login_path": "/rest/user/login", "login_field": "email"}


def jwt_claims(auth_header):
    """'Bearer <jwt>' → payload dict. 서명은 검증하지 않는다(라벨링용, 랩 트래픽)."""
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return None
    parts = auth_header.split()[1].split(".")
    if len(parts) != 3:
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except ValueError:
        return None


def parse_json(text):
    try:
        return json.loads(text) if text else None
    except ValueError:
        return None


def label_request(ts, ip, method, path, status, auth_header, req_body, resp_body, opt):
    """요청·응답 한 쌍 → 라벨 dict. mitmproxy 없이도 테스트할 수 있게 원시 값만 받는다."""
    claims = jwt_claims(auth_header)
    user = dig(claims, *opt["user_claim"].split(".")) if claims else None
    tmpl, _ = path_template(path)
    rec = {"ts": round(ts, 3), "ip": ip, "user": None if user is None else str(user),
           "method": method, "path": path, "status": status, "label": "normal"}
    if is_owned(tmpl) and 200 <= status < 300 and user is not None:
        owner = dig(parse_json(resp_body), *opt["owner_field"].split("."))
        if owner is not None:
            rec["owner"] = str(owner)
            rec["label"] = "own" if str(owner) == str(user) else "bola"
    elif path.split("?", 1)[0] == opt["login_path"] and status == 401:
        rec["label"] = "auth_fail"
        rec["tried"] = dig(parse_json(req_body), *opt["login_field"].split("."))
    return rec


class Labeler:
    def __init__(self):
        self.opt = dict(DEFAULTS)
        self.f = None

    def load(self, loader):
        for name, default in DEFAULTS.items():
            loader.add_option(name, str, default, f"mitm_label: {name}")

    def configure(self, updated):
        from mitmproxy import ctx
        self.opt = {k: getattr(ctx.options, k) for k in DEFAULTS}
        if "label_out" in updated or self.f is None:
            if self.f:
                self.f.close()
            os.makedirs(os.path.dirname(os.path.abspath(self.opt["label_out"])), exist_ok=True)
            self.f = open(self.opt["label_out"], "a", encoding="utf-8")

    def response(self, flow):
        req, resp = flow.request, flow.response
        ip = flow.client_conn.peername[0].removeprefix("::ffff:")   # 듀얼스택 소켓의 IPv4 매핑 주소
        rec = label_request(req.timestamp_start, ip, req.method, req.path,
                            resp.status_code, req.headers.get("authorization"),
                            req.get_text(strict=False), resp.get_text(strict=False), self.opt)
        self.f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self.f.flush()   # mitmdump 를 Ctrl+C 로 끊어도 남게

    def done(self):
        if self.f:
            self.f.close()


addons = [Labeler()]
