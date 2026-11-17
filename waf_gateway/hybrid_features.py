#!/usr/bin/env python3
"""WAF 로그 + API Gateway 로그 → 사용자 키 표 + IP 키 표 (두 키 함께 쓰기).  (waf_gateway/README.md)

왜 두 표인가
  사용자 키(user_id × 구간) : 로그인 후 공격(BOLA·탈취 토큰). NAT 뒤 여러 사용자가 한 IP여도 갈라진다
  IP 키  (client_ip × 구간)  : 로그인 전·401 거부·공개 페이지 요청까지 전부. 무차별 대입·크리덴셜 스터핑·스캐너
  → 인증 전 요청엔 사용자 ID가 없으므로 사용자 키만으로는 로그인 공격을 못 본다. 그래서 둘 다 만든다

입력
  --waf  WAF(nginx+ModSecurity) 접근 로그. combined 뒤에 "XFF" request_id 두 칸을 덧붙인 형식 (README §3-1)
  --gw   API Gateway JSON lines. 요청 ID·사용자 ID·상태 필드 이름은 --gw-field 로 바꿀 수 있다 (Kong 등)
  두 로그는 request_id 로 짝짓는다. 짝이 없는 WAF 요청 = 사용자 없음(IP 표에만 들어감)

출력 (둘 다 ml/features.py 와 같은 형식 → ml/models.py·evaluate.py 그대로 사용)
  --out-user  열 이름은 기존 도구 호환을 위해 'ip' 그대로, 값은 사용자 ID
  --out-ip    WEB_FEATURES + uniq_users(그 IP에서 본 사용자 수 — 한 IP 여러 계정 = 스터핑·공유 IP 신호)

사용:
  python waf_gateway/hybrid_features.py --waf waf_access.log --gw gw_access.jsonl \\
      --trusted-proxy 10.16.1.2 --out-user data/hy_user.csv --out-ip data/hy_ip.csv
  Kong 예: --gw-field request_id=request.headers.x-request-id --gw-field user_id=consumer.username \\
           --gw-field status=response.status
"""
import argparse
import csv
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ml"))
import features  # noqa: E402
from features import Window, WEB_FEATURES, add_request, iter_json, open_text  # noqa: E402
from wazuh_ml_detect import dig  # noqa: E402  (features 가 detector 경로를 이미 넣음)

# combined + "XFF" request_id. 뒤 두 칸이 없는 순수 combined 도 읽는다(그땐 짝짓기 불가 → IP 표만)
WAF_RE = re.compile(features.NGINX_RE.pattern + r'\S+ "[^"]*" "[^"]*"'
                    r'(?: "(?P<xff>[^"]*)" (?P<rid>\S+))?')   # rid: nginx hex · Apache UNIQUE_ID(@·- 포함)
GW_FIELDS = {"request_id": "request_id", "user_id": "user_id", "status": "status"}
NO_USER = {"", "-", "anonymous", "None", "null"}


def client_ip(remote, xff, trusted):
    """nginx real_ip_recursive 와 같은 규칙: remote 가 신뢰 프록시면 XFF 를 오른쪽부터 보며
    신뢰 목록에 없는 첫 주소. 클라이언트가 XFF 왼쪽에 위조 값을 넣어도 오른쪽 진짜 값이 이긴다 (docs/29 §7-4)."""
    if remote not in trusted or not xff or xff == "-":
        return remote
    for hop in reversed([h.strip() for h in xff.split(",") if h.strip()]):
        if hop not in trusted:
            return hop
    return remote


def load_gateway(paths, fields):
    """request_id → user_id(인증 안 됐으면 None)."""
    users = {}
    for p in paths:
        for e in iter_json(p):
            rid = dig(e, *fields["request_id"].split("."))
            if not rid:
                continue
            user = dig(e, *fields["user_id"].split("."))
            status = int(dig(e, *fields["status"].split("."), default=0) or 0)
            ok = user is not None and str(user) not in NO_USER and status not in (401, 403)
            users[str(rid)] = str(user) if ok else None
    return users


def write_table(path, windows, extra=None):
    """ml/features.py 와 같은 열 순서. extra = 열 이름 → (Window → 값)."""
    extra = extra or {}
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        wr = csv.writer(f)
        wr.writerow(["ip", "window_start"] + WEB_FEATURES + list(extra))
        for (key, ws), w in sorted(windows.items(), key=lambda kv: (kv[0][1], kv[0][0])):
            start = datetime.fromtimestamp(ws, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            wr.writerow([key, start] + w.web_row() + [fn(w) for fn in extra.values()])
    return len({k for k, _ in windows}), len(windows)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="WAF + Gateway 로그 → 사용자 키 표 + IP 키 표")
    ap.add_argument("--waf", action="append", required=True, help="WAF 접근 로그 (.gz 가능, 여러 번 가능)")
    ap.add_argument("--gw", action="append", required=True, help="Gateway JSON lines (.gz 가능, 여러 번 가능)")
    ap.add_argument("--gw-field", action="append", default=[], metavar="이름=경로",
                    help="Gateway 필드 위치 (request_id·user_id·status). 중첩은 점으로: user_id=consumer.username")
    ap.add_argument("--trusted-proxy", action="append", default=[],
                    help="WAF 앞의 신뢰 프록시/LB IP. 이 IP 에서 온 요청만 XFF 로 원래 IP 복원 (대역·0.0.0.0 금지)")
    ap.add_argument("--window", type=float, default=5, help="구간 길이(분), 기본 5 — 텀블링(겹치지 않음)")
    ap.add_argument("--out-user", required=True, help="사용자 키 피처 CSV")
    ap.add_argument("--out-ip", required=True, help="IP 키 피처 CSV")
    ap.add_argument("--owned-path", action="append", default=[],
                    help="uniq_objects 로 셀 소유 자원 경로 템플릿 (ml/features.py 와 같음)")
    args = ap.parse_args()

    fields = dict(GW_FIELDS)
    for kv in args.gw_field:
        name, _, path = kv.partition("=")
        if name not in GW_FIELDS or not path:
            ap.error(f"--gw-field 는 {list(GW_FIELDS)} 중 하나=경로: {kv}")
        fields[name] = path
    if args.owned_path:
        bad = [p for p in args.owned_path if not p.startswith("/")]
        if bad:   # Git Bash 경로 변환 함정 — ml/features.py 와 같은 이유
            ap.error(f"--owned-path 는 /로 시작해야 함: {bad} — Git Bash 라면 MSYS_NO_PATHCONV=1")
        features.OWNED_PREFIXES[:] = args.owned_path

    gw_users = load_gateway(args.gw, fields)
    trusted = set(args.trusted_proxy)
    win_sec = int(args.window * 60)
    user_windows, ip_windows = defaultdict(Window), defaultdict(Window)
    n = skipped = no_rid = unmatched = authed = 0
    for p in args.waf:
        with open_text(p) as f:
            for line in f:
                m = WAF_RE.match(line)
                if not m:
                    skipped += 1
                    continue
                req = m.groupdict()
                req["ip"] = client_ip(req["ip"], req["xff"], trusted)
                rid = req["rid"]
                if not rid or rid == "-":
                    no_rid += 1
                    user = None
                elif rid not in gw_users:
                    unmatched += 1
                    user = None
                else:
                    user = gw_users[rid]
                try:
                    add_request(ip_windows, win_sec, req)
                except ValueError:
                    skipped += 1
                    continue
                n += 1
                if user:
                    authed += 1
                    ts = datetime.strptime(req["time"], "%d/%b/%Y:%H:%M:%S %z").timestamp()
                    ip_windows[(req["ip"], int(ts // win_sec * win_sec))].users.add(user)
                    add_request(user_windows, win_sec, {**req, "ip": user})

    print(f"WAF 요청 {n}줄 사용" + (f", 형식이 다른 줄 {skipped}개 건너뜀" if skipped else "")
          + f" · Gateway 요청 {len(gw_users)}건")
    print(f"  인증된 요청 {authed} → 사용자 표 · 나머지 {n - authed} → IP 표에만")
    if no_rid or unmatched:
        print(f"  짝짓기 실패: request_id 없음 {no_rid} · Gateway 에 없는 id {unmatched}"
              " — 로그 형식·로테이션 시점 확인 (README §3)")
    if n and (no_rid + unmatched) / n > 0.2:
        print("  ⚠ 20% 넘게 짝이 없음 — 사용자 표가 비어 보일 수 있음. 양쪽에 같은 request_id 가 찍히는지 먼저 확인")
    if ip_windows and len({k for k, _ in ip_windows}) == 1 and n > 50:
        print("  ⚠ 출발지 IP 가 1개 — 프록시 IP 만 찍히는 상태. --trusted-proxy 또는 FortiGate SNAT 확인 (docs/29 §7)")

    keys, rows = write_table(args.out_user, user_windows)
    print(f"사용자 {keys}명 × {args.window:g}분 → {rows}행 → {args.out_user}")
    keys, rows = write_table(args.out_ip, ip_windows, {"uniq_users": lambda w: len(w.users)})
    print(f"IP {keys}개 × {args.window:g}분 → {rows}행 → {args.out_ip}")


if __name__ == "__main__":
    main()
