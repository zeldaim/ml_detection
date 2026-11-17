#!/usr/bin/env python3
"""Wazuh alerts.json 기반 ML 이상탐지 엔진 (랩용).

개념:
  - Wazuh는 룰 기반 SIEM이다. 이 스크립트는 Wazuh가 떨군 alerts.json(JSON lines)을
    읽어, 출발지 IP(srcip)별로 '행동 피처 벡터'를 만든 뒤 Isolation Forest(비지도)로
    '평소와 동떨어진' IP를 이상치로 뽑는다. 즉 Wazuh 위에 ML 한 겹을 얹는다.

피처(환경에 있는 것만 자동 사용):
  - alerts       : 해당 IP가 일으킨 총 알람 수
  - rule_level_max : 최고 룰 레벨
  - uniq_rules   : 서로 다른 룰 개수
  - auth_fail    : 인증 실패 알람 수 (브루트포스/크리덴셜 스터핑 징후)
  - uniq_users   : 공격당한 계정 수 (user enumeration)
  - uniq_agents  : 건드린 에이전트(호스트) 수 (횡적 이동 징후)
  - burst_entropy: 이벤트 시간 간격 분포 엔트로피 (낮을수록 기계적 자동화)
  - dns_qcount   : DNS 쿼리 수 (Sysmon EventID 22)
  - dns_name_ent : 조회 도메인 문자열 엔트로피 (높으면 DGA/터널링 의심)
  - sslvpn_fail  : FortiGate SSL-VPN/로그인 실패 수

사용:
  python3 wazuh_ml_detect.py --alerts /var/ossec/logs/alerts/alerts.json
  python3 wazuh_ml_detect.py --alerts alerts.json --window 10 --watch 15
  python3 wazuh_ml_detect.py --alerts alerts.json --block-file /var/ossec/logs/ml_block.log

--block-file 를 주면 이상 IP를 그 파일에 한 줄씩 적는다. Wazuh가 이 파일을 localfile
로 읽어 커스텀 룰 → Active Response(iptables 차단)로 연결하면 자동 대응이 된다(README 참고).
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone


# ----------------------------- 엔트로피 유틸 -----------------------------
def shannon(counts) -> float:
    """빈도 리스트 → 섀넌 엔트로피(bit). 단조로울수록 0에 가깝다."""
    total = sum(counts)
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c <= 0:
            continue
        p = c / total
        h -= p * math.log2(p)
    return h


def char_entropy(s: str) -> float:
    """문자열의 문자 분포 엔트로피. DGA/DNS 터널링 도메인은 높게 나온다."""
    s = (s or "").lower().replace(".", "")
    if not s:
        return 0.0
    return shannon(list(Counter(s).values()))


def interarrival_entropy(ts_list) -> float:
    """정렬된 타임스탬프(epoch) → 간격 분포 엔트로피.
    사람 손이면 간격이 들쭉날쭉(높음), 스크립트면 일정(낮음)."""
    if len(ts_list) < 3:
        return 0.0
    ts = sorted(ts_list)
    gaps = [round(b - a, 1) for a, b in zip(ts, ts[1:])]  # 0.1초 단위 버킷
    return shannon(list(Counter(gaps).values()))


# ----------------------------- alerts.json 파싱 -----------------------------
def parse_ts(raw) -> float:
    """Wazuh timestamp(ISO8601) → epoch 초. 실패 시 현재시각."""
    if not raw:
        return time.time()
    s = str(raw)
    try:
        # 예: 2026-10-21T13:05:07.123+0900
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y %b %d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).timestamp()
        except ValueError:
            continue
    return time.time()


def dig(d: dict, *path, default=None):
    """중첩 dict 안전 접근."""
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def extract_srcip(a: dict) -> str | None:
    """알람에서 출발지 IP 추출(여러 위치 대응)."""
    for path in (("data", "srcip"), ("data", "src_ip"),
                 ("data", "win", "eventdata", "sourceIp"),
                 ("agent", "ip")):
        v = dig(a, *path)
        if v:
            return str(v)
    return None


def iter_alerts(path: str):
    """alerts.json(JSON lines)을 한 줄씩 dict로."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


# ----------------------------- 피처 집계 -----------------------------
FEATURE_NAMES = [
    "alerts", "rule_level_max", "uniq_rules", "auth_fail", "uniq_users",
    "uniq_agents", "burst_entropy", "dns_qcount", "dns_name_ent", "sslvpn_fail",
]


class Acc:
    __slots__ = ("alerts", "level_max", "rules", "auth_fail", "users",
                 "agents", "ts", "dns_q", "dns_names", "sslvpn_fail")

    def __init__(self):
        self.alerts = 0
        self.level_max = 0
        self.rules = set()
        self.auth_fail = 0
        self.users = set()
        self.agents = set()
        self.ts = []
        self.dns_q = 0
        self.dns_names = []
        self.sslvpn_fail = 0

    def vector(self):
        dns_ent = (sum(char_entropy(n) for n in self.dns_names) / len(self.dns_names)
                   if self.dns_names else 0.0)
        return [
            float(self.alerts),
            float(self.level_max),
            float(len(self.rules)),
            float(self.auth_fail),
            float(len(self.users)),
            float(len(self.agents)),
            interarrival_entropy(self.ts),
            float(self.dns_q),
            dns_ent,
            float(self.sslvpn_fail),
        ]


def build_features(path: str, window_min: float):
    """alerts.json → {srcip: 피처벡터}. window_min 분 이내 알람만."""
    cutoff = time.time() - window_min * 60 if window_min > 0 else 0
    accs: dict[str, Acc] = defaultdict(Acc)

    for a in iter_alerts(path):
        ts = parse_ts(dig(a, "timestamp"))
        if ts < cutoff:
            continue
        ip = extract_srcip(a)
        if not ip:
            continue

        acc = accs[ip]
        acc.alerts += 1
        acc.ts.append(ts)

        level = int(dig(a, "rule", "level", default=0) or 0)
        acc.level_max = max(acc.level_max, level)

        rid = dig(a, "rule", "id")
        if rid:
            acc.rules.add(str(rid))

        groups = dig(a, "rule", "groups", default=[]) or []
        desc = (dig(a, "rule", "description", default="") or "").lower()
        if any("authentication_fail" in g or "invalid_login" in g for g in groups) \
                or "failed password" in desc or "login failed" in desc:
            acc.auth_fail += 1

        user = dig(a, "data", "srcuser") or dig(a, "data", "dstuser") \
            or dig(a, "data", "win", "eventdata", "targetUserName")
        if user:
            acc.users.add(str(user))

        agent = dig(a, "agent", "name") or dig(a, "agent", "id")
        if agent:
            acc.agents.add(str(agent))

        # DNS (Sysmon EventID 22)
        qname = dig(a, "data", "win", "eventdata", "queryName") \
            or dig(a, "data", "dns", "query")
        if qname:
            acc.dns_q += 1
            acc.dns_names.append(str(qname))

        # FortiGate SSL-VPN / 로그인 실패
        if "sslvpn" in desc or "ssl-vpn" in desc or "vpn" in " ".join(groups):
            if "fail" in desc or "denied" in desc:
                acc.sslvpn_fail += 1

    return {ip: acc.vector() for ip, acc in accs.items()}


# ----------------------------- ML 판정 -----------------------------
def detect(features: dict, contamination: float):
    """Isolation Forest로 이상 IP 판정. 표본이 적으면 룰 기반 폴백."""
    ips = list(features)
    if not ips:
        return []

    X = [features[ip] for ip in ips]

    # 표본이 너무 적으면 ML이 의미 없음 → 간단 룰 폴백
    if len(ips) < 8:
        out = []
        for ip, v in zip(ips, X):
            f = dict(zip(FEATURE_NAMES, v))
            # 인증실패 다수 OR 다수 호스트 접촉 OR 고위험 룰
            suspicious = (f["auth_fail"] >= 10 or f["uniq_agents"] >= 3
                          or f["rule_level_max"] >= 10 or f["dns_name_ent"] >= 3.5)
            out.append((ip, -1.0 if suspicious else 1.0, suspicious, f))
        out.sort(key=lambda r: (not r[2], r[0]))
        return out

    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        sys.stderr.write("[!] scikit-learn 미설치: pip install scikit-learn\n")
        return []

    model = IsolationForest(contamination=contamination, random_state=0,
                            n_estimators=200)
    model.fit(X)
    scores = model.decision_function(X)   # 낮을수록 이상
    preds = model.predict(X)              # -1 = 이상치

    rows = []
    for ip, s, p, v in zip(ips, scores, preds, X):
        rows.append((ip, float(s), p == -1, dict(zip(FEATURE_NAMES, v))))
    rows.sort(key=lambda r: r[1])  # 이상한 순
    return rows


def report(rows, block_file=None):
    anomalies = [r for r in rows if r[2]]
    print(f"\n{'='*64}")
    print(f"[ML 이상탐지] 주체 {len(rows)}개 · 이상 {len(anomalies)}개 "
          f"· {datetime.now(timezone.utc).astimezone():%H:%M:%S}")
    print('='*64)
    for ip, score, is_anom, f in rows:
        flag = "🚨 이상" if is_anom else "  정상"
        print(f"{flag}  {ip:<18} score={score:+.3f}  "
              f"alerts={int(f['alerts'])} authfail={int(f['auth_fail'])} "
              f"users={int(f['uniq_users'])} hosts={int(f['uniq_agents'])} "
              f"dnsH={f['dns_name_ent']:.2f} burstH={f['burst_entropy']:.2f}")
    if block_file and anomalies:
        with open(block_file, "a", encoding="utf-8") as bf:
            for ip, score, _, _ in anomalies:
                bf.write(f"{datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%S} "
                         f"ML_ANOMALY srcip={ip} score={score:.3f}\n")
        print(f"\n[→] 이상 IP {len(anomalies)}개 기록: {block_file}")


def main():
    # Windows 콘솔(cp949)에서 이모지 출력 시 UnicodeEncodeError 방지
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Wazuh alerts.json ML 이상탐지")
    ap.add_argument("--alerts", default="/var/ossec/logs/alerts/alerts.json",
                    help="Wazuh alerts.json 경로")
    ap.add_argument("--window", type=float, default=15,
                    help="분석 윈도(분). 0이면 전체")
    ap.add_argument("--contamination", type=float, default=0.1,
                    help="예상 이상치 비율(0~0.5)")
    ap.add_argument("--watch", type=float, default=0,
                    help="N초마다 반복(실시간). 0이면 1회")
    ap.add_argument("--block-file", default=None,
                    help="이상 IP 기록 파일(Active Response 연계용)")
    args = ap.parse_args()

    def once():
        feats = build_features(args.alerts, args.window)
        rows = detect(feats, args.contamination)
        report(rows, args.block_file)

    if args.watch > 0:
        print(f"[*] 실시간 감시 시작 (주기 {args.watch}s, 윈도 {args.window}분) "
              f"— Ctrl+C 종료")
        try:
            while True:
                once()
                time.sleep(args.watch)
        except KeyboardInterrupt:
            print("\n[*] 종료")
    else:
        once()


if __name__ == "__main__":
    main()
