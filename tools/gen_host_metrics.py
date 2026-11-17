#!/usr/bin/env python3
"""합성 node_exporter 지표 — host_metrics.py 입구 시험용.  (docs/27 §3)

Prometheus query_range 응답(matrix JSON) 형식으로 직접 찍는다 → host_metrics.py --matrix 로 읽음.
--snapshots 를 주면 같은 데이터를 node_exporter /metrics 텍스트 스냅샷(DIR/<host>/<epoch>.prom)으로도 쓴다.

**합성이다 = 입구(파싱·속도계산·구간화·학습 연결)가 도는지 확인용. 성능 증거 아님**(docs/21 §6, 합성 포화 교훈).
실제 검증은 랩 VM 에 node_exporter 를 깔고 같은 명령으로(docs/27 §3-4).

호스트 3대 (평소 부하가 서로 다름):
  10.16.1.10 web01 · 10.16.1.20 db01 · 10.16.1.30 app02
정상 안의 하드네거티브(공격과 닮은 합법 부하):
  batch  (web01, 2시간마다 8분) : CPU 0.7 — 채굴과 닮음(짧고 load 낮음)
  backup (db01,  2시간마다 8분) : 디스크 읽기 + 송신 급증 — 유출과 닮음
공격 (answer.csv 시간구간형, src=호스트):
  mining      (web01, 40분) : CPU 0.95 지속 + load·procs↑
  conn_flood  (web01, 15분) : TCP 연결 ×15, 수신 ×10
  exfil_burst (db01,  10분) : 송신 +12MB/s (디스크는 평소) — backup 과 송신만 같음
  exfil_slow  (app02, 60분) : 송신 ×3 (수신 그대로) — 임계로는 애매한 미묘한 유출
loopback(lo)·loop 디스크에 큰 값을 넣어 '가상 장치 제외'가 되는지도 함께 시험한다.

사용:
  python tools/gen_host_metrics.py --out data/host_matrix.json.gz --answer data/host_answer.csv
"""
import argparse
import csv
import gzip
import json
import math
import os
import random
from datetime import datetime, timedelta, timezone

HOSTS = {  # ip: (이름, cpu 수, cpu 평소, rx B/s, tx B/s, tcp 연결, 메모리 사용률)
    "10.16.1.10": ("web01", 2, 0.18, 80e3, 400e3, 30, 0.45),
    "10.16.1.20": ("db01", 4, 0.25, 300e3, 250e3, 15, 0.70),
    "10.16.1.30": ("app02", 2, 0.12, 120e3, 150e3, 20, 0.35),
}
MEM_TOTAL = 8 * 1024 ** 3
# (id, 호스트, 시작 분, 길이 분, 종류)
ATTACKS = [("mining#0", "10.16.1.10", 250, 40, "mining"),
           ("flood#0", "10.16.1.10", 370, 15, "conn_flood"),
           ("exfil#0", "10.16.1.20", 300, 10, "exfil_burst"),
           ("exfil#1", "10.16.1.30", 330, 60, "exfil_slow")]


def active(ip, minute):
    for _, h, s, d, typ in ATTACKS:
        if h == ip and s <= minute < s + d:
            return typ
    return None


def main():
    ap = argparse.ArgumentParser(description="합성 node_exporter 지표 (matrix JSON)")
    ap.add_argument("--out", default="data/host_matrix.json.gz")
    ap.add_argument("--answer", default="data/host_answer.csv")
    ap.add_argument("--snapshots", help="같은 데이터를 /metrics 텍스트 스냅샷으로도 쓸 디렉터리")
    ap.add_argument("--minutes", type=int, default=480)
    ap.add_argument("--step", type=int, default=15, help="표본 간격(초) = scrape_interval")
    ap.add_argument("--cycle", type=float, default=120,
                    help="부하 주기(분). 실제의 하루 주기를 압축 — 학습 구간이 한 주기 이상 덮어야 함(docs/27 §3-3)")
    ap.add_argument("--seed", type=int, default=11)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    base = datetime(2026, 10, 25, 0, 0, 0, tzinfo=timezone.utc)
    t0 = base.timestamp()

    series = {}   # (name, labels tuple) → [[ts, "v"], ...]

    def put(name, labels, ts, v):
        series.setdefault((name, tuple(sorted(labels.items()))), []).append([ts, repr(float(v))])

    def jit(x, s=0.15):
        return max(0.0, x * rng.gauss(1, s))

    for ip, (name, ncpu, cpu0, rx0, tx0, tcp0, mem0) in HOSTS.items():
        inst = {"instance": f"{ip}:9100", "job": "node"}
        cpu_c = {(c, m): 1e5 * rng.random() for c in range(ncpu) for m in ("idle", "iowait", "user")}
        net = {"rx": 1e9, "tx": 1e9, "lo": 5e9}
        disk = {"read": 1e9, "write": 1e9, "loop": 1e9}
        for k in range(a.minutes * 60 // a.step):
            ts = t0 + k * a.step
            minute = k * a.step / 60
            diurnal = 1 + 0.25 * math.sin(2 * math.pi * minute / a.cycle)
            busy, iow = cpu0 * diurnal, 0.01
            rx, tx, tcp = rx0 * diurnal, tx0 * diurnal, tcp0 * diurnal
            dread, dwrite, procs, load_extra = 50e3, 200e3, 1.5, 0.0
            # 정상 하드네거티브 (2시간마다 8분)
            if minute % 120 < 8:
                if name == "web01":
                    busy = 0.70
                if name == "db01":
                    dread, tx, iow, busy = 30e6, 8e6, 0.10, busy + 0.3
            typ = active(ip, minute)
            if typ == "mining":
                busy, procs, load_extra = 0.95, 1.5 + ncpu, ncpu * 0.3
            elif typ == "conn_flood":
                tcp, rx, busy = tcp * 15, rx * 10, busy + 0.25
            elif typ == "exfil_burst":
                tx += 12e6
            elif typ == "exfil_slow":
                tx *= 3
            busy = min(0.99, jit(busy, 0.1))
            iow = min(1 - busy, jit(iow, 0.3))
            for c in range(ncpu):
                cpu_c[(c, "user")] += busy * a.step
                cpu_c[(c, "iowait")] += iow * a.step
                cpu_c[(c, "idle")] += (1 - busy - iow) * a.step
            net["rx"] += jit(rx) * a.step
            net["tx"] += jit(tx) * a.step
            net["lo"] += 50e6 * a.step                      # 루프백 대량 — 제외돼야 함
            disk["read"] += jit(dread) * a.step
            disk["write"] += jit(dwrite) * a.step
            disk["loop"] += 80e6 * a.step                   # loop 장치 — 제외돼야 함
            for (c, m), v in cpu_c.items():
                put("node_cpu_seconds_total", {**inst, "cpu": str(c), "mode": m}, ts, v)
            put("node_network_receive_bytes_total", {**inst, "device": "eth0"}, ts, net["rx"])
            put("node_network_transmit_bytes_total", {**inst, "device": "eth0"}, ts, net["tx"])
            put("node_network_receive_bytes_total", {**inst, "device": "lo"}, ts, net["lo"])
            put("node_network_transmit_bytes_total", {**inst, "device": "lo"}, ts, net["lo"])
            put("node_disk_read_bytes_total", {**inst, "device": "sda"}, ts, disk["read"])
            put("node_disk_written_bytes_total", {**inst, "device": "sda"}, ts, disk["write"])
            put("node_disk_read_bytes_total", {**inst, "device": "loop0"}, ts, disk["loop"])
            put("node_load1", inst, ts, jit(busy * ncpu + load_extra, 0.1))
            put("node_memory_MemTotal_bytes", inst, ts, MEM_TOTAL)
            put("node_memory_MemAvailable_bytes", inst, ts, MEM_TOTAL * (1 - min(0.95, jit(mem0, 0.03))))
            put("node_netstat_Tcp_CurrEstab", inst, ts, round(jit(tcp, 0.2)))
            put("node_procs_running", inst, ts, round(jit(procs, 0.3)))

    result = [{"metric": {"__name__": n, **dict(lab)}, "values": v} for (n, lab), v in series.items()]
    doc = {"status": "success", "data": {"resultType": "matrix", "result": result}}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    opener = gzip.open if a.out.endswith(".gz") else open
    with opener(a.out, "wt", encoding="utf-8") as f:
        json.dump(doc, f)

    with open(a.answer, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["attack_id", "src", "start", "end", "type"])
        for aid, ip, s, d, typ in ATTACKS:
            fmt = "%Y-%m-%dT%H:%M:%SZ"
            w.writerow([aid, ip, (base + timedelta(minutes=s)).strftime(fmt),
                        (base + timedelta(minutes=s + d)).strftime(fmt), typ])

    if a.snapshots:   # 같은 표본을 시각별 텍스트 노출 형식으로
        by_host_ts = {}
        for (n, lab), vals in series.items():
            d = dict(lab)
            host = d["instance"].split(":")[0]
            lbl = ",".join(f'{k}="{v}"' for k, v in sorted(d.items()) if k not in ("instance", "job"))
            for ts, v in vals:
                by_host_ts.setdefault((host, int(ts)), []).append(f"{n}{{{lbl}}} {v}" if lbl else f"{n} {v}")
        for (host, ts), lines in by_host_ts.items():
            os.makedirs(os.path.join(a.snapshots, host), exist_ok=True)
            with open(os.path.join(a.snapshots, host, f"{ts}.prom"), "w", encoding="utf-8") as f:
                f.write("# HELP synthetic\n" + "\n".join(lines) + "\n")

    n_pts = sum(len(v) for v in series.values())
    print(f"시계열 {len(series)}개 · 표본 {n_pts}개 · 호스트 {len(HOSTS)} × {a.minutes}분 → {a.out}")
    print(f"정답지(시간구간형, 공격 {len(ATTACKS)}건) → {a.answer}")


if __name__ == "__main__":
    main()
