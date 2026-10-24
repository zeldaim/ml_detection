#!/usr/bin/env python3
"""CSIC 2010 HTTP 데이터셋 → 우리 피처 형식으로 변환 (공개 데이터 교차검증용).  (docs/07·docs/16 §2)

CSIC 2010은 스페인 CSIC의 웹 요청 모음(정상/비정상 라벨). 우리 랩 결과가 공개 데이터에서도
재현되는지 확인하는 교차검증에 쓴다.

⚠️ 데이터는 수동으로 받아 둬야 한다(저작권·용량). 받는 곳 예:
   - "CSIC 2010 HTTP dataset" 검색 → 여러 미러(GitHub/대학 페이지)에 normalTrafficTraining.txt,
     anomalousTrafficTest.txt 형태 또는 CSV 변환본이 있다.
   형식이 미러마다 달라, 이 스크립트는 흔한 두 형식을 지원하고 안 맞으면 --inspect로 샘플을 보여준다.

이 변환기는 '요청 단위' CSIC을 우리 'IP×구간' 피처로 바로 매핑하진 않는다(CSIC엔 IP·시각이 없음).
대신 요청 묶음을 가짜 구간으로 묶어 웹 피처 근사치를 만든다 → 모델 틀 교차검증용.
정밀 비교가 필요하면 요청 단위 분류(별도)로 가야 한다(README 주석 참고).

사용:
  python ml/load_csic.py --normal normalTraffic.txt --anomalous anomalous.txt --out data/features_csic.csv --answer data/answer_csic.csv
  python ml/load_csic.py --inspect anomalous.txt        # 형식 확인만
"""
import argparse
import csv
import os
import re
import sys
from collections import Counter, defaultdict

# CSIC 요청 한 건을 느슨하게 파싱: "METHOD path?query HTTP/1.1" 라인 + 이어지는 헤더/본문
REQ_RE = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|PUT|PATCH)\s+(\S+)\s+HTTP", re.I)
NUM_SEG = re.compile(r"/(\d+)(?=/|$|\?)")
SQLI = re.compile(r"(union|select|sleep\(|information_schema|or\s+1=1|--|/\*|<script|%27|')", re.I)
OWNED = ["/basket", "/order", "/user", "/account", "/tienda1/publico/caracteristicas"]  # 예시, 데이터에 맞게


def inspect(path, n=15):
    print(f"--- {path} 앞 {n}줄 (형식 확인) ---")
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= n:
                break
            print(repr(line.rstrip("\n")[:160]))
    print("\nREQ_RE에 맞는 요청 라인이 보이면 변환 가능. 아니면 미러의 CSV 변환본을 쓰거나 REQ_RE를 맞추자.")


def iter_requests(path):
    """파일에서 (method, path, raw요청블록)을 뽑는다. 요청 라인 기준으로 블록을 나눈다."""
    block, head = [], None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = REQ_RE.match(line.strip())
            if m:
                if head:
                    yield head[0], head[1], "".join(block)
                head, block = (m.group(1).upper(), m.group(2)), [line]
            elif head:
                block.append(line)
        if head:
            yield head[0], head[1], "".join(block)


def features_from(requests, label, win, start_idx):
    """요청들을 win개씩 묶어 가짜 '구간' 피처를 만든다. (CSIC엔 IP·시각 없음 → 묶음=구간 근사)"""
    rows = []
    buf = []
    idx = start_idx
    for req in requests:
        buf.append(req)
        if len(buf) >= win:
            rows.append(_agg(buf, label, idx))
            idx += 1
            buf = []
    if buf:
        rows.append(_agg(buf, label, idx))
    return rows, idx + 1


def _agg(reqs, label, idx):
    paths, objs, writes, errs, sqli = set(), set(), 0, 0, 0
    for method, path, raw in reqs:
        p = path.split("?")[0]
        tmpl = NUM_SEG.sub("/{id}", p)
        paths.add((method, tmpl))
        if any(p.startswith(o) for o in OWNED):
            objs.update(NUM_SEG.findall(path))
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            writes += 1
        if SQLI.search(raw):
            sqli += 1
    n = len(reqs)
    # 우리 웹 피처 열 이름에 최대한 맞춘다(없는 건 0)
    return {
        "ip": f"csic-{label}-{idx}", "window_start": f"2026-01-01T00:{idx % 60:02d}:00Z",
        "req_count": n, "max_req_1min": n, "uniq_paths": len(paths),
        "uniq_objects": len(objs), "err_ratio": round(errs / n, 4),
        "write_ratio": round(writes / n, 4), "interval_cv": 1.0,
        "endpoint_entropy": round(len(paths) / n, 4), "ssh_fail": 0,
        "_sqli": sqli, "_label": label,
    }


def main():
    ap = argparse.ArgumentParser(description="CSIC 2010 → 우리 웹 피처 CSV")
    ap.add_argument("--normal", help="정상 트래픽 파일")
    ap.add_argument("--anomalous", help="비정상 트래픽 파일")
    ap.add_argument("--inspect", help="형식만 확인할 파일")
    ap.add_argument("--window", type=int, default=20, help="요청 몇 개를 한 구간으로 묶을지")
    ap.add_argument("--out", default="data/features_csic.csv")
    ap.add_argument("--answer", default="data/answer_csic.csv")
    args = ap.parse_args()

    if args.inspect:
        inspect(args.inspect)
        return
    if not (args.normal and args.anomalous):
        ap.error("--normal 과 --anomalous 가 필요 (또는 --inspect)")

    cols = ["ip", "window_start", "req_count", "max_req_1min", "uniq_paths", "uniq_objects",
            "err_ratio", "write_ratio", "interval_cv", "endpoint_entropy", "ssh_fail"]
    nrows, idx = features_from(iter_requests(args.normal), "normal", args.window, 0)
    arows, _ = features_from(iter_requests(args.anomalous), "attack", args.window, idx)
    allrows = nrows + arows

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in allrows:
            w.writerow({c: r[c] for c in cols})
    # 정답지: 비정상 구간을 공격으로 (IP형)
    with open(args.answer, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "label", "type"])
        for r in arows:
            w.writerow([r["ip"], "attack", "csic_anomalous"])
    print(f"정상 구간 {len(nrows)} · 공격 구간 {len(arows)} → {args.out}")
    print(f"정답지: {args.answer}")
    print("다음: python ml/models.py", args.out, "--methods iforest lof autoencoder --contamination 0.1")
    print("      python ml/evaluate.py <detections> --answer", args.answer)
    print("※ CSIC엔 IP·시각이 없어 '요청 묶음=구간'으로 근사했다. 정밀 비교는 요청 단위 분류 권장.")


if __name__ == "__main__":
    main()
