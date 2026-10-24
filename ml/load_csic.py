#!/usr/bin/env python3
"""CSIC 2010 HTTP 데이터셋 → 우리 피처 형식으로 변환 (공개 데이터 교차검증용).  (docs/07·docs/16 §2)

CSIC 2010은 스페인 CSIC의 웹 요청 모음(정상/비정상 라벨). 우리 랩 결과가 공개 데이터에서도
재현되는지 확인하는 교차검증에 쓴다.

⚠️ 데이터는 수동으로 받아 둬야 한다(저작권·용량). 받는 곳 예:
   - "CSIC 2010 HTTP dataset" 검색 → 여러 미러(GitHub/대학 페이지)에 normalTrafficTraining.txt,
     anomalousTrafficTest.txt 형태 또는 CSV 변환본이 있다.
   형식이 미러마다 달라, 이 스크립트는 흔한 두 형식을 지원하고 안 맞으면 --inspect로 샘플을 보여준다.

CSIC 공격은 '요청 내용(페이로드)' 공격(SQLi·XSS·traversal)이다 — 우리 랩의 '행위' 공격(BOLA·느린공격)과
다른 종류(docs/16). 그래서 행위 피처가 아니라 **내용 피처**(sqli/xss/traversal 토큰, 특수문자 비율,
경로 길이, 파라미터 수)를 뽑는다. CSIC엔 IP·시각이 없어 요청 win개를 한 구간으로 묶어 집계(max 위주).
정상=2026-01-01, 공격=2026-01-02로 시각을 찍어 --train-until로 정상만 학습할 수 있게 한다.

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
# CSIC 공격은 '요청 내용(페이로드)' 공격 → 내용 피처로 잡는다 (우리 행위 피처와 다른 종류, docs/16)
SQLI = re.compile(r"(union\b|select\b|sleep\(|benchmark\(|information_schema|or\s+1\s*=\s*1|--|/\*|%27|'|;|\bdrop\b|\bexec\b)", re.I)
XSS = re.compile(r"(<script|onerror\s*=|onload\s*=|alert\(|%3cscript|javascript:|<img|<svg|document\.cookie)", re.I)
TRAVERSAL = re.compile(r"(\.\./|\.\.%2f|/etc/passwd|%2e%2e|\bcmd\b|/bin/)", re.I)
SPECIAL = re.compile(r"[^A-Za-z0-9/_\-.?=&%: ]")   # 특수문자(페이로드일수록 많음)

# 요청 1건 → 내용 피처 dict
CONTENT_FEATURES = ["req_count", "uniq_paths", "path_len_max", "param_count_max",
                    "body_len_max", "special_ratio_max", "sqli_hits", "xss_hits", "traversal_hits"]


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


def _special_ratio(s):
    return round(len(SPECIAL.findall(s)) / len(s), 4) if s else 0.0


def _agg(reqs, label, idx):
    """구간(요청 묶음) → 내용 피처. 공격은 한 요청만 악성이어도 되므로 max 위주."""
    paths = set()
    path_len = param = body = spec = sqli = xss = trav = 0
    for method, path, raw in reqs:
        # 요청 라인 아래 본문(헤더 제외 근사: 빈 줄 이후). CSIC POST 본문에 페이로드가 많다.
        body_txt = raw.split("\n\n", 1)[1] if "\n\n" in raw else ""
        probe = path + " " + body_txt            # 경로+쿼리+본문을 함께 검사
        paths.add((method, path.split("?")[0]))
        path_len = max(path_len, len(path))
        param = max(param, path.count("=") + body_txt.count("="))
        body = max(body, len(body_txt.strip()))
        spec = max(spec, _special_ratio(probe))
        sqli += 1 if SQLI.search(probe) else 0
        xss += 1 if XSS.search(probe) else 0
        trav += 1 if TRAVERSAL.search(probe) else 0
    n = len(reqs)
    # 시각은 단조 증가(정상=1일, 공격=2일) → --train-until로 정상만 학습 가능
    day = "01" if label == "normal" else "02"
    return {
        "ip": f"csic-{label}-{idx}",
        "window_start": f"2026-01-{day}T{idx // 60 % 24:02d}:{idx % 60:02d}:00Z",
        "req_count": n, "uniq_paths": len(paths), "path_len_max": path_len,
        "param_count_max": param, "body_len_max": body, "special_ratio_max": spec,
        "sqli_hits": sqli, "xss_hits": xss, "traversal_hits": trav, "_label": label,
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

    cols = ["ip", "window_start"] + CONTENT_FEATURES
    nrows, idx = features_from(iter_requests(args.normal), "normal", args.window, 0)
    arows, _ = features_from(iter_requests(args.anomalous), "attack", args.window, 0)
    allrows = nrows + arows

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in allrows:
            w.writerow({c: r[c] for c in cols})
    with open(args.answer, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "label", "type"])
        for r in arows:
            w.writerow([r["ip"], "attack", "csic_anomalous"])
    print(f"정상 구간 {len(nrows)} · 공격 구간 {len(arows)} → {args.out}")
    print(f"피처(내용 기반): {', '.join(CONTENT_FEATURES)}")
    print(f"정답지: {args.answer}")
    print("\n다음 — 정상만으로 학습(--train-until)해야 공정하다. 정상=2026-01-01, 공격=2026-01-02 이므로:")
    print(f"  python ml/models.py {args.out} --train-until 2026-01-02T00:00:00Z --methods iforest lof autoencoder --contamination 0.1 --out data/det_csic.csv")
    print(f"  python ml/evaluate.py data/det_csic.csv --answer {args.answer}")
    print("※ CSIC은 '요청 내용' 공격이라 내용 피처(sqli/xss/특수문자)로 잡는다. 우리 랩의 '행위' 탐지와는 다른 종류(docs/16).")


if __name__ == "__main__":
    main()
