#!/usr/bin/env python3
"""Wazuh OpenSearch CSV export → archives.json (JSONL) 변환.
pentagi_features.py 가 읽는 형식으로 변환한다.

사용:
  python tools/csv_to_archives.py raw1.csv raw2.csv --out data/archives.json
"""
import argparse
import csv
import json
import sys

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csvfiles", nargs="+")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    count = 0
    with open(args.out, "w", encoding="utf-8") as fout:
        for path in args.csvfiles:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ts = row.get("_source.data.timestamp", "").strip()
                    ip = row.get("_source.data.client_ip", "").strip()
                    rpath = row.get("_source.data.path", "").strip()
                    status = row.get("_source.data.status", "").strip()
                    ua = row.get("_source.data.user_agent", "").strip()
                    nbytes = row.get("_source.data.response_bytes", "0").strip()

                    if not (ts and ip and rpath):
                        continue
                    if ip in ("", "null", "unknown"):
                        continue

                    try:
                        status_int = int(float(status)) if status else 0
                        nbytes_int = int(float(nbytes)) if nbytes else 0
                    except ValueError:
                        continue

                    obj = {
                        "timestamp": ts,
                        "data": {
                            "timestamp": ts,
                            "client_ip": ip,
                            "path": rpath,
                            "status": status_int,
                            "user_agent": ua or "-",
                            "response_bytes": nbytes_int,
                        }
                    }
                    fout.write(json.dumps(obj, ensure_ascii=False) + "\n")
                    count += 1

    print(f"변환 완료: {count}건 → {args.out}")

if __name__ == "__main__":
    main()
