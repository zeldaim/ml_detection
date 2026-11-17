#!/usr/bin/env python3
"""확정 피처셋 — 학습·판정이 같은 열·같은 순서를 쓰도록 하는 단일 출처.  (docs/27)

피처를 바꾸려면 여기서 **새 이름(web_v2 …)을 추가**한다. 기존 셋을 고치면 그 셋으로 학습한 모델과
열이 어긋난다(predict 가 막는다). 각 피처의 채택 근거는 docs/27 §2 소거 실험.

사용:
  python ml/feature_spec.py                         # 전체 목록
  python ml/feature_spec.py --check data/x.csv web_v1   # CSV 가 그 셋을 담고 있나
  python ml/train_export.py x.csv --answer a.csv --feature-set web_v1 ...
"""
import argparse
import csv
import sys

# (이름, 소스, 주 공격 클래스, 역할)
#   역할 = 소거 실험(docs/27 §2) 결과, seed 노이즈(±0.04)를 넘는 차이만 인정:
#   탐지(빼면 탐지율↓; LOF 는 결정적이라 작은 차이도 인정) / 탐지(묶음)(혼자선 노이즈 내, 짝과 함께 빼면 ↓) / 오탐억제(빼면 오탐↑) / 중립(노이즈 내 — 해당 공격 클래스 대비로 유지, 제거 1순위) / 커버리지(이 데이터에 해당 공격이 없어 측정 불가) / 가설(합성으로만 확인)
FEATURE_SETS = {
    "web_v1": [
        ("req_count", "nginx", "대량수집·자원소비", "중립"),
        ("max_req_1min", "nginx", "대입·고속 열거", "탐지"),
        ("uniq_paths", "nginx", "스캐닝·섀도우API", "중립"),
        ("uniq_objects", "nginx", "BOLA(소유자원 열거)", "탐지"),
        ("err_ratio", "nginx", "대입·스캐닝", "중립"),
        ("write_ratio", "nginx", "BFLA·대량 쓰기", "커버리지"),
        ("interval_cv", "nginx", "봇/AI 에이전트 규칙성", "탐지"),
        ("endpoint_entropy", "nginx", "내용 겹침(빠른 합법 vs 한 경로 수집)", "탐지(묶음·§J)"),
        ("rel_req_count", "UEBA", "계정탈취형 급변", "탐지(묶음)"),
        ("rel_max_req_1min", "UEBA", "계정탈취형 급변", "탐지(묶음)"),
    ],
    # db_v1 = 현재 db_features.py 그대로 고정. 역할은 합성 DB 아크 소거 결과(앙상블 오탐 0.31 — 운영급 아님)
    "db_v1": [
        ("q_count", "mysql", "대량수집", "탐지"),
        ("select_ratio", "mysql", "읽기 편중", "오탐억제"),
        ("write_ratio", "mysql", "대량 쓰기·변조", "오탐억제"),
        ("uniq_templates", "mysql", "scrape vs 리포트(하드네거티브)", "중립"),
        ("distinct_tables", "mysql", "스키마 탐색", "오탐억제"),
        ("distinct_where_ids", "mysql", "BOLA/열거", "탐지"),
        ("sqli_token_hits", "mysql", "SQLi", "탐지"),
        ("interval_cv", "mysql", "봇 규칙성", "중립"),
    ],
    "host_v1": [
        ("cpu_busy_mean", "node_exporter", "채굴·DoS", "가설"),
        ("cpu_busy_sustain", "node_exporter", "채굴(지속) vs 배치(짧음)", "가설"),
        ("cpu_iowait_mean", "node_exporter", "디스크 대량 읽기", "가설"),
        ("load1_per_cpu_max", "node_exporter", "채굴·과부하", "가설"),
        ("mem_used_ratio", "node_exporter", "메모리 고갈", "가설"),
        ("net_rx_Bps", "node_exporter", "연결 폭주(DoS)", "가설"),
        ("net_tx_Bps", "node_exporter", "유출", "가설"),
        ("tx_rx_ratio", "node_exporter", "유출(송신 편중)", "가설"),
        ("net_tx_cv", "node_exporter", "버스트 유출", "가설"),
        ("tcp_estab_max", "node_exporter", "연결 폭주", "가설"),
        ("disk_io_Bps", "node_exporter", "백업(하드네거티브)·랜섬웨어", "가설"),
        ("procs_running_max", "node_exporter", "채굴·포크", "가설"),
    ],
}

# 채택하지 않은 피처와 이유 (다시 제안될 때 근거 확인용)
REJECTED = {
    "ssh_fail": "nginx 소스에선 항상 0(분산 0) — 정보 없음. --archives 로 sshd 를 같이 볼 때만 의미, 셋에서 제외",
    "seq_id_score": "uniq_objects 와 중복, IF 오탐↑ (docs/21 §E)",
    "ip / user_agent / 원문 경로·쿼리": "식별자·원문 = 누수·민감정보 (docs/21 §4, docs/25)",
}


def columns(name):
    if name not in FEATURE_SETS:
        sys.exit(f"모르는 피처셋 {name!r} — 있는 것: {', '.join(FEATURE_SETS)}")
    return [f[0] for f in FEATURE_SETS[name]]


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="확정 피처셋 보기/검사")
    ap.add_argument("--check", nargs=2, metavar=("CSV", "SET"), help="CSV 헤더가 피처셋을 담고 있는지")
    args = ap.parse_args()
    if args.check:
        path, name = args.check
        header = next(csv.reader(open(path, encoding="utf-8")))
        missing = [c for c in columns(name) if c not in header]
        if missing:
            sys.exit(f"{path}: {name} 에 필요한 열 없음 {missing}")
        print(f"{path}: {name} 피처 {len(columns(name))}개 모두 있음")
        return
    for name, feats in FEATURE_SETS.items():
        print(f"[{name}] {len(feats)}개")
        for f, src, cls, role in feats:
            print(f"  {f:<20}{src:<15}{role:<8}{cls}")
    print("[채택 안 함]")
    for f, why in REJECTED.items():
        print(f"  {f}: {why}")


if __name__ == "__main__":
    main()
