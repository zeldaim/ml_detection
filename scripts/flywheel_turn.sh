#!/usr/bin/env bash
# 플라이휠 1회전 자동화 — 환경 무관 재사용.  (런북: docs/24)
# 수집된 로그 + 정답지 → 피처 → (선택)상대피처 → 누적셋 append → 검증(교차검증) 을 한 번에.
#
#   사용:
#     scripts/flywheel_turn.sh --log data/env_access.log --answer data/env_answer.csv --source env_2026-xx [옵션]
#   옵션:
#     --kind nginx|archives|db   입력 로그 종류 (기본 nginx). db = MySQL general log → db_features.py
#     --dataset PATH          누적셋 (기본 data/dataset_web.csv)
#     --relative              UEBA 상대피처(rel_*) 추가 후 검증 (docs/21 §K)
#     --contamination N       IF/LOF/AE 이상비율 (기본 0.1)
#     --no-accumulate         검증만, 누적셋에 안 쌓음
set -euo pipefail
ML="${ML_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
LOG="" ANS="" SRC="" KIND="nginx" DS="data/dataset_web.csv" REL=0 CONT=0.1 ACC=1
while [ $# -gt 0 ]; do case "$1" in
  --log) LOG="$2";shift 2;; --answer) ANS="$2";shift 2;; --source) SRC="$2";shift 2;;
  --kind) KIND="$2";shift 2;; --dataset) DS="$2";shift 2;; --relative) REL=1;shift;;
  --contamination) CONT="$2";shift 2;; --no-accumulate) ACC=0;shift;;
  *) echo "모르는 옵션: $1";exit 1;; esac; done
[ -n "$LOG" ] && [ -n "$ANS" ] && [ -n "$SRC" ] || { echo "--log --answer --source 필수"; exit 1; }
export PYTHONUTF8=1
F="${LOG%.log}_features.csv"

echo "== 1) 피처 추출 ($KIND) =="
if [ "$KIND" = "db" ]; then
  # DB 계층: MySQL general log → db_features.py (웹과 다른 입력 경로). 기본 누적셋도 DB로.
  python "$ML/edge/db_features.py" --log "$LOG" --out "$F" | tail -1
  [ "$DS" = "data/dataset_web.csv" ] && DS="data/dataset_db.csv"
else
  python "$ML/ml/features.py" --$KIND "$LOG" --out "$F" | tail -1
fi

FEED="$F"
if [ "$REL" = 1 ]; then
  echo "== 1b) UEBA 상대피처 =="
  R="${F%.csv}_rel.csv"
  python "$ML/ml/relative_features.py" "$F" --mode self --cols req_count max_req_1min --out "$R" | tail -1
  FEED="$R"
fi

if [ "$ACC" = 1 ]; then
  echo "== 2) 누적셋에 append =="
  python "$ML/ml/accumulate.py" "$F" --answer "$ANS" --source "$SRC" --dataset "$DS" 2>&1 | tail -4
fi

echo "== 3) 검증 (처음 보는 공격, 종류 기준) =="
python "$ML/ml/supervised.py" "$FEED" --answer "$ANS" --group-by type --contamination "$CONT" 2>&1 \
  | grep -E "^(IF|LOF|AE|IF\|LOF\|AE)\s|H5|놓치고" || \
  python "$ML/ml/supervised.py" "$FEED" --answer "$ANS" --group-by type --contamination "$CONT" 2>&1 | tail -12

echo "== 완료: 누적 현황 =="
python "$ML/ml/accumulate.py" --dataset "$DS" --stats 2>&1 | tail -3
