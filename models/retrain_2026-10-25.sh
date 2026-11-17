#!/usr/bin/env bash
# 2026-10-25 에 만든 모델 10개를 같은 입력·설정으로 다시 학습한다 (학습 코드는 전부 ml/train_export.py).
# 결과는 $OUT 에 저장 — models/ 의 원본은 덮어쓰지 않는다. 원본과 같은지는 끝에서 자동 비교.
#
#   bash models/retrain_2026-10-25.sh            # OUT=models/_retrained
#   OUT=/tmp/rt bash models/retrain_2026-10-25.sh
#
# 입력은 data/ 의 CSV (저장소에 포함).
# 2026-10-25 로 같은 내용 재현을 확인함(IF·LOF·AE·RF 예측, AE 경계, 학습 구간 수 일치).
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=${OUT:-models/_retrained}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$OUT"
export PYTHONWARNINGS=ignore
train() { python ml/train_export.py "$@" | head -1; }

# ① 합성 contamination 스윕 (experiments/CHANGELOG "contamination 스윕") — 정답지 있음 → RF 포함
for c in 010 005 003 001; do
  train data/synth_features.csv --answer data/synth_answer.csv --contamination "0.${c#0}" \
        --out "$OUT/model_synth_c$c.joblib"
done

# ② 실제 Juice Shop 1차(48구간) · ③ 실제 2수집 합본(70구간) — 정답지 없이 전체를 정상으로 학습
train data/real_features.csv     --contamination 0.05 --out "$OUT/model_real_juiceshop_c005.joblib"
train data/real_all_features.csv --contamination 0.10 --out "$OUT/model_real_v2_c010.joblib"

# ④ DB 아크(92구간) — 학습 당시(07:07, 커밋 5b53e5f)의 생성기로 만든 로그.
#    지금 gen_db_arc.py 는 08:54 커넥션 id 버그 수정(496a7a4) 후라 96구간이 나와 다른 모델이 된다.
git archive 5b53e5f tools/gen_db_arc.py | tar -x -C "$TMP"
python "$TMP/tools/gen_db_arc.py" --out "$TMP/db_arc.log" --answer "$TMP/db_arc_answer.csv" > /dev/null
python edge/db_features.py --log "$TMP/db_arc.log" --out "$TMP/db_arc_features.csv" > /dev/null
train "$TMP/db_arc_features.csv" --contamination 0.05 --out "$OUT/model_db_arc_c005.joblib"

# ⑤ 실제 정본(246구간, rel 없음)
train data/real_canon_features.csv --contamination 0.05 --out "$OUT/model_real_canon_c005.joblib"

# ⑥ v3 (결함판, archive 보관용) — 정답지를 안 줘서 공격 32구간까지 정상으로 학습된 그 상태
train data/real_canon_rel.csv --contamination 0.05 \
      --out "$OUT/model_web_v3_canon_rel_trained-with-attacks.joblib"

# ⑦ v3.1 운영 후보 — MODEL_CARD.md §9 와 같은 파이프라인 (저장소 datasets/ 만으로 재현)
python -c "import gzip,shutil,sys; shutil.copyfileobj(gzip.open(sys.argv[1]), open(sys.argv[2],'wb'))" \
       datasets/real_web/real_canon_access.log.gz "$TMP/c.log"
python ml/features.py --nginx "$TMP/c.log" --out "$TMP/c.csv" > /dev/null
python ml/relative_features.py "$TMP/c.csv" --mode self --cols req_count max_req_1min --out "$TMP/c_rel.csv" > /dev/null
train "$TMP/c_rel.csv" --answer datasets/real_web/real_canon_answer.csv --feature-set web_v1 \
      --contamination 0.05 --out "$OUT/model_web_v3.1.joblib"

# 원본과 비교
echo; echo "== 원본 대조"
cmp() { python tools/compare_bundles.py "$1" "$OUT/$(basename "$1")" "$2"; }
for c in 010 005 003 001; do cmp models/experiments/model_synth_c$c.joblib data/synth_features.csv; done
cmp models/experiments/model_real_juiceshop_c005.joblib data/real_features.csv
cmp models/experiments/model_real_v2_c010.joblib      data/real_all_features.csv
cmp models/experiments/model_db_arc_c005.joblib       "$TMP/db_arc_features.csv"
cmp models/experiments/model_real_canon_c005.joblib   data/real_canon_features.csv
cmp models/archive/model_web_v3_canon_rel_trained-with-attacks.joblib data/real_canon_rel.csv
cmp models/model_web_v3.1.joblib                      "$TMP/c_rel.csv"
