#!/usr/bin/env bash
# docs/37 재현 — numpy 만 필요 (scikit-learn 없이 돈다). 저장소 루트에서:  bash docs/37_결과/run.sh
set -e
T=$(mktemp -d)
python - "$T" <<'PY'
import gzip, shutil, sys
for src, dst in (("real_canon_access.log.gz", "c.log"), ("boost_bola_slow_access.log.gz", "boost.log")):
    shutil.copyfileobj(gzip.open("datasets/real_web/" + src, "rb"), open(sys.argv[1] + "/" + dst, "wb"))
PY
python ml/features.py --nginx "$T/c.log" --out "$T/c.csv" >/dev/null
python ml/features.py --nginx "$T/boost.log" --out "$T/boost.csv" >/dev/null
A=datasets/real_web/real_canon_answer.csv; B=datasets/real_web/boost_bola_answer.csv
echo "################ 1. 빈도 룰 재현 — real_canon (소유 자원 URL 을 건드린 출발지만)"
python docs/37_결과/rule_sim.py "$T/c.log" $A
echo; echo "################ 2. 빈도 룰 재현 — boost_bola_slow"
python docs/37_결과/rule_sim.py "$T/boost.log" $B
echo; echo "################ 3. LOF(numpy) vs uniq_objects>=5 룰 — 출발지 분할 seed 0~4"
python docs/37_결과/lof_np.py "$T/c.csv" "$T/boost.csv" $A $B
