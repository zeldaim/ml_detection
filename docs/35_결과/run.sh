#!/usr/bin/env bash
# docs/35 재현 — Docker 이미지(ml-detection)에서:
#   MSYS_NO_PATHCONV=1 docker run --rm -v "D:/ml_detection:/app" ml-detection bash /app/docs/35_결과/run.sh
# 인자: 피처 CSV (기본 data/feat_canon_otto.csv = features.py --nginx <real_canon 원본> --nginx data/otto_replay_s0.log)
#   다른 재생 시드: bash /app/docs/35_결과/run.sh data/feat_canon_otto_s1.csv
set -e
cd /app
F=${1:-data/feat_canon_otto.csv}; A=datasets/real_web/real_canon_answer.csv
C="--group-by type --contamination 0.05"
echo "### 지름길: OTTO 재생 정상(10.30.*) vs 생성기·공격 전체 — 공격 출발지 행은 빼고 정상끼리"
F=$F python - <<'PY'
import csv
import os
rows=[r for r in csv.DictReader(open(os.environ["F"])) if not r["ip"].startswith("10.16.1.2")]
csv.writer(open("/tmp/normals.csv","w",newline="")).writerows([list(rows[0])]+[list(r.values()) for r in rows])
PY
awk -F, 'NR>1 && $1 ~ /^10\.30\./ {print $1}' $F | sort -u | awk 'BEGIN{print "ip,label,type"}{print $1",attack,otto_replay"}' > /tmp/otto_as_label.csv
python ml/shortcut_auc.py /tmp/normals.csv /tmp/otto_as_label.csv
for s in 0 1 2 3 4; do
  echo "################ A 기준선 seed $s"; python ml/supervised.py $F --answer $A $C --seed $s --exclude-prefix 10.30. | sed -n '/분할/p;/합계/,/H5/p'
  echo "################ B 재생 학습추가 seed $s"; python ml/supervised.py $F --answer $A $C --seed $s --train-only-prefix 10.30. | sed -n '/분할/p;/합계/,/H5/p'
done
echo "################ C 생성기 정상으로만 학습 → 재생 정상 오탐 (회차 무관, 공격 라벨 미사용)"
F=$F python - <<'PY'
import csv, numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler
import os
rows=list(csv.DictReader(open(os.environ["F"])))
cols=[c for c in rows[0] if c not in ("ip","window_start")]
X=lambda rs: np.array([[float(r[c] or 0) for c in cols] for r in rs])
gen=[r for r in rows if r["ip"].startswith("10.16.1.1")]            # 생성기 정상 출발지(101~132)
otto=[r for r in rows if r["ip"].startswith("10.30.")]
for name, tr, te in [("생성기 전부 학습", gen, otto)]:
    Xtr, Xte = X(tr), X(te); sc=StandardScaler().fit(Xtr)
    iso=IsolationForest(n_estimators=300, contamination=0.05, random_state=0).fit(Xtr)
    lof=LocalOutlierFactor(n_neighbors=20, contamination=0.05, novelty=True).fit(sc.transform(np.unique(Xtr,axis=0)))
    ae=MLPRegressor(hidden_layer_sizes=(max(2,Xtr.shape[1]//2),), max_iter=1500, random_state=0).fit(sc.transform(Xtr), sc.transform(Xtr))
    err=lambda Z: ((ae.predict(sc.transform(Z))-sc.transform(Z))**2).mean(axis=1)
    thr=np.quantile(err(Xtr), 0.95)
    f={"IF": iso.predict(Xte)==-1, "LOF": lof.predict(sc.transform(Xte))==-1, "AE": err(Xte)>=thr}
    print(f"{name}: 학습 {len(tr)}구간 → 재생 정상 {len(te)}구간 / 출발지 {len({r['ip'] for r in te})}개")
    for k,v in f.items():
        ips={r['ip'] for r,b in zip(te,v) if b}
        print(f"  {k:<4} 오탐 구간 {v.sum()}/{len(v)} ({v.mean():.0%}) · 한 번이라도 걸린 출발지 {len(ips)}/{len({r['ip'] for r in te})}")
PY
