#!/usr/bin/env bash
# docs/33 §5 재현: Docker 이미지(ml-detection)에서 실행 — Windows 스마트 앱 컨트롤이 scipy 를 막으므로
#   MSYS_NO_PATHCONV=1 docker run --rm -v "D:/ml_detection:/app" ml-detection bash /app/docs/33_결과/run.sh
set -e
cd /app
python -c "import sklearn,sys;print('python',sys.version.split()[0],'sklearn',sklearn.__version__)"
zcat datasets/real_web/real_canon_access.log.gz > /tmp/c.log
python ml/features.py --nginx /tmp/c.log --out /tmp/c.csv >/dev/null
python ml/features.py --nginx /tmp/c.log --cum-hours 1 --out /tmp/c_1h.csv >/dev/null
python ml/features.py --nginx /tmp/c.log --cum-hours 24 --out /tmp/c_24h.csv >/dev/null
A=datasets/real_web/real_canon_answer.csv
for f in c c_1h c_24h; do for sp in time ip; do
  echo "################ $f  --split $sp"
  python ml/supervised.py /tmp/$f.csv --answer $A --group-by type --contamination 0.05 --split $sp
done; done
for seed in 1 2 3 4; do echo "################ c_1h --split ip --seed $seed"; python ml/supervised.py /tmp/c_1h.csv --answer $A --group-by type --contamination 0.05 --seed $seed | sed -n '/합계/,/H5/p'; echo "######## c (base) seed $seed"; python ml/supervised.py /tmp/c.csv --answer $A --group-by type --contamination 0.05 --seed $seed | sed -n '/합계/,/H5/p'; done
echo "################ synthetic combined"
for sp in time ip; do echo "## $sp"; python ml/supervised.py data/features_combined.csv --answer data/answer.csv --group-by type --contamination 0.05 --split $sp | sed -n '/분할/p;/합계/,/H5/p'; done
