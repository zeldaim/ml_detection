#!/usr/bin/env bash
# 외부 데이터 없이 핵심 결과를 재생성하는 데모 (합성 데이터 → 피처 → IF·LOF·AE·RF 비교 → 채점).
# 실제 랩 로그·CSIC은 docs/08·14·16 참고. 출력은 data/(gitignore)로 간다.
set -e
cd "$(dirname "$0")"
export PYTHONUTF8=1
mkdir -p data

echo "########## 1. DB 합성 데이터 생성 (정상 + BOLA·SQLi·대량수집) ##########"
python tools/gen_db_traffic.py --out data/general_lab.log --answer data/answer_db.csv
python edge/db_features.py --log data/general_lab.log --out data/features_db.csv

echo
echo "########## 2. DB — 비지도(IF·LOF·AE) + 지도(RF) 비교 [E2: 처음 보는 공격] ##########"
python ml/supervised.py data/features_db.csv --answer data/answer_db.csv \
    --group-by type --contamination 0.05 | sed -n '/합계/,/H5/p'

echo
echo "########## 3. DB — RF 공격 종류 분류 ##########"
python ml/classify_type.py data/features_db.csv --answer data/answer_db.csv | sed -n '/종류 정확도/,/중요도/p'

echo
echo "########## 4. alerts 샘플(커밋됨) — 같은 비교 ##########"
python ml/features.py --alerts samples/sample_alerts_if.json --out data/features_alerts.csv
python ml/supervised.py data/features_alerts.csv --answer samples/sample_answer_if.csv \
    --group-by type --contamination 0.05 | sed -n '/합계/,/H5/p'

echo
echo "########## 5. 저장 모델 학습 + 불러서 판정 ##########"
python ml/train_export.py data/features_db.csv --answer data/answer_db.csv \
    --contamination 0.05 --out data/demo_db_model.joblib | sed -n '1,6p'
python ml/predict.py data/demo_db_model.joblib data/features_db.csv | grep -E 'window_start|10.16.2.10[1-6]' | head

echo
echo "완료. 핵심: 느린 BOLA를 IF는 놓치고 LOF·AE가 잡는다 (H5). 자세한 해석은 docs/13."
