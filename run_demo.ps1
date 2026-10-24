# 외부 데이터 없이 핵심 결과를 재생성하는 데모 (Windows PowerShell).
# bash 쓰면 run_demo.sh. 출력은 data/(gitignore)로 간다.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$env:PYTHONUTF8 = "1"
New-Item -ItemType Directory -Force data | Out-Null

Write-Host "########## 1. DB 합성 데이터 생성 ##########"
python tools/gen_db_traffic.py --out data/general_lab.log --answer data/answer_db.csv
python edge/db_features.py --log data/general_lab.log --out data/features_db.csv

Write-Host "`n########## 2. DB — IF·LOF·AE + RF 비교 [E2] ##########"
python ml/supervised.py data/features_db.csv --answer data/answer_db.csv --group-by type --contamination 0.05

Write-Host "`n########## 3. DB — RF 공격 종류 분류 ##########"
python ml/classify_type.py data/features_db.csv --answer data/answer_db.csv

Write-Host "`n########## 4. alerts 샘플(커밋됨) — 같은 비교 ##########"
python ml/features.py --alerts samples/sample_alerts_if.json --out data/features_alerts.csv
python ml/supervised.py data/features_alerts.csv --answer samples/sample_answer_if.csv --group-by type --contamination 0.05

Write-Host "`n########## 5. 저장 모델 학습 + 판정 ##########"
python ml/train_export.py data/features_db.csv --answer data/answer_db.csv --contamination 0.05 --out data/demo_db_model.joblib
python ml/predict.py data/demo_db_model.joblib data/features_db.csv

Write-Host "`n완료. 핵심: 느린 BOLA를 IF는 놓치고 LOF·AE가 잡는다 (H5). 해석은 docs/13."
