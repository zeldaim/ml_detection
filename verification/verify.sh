#!/usr/bin/env bash
# 검증 재실행 스크립트 — 누구나 repo clone 후 돌려 결과를 '직접' 확인(= 우리 주장 아닌 재현).
# 붙여진 비판(AI 생성 코드 함정)에 대한 반증을 '증거'로 돌린다.
#   bash verification/verify.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export PYTHONUTF8=1
PASS=0; FAIL=0
ok(){ echo "  ✅ $1"; PASS=$((PASS+1)); }
no(){ echo "  ❌ $1"; FAIL=$((FAIL+1)); }

echo "===== [1] 파이프라인 end-to-end (껍데기/연결안됨 반증) ====="
gunzip -c datasets/real_web/real_canon_access.log.gz > /tmp/ver.log
python ml/features.py --nginx /tmp/ver.log --out /tmp/ver_f.csv >/dev/null 2>&1 && ok "로그→피처" || no "피처 추출 실패"
python ml/relative_features.py /tmp/ver_f.csv --mode self --cols req_count max_req_1min --out /tmp/ver_r.csv >/dev/null 2>&1 && ok "피처→상대피처" || no "상대피처 실패"
python ml/supervised.py /tmp/ver_r.csv --answer datasets/real_web/real_canon_answer.csv --group-by type --contamination 0.05 >/tmp/ver_sup.txt 2>&1 && ok "교차검증 완주" || no "검증 실패"
grep -E "IF\|LOF\|AE" /tmp/ver_sup.txt | head -1 | sed 's/^/     /'

echo "===== [2] train→inference 연결 (모델 저장·로드·판정) ====="
python ml/predict.py models/model_web_v3_canon_rel.joblib /tmp/ver_r.csv >/tmp/ver_pred.txt 2>&1 && ok "저장모델 로드·판정" || no "predict 실패"

echo "===== [3] 누수/가짜100% 반증 (퍼뮤테이션: 가짜공격 ≈0, 진짜 >>) ====="
python - <<'PY'
import csv, random
rows=list(csv.DictReader(open("datasets/real_web/real_canon_features.csv",encoding="utf-8")))
ans={a["ip"] for a in csv.DictReader(open("datasets/real_web/real_canon_answer.csv",encoding="utf-8"))}
nip=sorted({r["ip"] for r in rows if r["ip"] not in ans}); rng=random.Random(7)
open("data/_fake.csv","w",encoding="utf-8").write("ip,label,type\n"+"\n".join(f"{ip},attack,fake" for ip in rng.sample(nip,4)))
PY
python ml/models.py datasets/real_web/real_canon_features.csv --methods lof --contamination 0.1 --out data/_d.csv >/dev/null 2>&1
FAKE=$(python ml/evaluate.py data/_d.csv --answer data/_fake.csv 2>/dev/null | awk '/^lof *구간/{print $7}')
REAL=$(python ml/evaluate.py data/_d.csv --answer datasets/real_web/real_canon_answer.csv 2>/dev/null | awk '/^lof *구간/{print $7}')
echo "     가짜공격 재현율=$FAKE  진짜공격 재현율=$REAL"
awk "BEGIN{exit !($REAL > $FAKE)}" && ok "진짜>가짜 → 누수 없음(모델이 진짜 신호 학습)" || no "가짜가 더 높음 → 누수 의심"
rm -f data/_fake.csv data/_d.csv

echo "===== [4] 누수원 차단 확인 (IP/UA 피처 미사용) ====="
grep -q 'WEB_FEATURES = \["req_count"' ml/features.py && ! grep -q '"ip"\|"user_agent"\|"ua"' <(grep WEB_FEATURES ml/features.py) && ok "피처에 IP/UA 없음(행위 피처만)" || no "원문 식별자가 피처에 있음"

echo
echo "===== 결과: PASS=$PASS  FAIL=$FAIL ====="
[ "$FAIL" -eq 0 ] && echo "모든 검증 통과" || echo "실패 항목 확인 필요"
