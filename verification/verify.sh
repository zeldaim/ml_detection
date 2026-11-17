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
grep -E "^IF\|LOF\|AE " /tmp/ver_sup.txt | head -1 | sed 's/^/     /'
echo "     (↑ AE seed 하나·11피처 값. 확정 수치는 seed 10개 평균 0.91±0.04 — docs/27 §2-1, ml/ablation.py)"

echo "===== [2] train→inference 연결 (모델 저장·로드·판정) ====="
python ml/predict.py models/model_web_v3.1.joblib /tmp/ver_r.csv >/tmp/ver_pred.txt 2>&1 && ok "저장모델(v3.1) 로드·판정" || no "predict 실패"
# 회귀: IP형 정답지로 학습하면 공격 구간이 빠져야 한다 (v3 결함 — 정상 214, 공격 포함이면 246)
python ml/train_export.py /tmp/ver_r.csv --answer datasets/real_web/real_canon_answer.csv --feature-set web_v1 --out /tmp/ver_m.joblib 2>/dev/null   | grep -q "학습 정상 구간 214개" && ok "IP형 정답지 → 정상만 학습(214)" || no "공격이 정상으로 섞여 학습됨(docs/27 §4)"

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

echo "===== [5] 피처셋 확정 + 호스트 지표 입구 (docs/27) ====="
rm -rf /tmp/ver_h*.csv /tmp/ver_h*.json.gz /tmp/ver_pk.txt /tmp/ver_snap   # 이전 실행 산출물로 통과하는 것 방지
python ml/feature_spec.py --check /tmp/ver_r.csv web_v1 >/dev/null 2>&1 && ok "웹 피처 CSV ⊇ web_v1" || no "web_v1 열 누락"
python tools/gen_host_metrics.py --minutes 60 --out /tmp/ver_h.json.gz --answer /tmp/ver_ha.csv --snapshots /tmp/ver_snap >/dev/null 2>&1
python edge/host_metrics.py --matrix /tmp/ver_h.json.gz --out /tmp/ver_hm.csv >/dev/null 2>&1
python edge/host_metrics.py --snapshots /tmp/ver_snap --out /tmp/ver_hs.csv >/dev/null 2>&1
[ -s /tmp/ver_hm.csv ] && cmp -s /tmp/ver_hm.csv /tmp/ver_hs.csv && ok "입구 2경로(query_range JSON / /metrics 스냅샷) 출력 동일" || no "입력 경로별 결과가 다름"
python tools/gen_host_metrics.py --out /tmp/ver_h8.json.gz --answer /tmp/ver_h8a.csv >/dev/null 2>&1
python edge/host_metrics.py --matrix /tmp/ver_h8.json.gz --out /tmp/ver_h8.csv >/dev/null 2>&1
python ml/per_key_eval.py /tmp/ver_h8.csv --answer /tmp/ver_h8a.csv 2>/dev/null | awk '/^LOF /{print "     " $0}' | tee /tmp/ver_pk.txt
python - /tmp/ver_pk.txt <<'PY' && ok "호스트별 기준선 > 통합 모델 (LOF 탐지)" || no "호스트별 모델 우위 재현 안 됨"
import re, sys; t=open(sys.argv[1],encoding="utf-8").read(); a=[float(x) for x in re.findall(r"탐지 ([0-9.]+)", t)]
raise SystemExit(0 if len(a)==2 and a[1] > a[0] else 1)
PY
rm -rf /tmp/ver_snap

echo "===== [6] 폴더 투입구 (ml/ingest.py — inbox/README.md) ====="
rm -rf /tmp/ver_inbox && mkdir -p /tmp/ver_inbox
cp datasets/real_web/real_canon_access.log.gz /tmp/ver_inbox/ && cp datasets/real_web/real_canon_answer.csv /tmp/ver_inbox/answer_web.csv
cp datasets/real_db/db_arc_general.log.gz /tmp/ver_inbox/ && cp datasets/real_db/db_arc_answer.csv /tmp/ver_inbox/answer_db.csv
python ml/ingest.py /tmp/ver_inbox --retrain >/tmp/ver_ingest.txt 2>&1   && grep -q "웹(API 행위): 탐지" /tmp/ver_ingest.txt && grep -q "DB(쿼리): 탐지" /tmp/ver_ingest.txt   && ok "로그 폴더 → 종류 자동 인식 → 피처 → 재학습 → 채점 보고서" || no "ingest 실패 (/tmp/ver_ingest.txt)"
grep -E "^  (웹|DB)" /tmp/ver_ingest.txt | sed 's/^/   /'
rm -rf /tmp/ver_inbox

echo "===== [7] 공통 요청 형식 (normalize/ — 수집 방식이 바뀌어도 같은 피처) ====="
python normalize/normalize.py /tmp/ver.log --out /tmp/ver_req.jsonl >/dev/null 2>&1 \
  && python ml/features.py --requests /tmp/ver_req.jsonl --out /tmp/ver_f2.csv >/dev/null 2>&1 \
  && cmp -s /tmp/ver_f.csv /tmp/ver_f2.csv && ok "nginx 직접 vs 공통 형식 경유 → 피처 CSV 동일" || no "공통 형식 경유 피처가 다름 (/tmp/ver_f2.csv)"

echo
echo "===== 결과: PASS=$PASS  FAIL=$FAIL ====="
[ "$FAIL" -eq 0 ] && echo "모든 검증 통과" || echo "실패 항목 확인 필요"
