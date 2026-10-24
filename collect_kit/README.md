# collect_kit — 실제 로그 수집 (플라이휠 첫 실제 바퀴)

> Juice Shop 타겟 + Kali 로 **정상 + 공격 변주** 로그를 만들어, `features.py → accumulate.py → supervised.py`
> 로 검증하고 누적 데이터셋에 쌓는다. Wazuh 없이 **nginx access.log** 만으로 된다. 설계: `docs/20`.

## 0. 준비 (한 번)
- 타겟(Juice Shop+nginx, 예 `10.16.1.10`)에 **정상 계정 1개 가입** → `EMAIL`/`PASS` 에 넣는다.
- 세 스크립트의 `TARGET`/`EMAIL`/`PASS` 기본값(TODO)을 네 랩 값으로 수정.
- `bash` 로 실행. (Linux 개행(LF) 필요 — 복사 후 깨지면 `sed -i 's/\r$//' *.sh`)

## 1. 정상 기준선 (공격 금지 구간)
타겟이나 Kali 에서:
```bash
TARGET=http://10.16.1.10 EMAIL=me@juice.sh PASS=... ./normal.sh 20
```
→ 끝나면 출력된 **끝 UTC 시각**을 적어둔다 (= `--train-until`). 이 구간엔 공격을 **절대** 섞지 않는다.

## 2. 공격 변주 (Kali 에서, 시각 자동 기록)
변주를 여러 개 — fast/slow 둘 다 돌리는 게 핵심(`docs/19` 다양성):
```bash
./attack.sh brute_fast
./attack.sh bola_slow     # ← IF 놓치고 LOF/AE 잡는지(H5) 핵심
./attack.sh bola_fast
./attack.sh brute_slow
# (정상 트래픽도 공격과 '동시에' 조금 흘려두면 더 현실적 — 다른 창에서 normal.sh)
```
각 실행이 `runs/<시각>_<scenario>.json` 에 `{scenario,src,start,end}` 를 남긴다 (= 라벨 근거).

## 3. 정답지 만들기
```bash
python build_answer.py            # runs/ → answer.csv
```

## 4. 로그 + 정답지를 호스트로
타겟 nginx 접근 로그와 answer.csv 를 호스트 `D:\ml_detection\data\` 로:
```bash
scp root@10.16.1.10:/var/log/nginx/access.log  <host>:/d/ml_detection/data/real_access.log
scp ./answer.csv                               <host>:/d/ml_detection/data/answer_real.csv
```
> nginx 로그 경로가 다르면(`/var/log/nginx/access.log` 아님) 맞게. Juice Shop 을 nginx 리버스프록시(80)로
> 올린 구성이어야 접근 로그가 남는다. 앱 직접(3000)이면 nginx 를 앞단에 두거나 앱 로그 포맷을 확인.

## 5. (호스트에서) 피처 → 축적 → 검증  ← 이건 분석 담당이 수행
```bash
export PYTHONUTF8=1
python ml/features.py --nginx data/real_access.log --out data/features_real.csv
python ml/accumulate.py data/features_real.csv --answer data/answer_real.csv \
    --source real_juiceshop_$(date +%F) --dataset data/dataset_web.csv
python ml/accumulate.py --dataset data/dataset_web.csv --stats
python ml/supervised.py data/features_real.csv --answer data/answer_real.csv --group-by type
```

## 주의
- 공격은 **직접 통제하는 랩에서만**. Juice Shop 은 의도적 취약 앱 → 외부 노출 금지.
- 정상 계정 비번 등은 커밋하지 말 것(스크립트 기본값은 TODO placeholder).
