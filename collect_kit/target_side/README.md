# collect_kit/target_side — 타겟에서 직접 돌리는 실제 트래픽 생성기

> 이 스크립트들은 **타겟 VM(10.16.1.10)에서 실행**한다. IP 별칭을 붙여 **다중 출발지**로 실제 HTTP
> 요청을 nginx(:80)에 보내 **진짜 로그**를 만든다. (합성 로그 생성 `tools/gen_synth_log.py`와 다름 — 이건 실제 요청.)
> 실행 방식: `scp *.sh root@10.16.1.10:/root/` → `ssh root@10.16.1.10 'bash /root/<script>.sh [초]'`
> nginx 가 remote_addr=별칭 으로 기록하므로 머신 1대로 여러 출발지를 연출(= 실제 로그, 다중 IP).

| 스크립트 | 무엇 | 출발지 |
|---|---|---|
| `real_attacks.sh` | 7종 공격 동시 생성(brute fast/slow·harvest·user_enum·scanning·bola fast/slow) + 정상 동시 | 공격 .221~227, 정상 .101~106 |
| `normal_realistic.sh` | **사람 속도** 정상(프로필 6종, 1~11 req/min). 기본 정상 생성기 | .101~106 |
| `fastclient.sh` | **하드 네거티브**: 빠르지만 합법적인 클라이언트(모바일앱·수집봇) — 빠르나 **경로 다양** | .131~132 |

## 중요 교훈 (docs/21 §H·I)
- 정상 생성기의 **속도가 결과를 왜곡**한다. 정상은 반드시 **현실적 간격**(`normal_realistic.sh`)으로.
  (초기 `normal_rich.sh`는 sleep 1~3s로 너무 빨라 harvest 공격과 인위적 겹침을 만듦 → 폐기, realistic 사용.)
- `fastclient.sh`는 "속도로 못 가르는 정상"을 일부러 만든 **상시 회귀 픽스처**(하드 네거티브). 새 피처·모델이
  이 어려운 정상을 여전히 안 틀리는지 검사용. (단 '빠름+한 경로' 모니터링 케이스는 ML 아닌 allowlist 영역.)

## 수집 → 처리 (호스트에서)
```bash
# 새 로그만 뽑기(mark 이용) 또는 전체 받기
ssh root@10.16.1.10 'cat /var/log/nginx/juiceshop_access.log-* /var/log/nginx/juiceshop_access.log' > data/real.log
python ml/features.py --nginx data/real.log --out data/real_features.csv
python ml/accumulate.py data/real_features.csv --answer <IP형 정답지> --source real_<날짜> --dataset data/dataset_web.csv
python ml/supervised.py data/real_features.csv --answer <정답지> --group-by type
```
> 정답지(IP형): 공격 전용 별칭 IP를 `ip,label,type` 로. 로그 로테이션 주의(`juiceshop_access.log-YYYYMMDD`도 합쳐야 함).
> 공격은 **직접 통제하는 랩의 Juice Shop에만**.
