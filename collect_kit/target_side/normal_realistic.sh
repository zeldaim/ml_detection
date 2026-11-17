#!/usr/bin/env bash
# 타겟에서 실행. 정상 트래픽 '사람 속도'로 — 페이지 읽는 시간만큼 느린 간격.
# 목적: 지난 번 생성기가 너무 빨라(sleep 1~3s) harvest 공격과 인위적으로 겹친 것을 제거.
#       느리게 하면 LOF 오탐이 다시 내려가는지 = 그 겹침이 '인위적'이었나 검증.
set -u
BASE="http://10.16.1.10"
DUR="${1:-1080}"   # 초 (기본 18분)
end=$(( $(date +%s) + DUR ))
echo "[$(date -u +%FT%TZ)] 현실적 정상 ${DUR}s 시작"

# sleep 범위를 사람답게 넓고 길게 (min..max 초)
r_sleep(){ local lo=$1 hi=$2; echo $(( RANDOM % (hi-lo+1) + lo )); }

user(){
  local ip=$1 prof=$2
  while [ "$(date +%s)" -lt "$end" ]; do
    case "$prof" in
      shopper)  curl -s -o /dev/null --interface $ip "$BASE/rest/products/search?q=$(shuf -e apple juice cola -n1)"
                curl -s -o /dev/null --interface $ip "$BASE/rest/products/$((RANDOM%30+1))/reviews"
                curl -s -o /dev/null --interface $ip "$BASE/rest/basket/$((RANDOM%3+1))"; s=$(r_sleep 8 25);;
      browser)  curl -s -o /dev/null --interface $ip "$BASE/api/Products"; s=$(r_sleep 5 15);;
      reviewer) curl -s -o /dev/null --interface $ip "$BASE/rest/products/$((RANDOM%40+1))/reviews"; s=$(r_sleep 10 30);;
      casual)   curl -s -o /dev/null --interface $ip "$BASE/"; s=$(r_sleep 30 90);;
      apiuser)  curl -s -o /dev/null --interface $ip "$BASE/api/Products"; s=$(r_sleep 10 25);;
      mixed)    case $((RANDOM%4)) in
                  0) curl -s -o /dev/null --interface $ip "$BASE/rest/products/search?q=x";;
                  1) curl -s -o /dev/null --interface $ip "$BASE/api/Products";;
                  2) curl -s -o /dev/null --interface $ip "$BASE/rest/products/$((RANDOM%20+1))/reviews";;
                  3) curl -s -o /dev/null --interface $ip "$BASE/";;
                esac; s=$(r_sleep 6 20);;
    esac
    sleep "$s"
  done
}

user 10.16.1.101 shopper  &
user 10.16.1.102 browser  &
user 10.16.1.103 reviewer &
user 10.16.1.104 casual   &
user 10.16.1.105 apiuser  &
user 10.16.1.106 mixed    &
wait
echo "[$(date -u +%FT%TZ)] 종료"
