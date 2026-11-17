#!/usr/bin/env bash
# 타겟에서 실행. '빠르지만 합법적인 클라이언트' = 하드 네거티브(정상인데 harvest 공격과 속도가 겹침).
# 단 harvest 와 달리 '여러 경로'를 돈다(모바일앱/정상 봇처럼) → endpoint_entropy 높음.
# 목적: #2(경로 다양성 피처)가 '속도로 못 가르는' 이 케이스를 내용으로 가르는지 테스트할 고정 픽스처.
set -u
BASE="http://10.16.1.10"
DUR="${1:-900}"   # 15분
end=$(( $(date +%s) + DUR ))
echo "[$(date -u +%FT%TZ)] 빠른 합법 클라이언트 ${DUR}s"

# .131 모바일앱(빠름, 다경로), .132 허가된 가격수집봇(빠름, 다경로)
mobile(){ # 빠르지만 검색어·상품·리뷰·카테고리로 경로 다양
  local ip=$1
  while [ "$(date +%s)" -lt "$end" ]; do
    case $((RANDOM%5)) in
      0) curl -s -o /dev/null --interface $ip "$BASE/rest/products/search?q=$(shuf -e apple juice cola milk tea water -n1)";;
      1) curl -s -o /dev/null --interface $ip "$BASE/rest/products/$((RANDOM%40+1))/reviews";;
      2) curl -s -o /dev/null --interface $ip "$BASE/api/Products";;
      3) curl -s -o /dev/null --interface $ip "$BASE/api/Quantitys";;
      4) curl -s -o /dev/null --interface $ip "$BASE/rest/products/search?q=";;
    esac
    sleep "$(awk 'BEGIN{srand(); print 1+rand()*2}')"   # 1~3초 (빠름, harvest 수준)
  done
}

ip addr add 10.16.1.131/24 dev $(ip route|awk '/default/{print $5;exit}') 2>/dev/null
ip addr add 10.16.1.132/24 dev $(ip route|awk '/default/{print $5;exit}') 2>/dev/null
mobile 10.16.1.131 &
mobile 10.16.1.132 &
wait
echo "[$(date -u +%FT%TZ)] 종료"
