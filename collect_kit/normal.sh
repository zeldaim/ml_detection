#!/usr/bin/env bash
# 정상 트래픽(기준선). 공격 '전에' 돌린다. 이 구간엔 절대 공격 금지(기준 오염).
# Juice Shop 정상 동선: 상품 검색/조회/로그인/내 장바구니 — 랜덤 간격(사람처럼).
#
#   사용: ./normal.sh [분=20]
#   TARGET, EMAIL, PASS 는 환경변수로 (아래 기본값 수정)
set -eu
TARGET="${TARGET:-http://10.16.1.10}"
EMAIL="${EMAIL:-TODO_me@juice.sh}"       # 미리 가입한 정상 계정
PASS="${PASS:-TODO_password}"
MIN="${1:-20}"

echo "정상 트래픽 ${MIN}분 → $TARGET  (시작 UTC: $(date -u +%FT%TZ))"
# 로그인해서 내 토큰(내 장바구니 조회에 사용)
TOKEN=$(curl -s -X POST "$TARGET/rest/user/login" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

END=$(( $(date +%s) + MIN*60 ))
while [ "$(date +%s)" -lt "$END" ]; do
  case $((RANDOM % 5)) in
    0) curl -s -o /dev/null "$TARGET/rest/products/search?q=apple" ;;
    1) curl -s -o /dev/null "$TARGET/api/Products" ;;
    2) curl -s -o /dev/null "$TARGET/rest/products/1/reviews" ;;
    3) curl -s -o /dev/null "$TARGET/" ;;
    4) [ -n "$TOKEN" ] && curl -s -o /dev/null "$TARGET/rest/basket/1" -H "Authorization: Bearer $TOKEN" ;;
  esac
  sleep "$(awk 'BEGIN{srand(); print 1+rand()*6}')"   # 1~7초 랜덤
done
echo "정상 끝 (끝 UTC: $(date -u +%FT%TZ)) ← 이 시각을 --train-until 로 쓴다"
