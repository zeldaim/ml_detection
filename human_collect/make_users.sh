#!/usr/bin/env bash
# 참가자 기본 인증 계정 만들기: p01 … pNN, 각자 무작위 비밀번호.
#   bash make_users.sh 10
# 결과: htpasswd (nginx 용, 해시만) + participants_secret.csv (아이디·비밀번호 — 참가자에게 따로 전달, 레포에 올리지 않음)
set -euo pipefail
cd "$(dirname "$0")"
N="${1:-10}"
: > htpasswd
echo "id,password" > participants_secret.csv
for i in $(seq 1 "$N"); do
  id="$(printf 'p%02d' "$i")"
  pw="$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 12)"
  # htpasswd 는 Docker 의 httpd 이미지로 만든다 (PC 에 따로 설치 불필요)
  MSYS_NO_PATHCONV=1 docker run --rm httpd:2.4-alpine htpasswd -nbB "$id" "$pw" | head -1 >> htpasswd
  echo "$id,$pw" >> participants_secret.csv
done
echo "참가자 $N명 → htpasswd, participants_secret.csv (비밀번호 파일은 레포에 올리지 말 것)"
