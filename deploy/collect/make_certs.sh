#!/usr/bin/env bash
# 수집용 TLS 인증서 만들기 — 우리 CA 하나 + ML PC 서버 인증서 + 보내는 쪽마다 클라이언트 인증서.  (docs/29 §4-1)
# Git Bash(Windows, openssl 포함) 또는 Linux 에서.
#
#   bash deploy/collect/make_certs.sh server 10.16.1.1 [추가 IP/이름 …]   # ML PC (처음 한 번)
#   bash deploy/collect/make_certs.sh client web01                         # 보내는 쪽마다
#
# 결과: deploy/collect/certs/  — .gitignore (절대 커밋 금지).
#   보내는 쪽에 줄 것: ca.crt + <이름>.crt + <이름>.key  (그 3개만. ca.key 는 ML PC 밖으로 안 나감)
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs && cd certs
export MSYS_NO_PATHCONV=1   # Git Bash 가 -subj "/CN=…" 를 경로로 바꾸는 것 방지

# openssl 은 진행 표시를 stderr 로 내므로 평소엔 숨기고, 실패할 때만 보여준다
run() { "$@" 2>.openssl.err || { cat .openssl.err >&2; rm -f .openssl.err; exit 1; }; rm -f .openssl.err; }
# 확장 정보는 임시 파일로 — Windows openssl 은 <(...) 의 /dev/fd 를 못 읽어 조용히 실패했다
ext() { printf '%s\n' "$@" > .ext.cnf; }
# 말단 인증서 공통 확장 — 엄격한 검증기(Python 3.13+ 등)는 이게 없으면 거부한다
LEAF=("basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature,keyEncipherment"
      "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid,issuer")

if [ ! -f ca.key ]; then
  run openssl req -x509 -newkey rsa:3072 -nodes -days 825 -keyout ca.key -out ca.crt -subj "/CN=ml-detection-collect-CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
  echo "CA 생성: certs/ca.crt"
fi

kind=${1:?server 또는 client}; shift
case "$kind" in
  server)
    [ $# -ge 1 ] || { echo "ML PC 주소(IP/이름)를 하나 이상"; exit 1; }
    san=""
    for a in "$@"; do
      if [[ "$a" =~ ^[0-9.]+$ ]]; then san+="IP:$a,"; else san+="DNS:$a,"; fi
    done
    run openssl req -newkey rsa:3072 -nodes -keyout server.key -out server.csr -subj "/CN=$1"
    ext "subjectAltName=${san%,}" "extendedKeyUsage=serverAuth" "${LEAF[@]}"
    run openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 -out server.crt -extfile .ext.cnf
    run openssl pkcs8 -topk8 -nocrypt -in server.key -out server.pkcs8.key      # Logstash beats 입력용
    rm -f server.csr .ext.cnf
    echo "서버 인증서: certs/server.crt (SAN ${san%,})"
    ;;
  client)
    name=${1:?클라이언트 이름 (예: web01, wazuh-teamb)}
    [[ "$name" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo "이름은 영문·숫자·_.- 만"; exit 1; }
    run openssl req -newkey rsa:3072 -nodes -keyout "$name.key" -out "$name.csr" -subj "/CN=$name"
    ext "extendedKeyUsage=clientAuth" "${LEAF[@]}"
    run openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 -out "$name.crt" -extfile .ext.cnf
    rm -f "$name.csr" .ext.cnf
    echo "클라이언트 인증서: certs/$name.crt — 보낼 것: ca.crt, $name.crt, $name.key"
    ;;
  *) echo "server 또는 client"; exit 1 ;;
esac
