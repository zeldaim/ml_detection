# 깨끗한 환경에서 검증·판정 — 학습한 버전과 같은 Python·라이브러리로 고정 (models/README.md, docs/30)
#   docker build -t ml-detection .
#   docker run --rm ml-detection                                   # 환경 검사 = verification/verify.sh
#   docker run --rm -v "$PWD/inbox:/app/inbox" ml-detection python ml/ingest.py inbox/<폴더> --retrain
FROM python:3.15.1-slim

WORKDIR /app
ENV PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1

# 의존성 먼저 (코드만 바뀌면 이 층은 캐시 재사용)
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
# data/ 는 이미지에 안 넣는다(.dockerignore) — 스크립트가 쓰는 출력 폴더만 만든다.
# Windows 체크아웃(autocrlf)의 CRLF 가 섞여 들어와도 bash 가 돌게 .sh 의 \r 을 지운다 (.gitattributes 와 이중 안전장치)
RUN mkdir -p data inbox && find . -name '*.sh' -exec sed -i 's/\r$//' {} +

CMD ["bash", "verification/verify.sh"]
