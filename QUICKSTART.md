# 새 PC에서 바로 실행하기

## 1. 받기

```bash
git clone https://github.com/zeldaim/ml_detection.git
cd ml_detection
```

## 2. 설치

```bash
pip install scikit-learn pandas
```

Python만 있으면 끝.

## 3. 로그 넣고 실행

```bash
python ml/ingest.py inbox/live/lab/nginx_shopapi --retrain
```

- `inbox/` 폴더에 로그 파일 넣으면 자동으로 분석
- `--retrain` 붙이면 새 로그로 재학습까지 자동
- 결과는 같은 폴더 `REPORT.md` 에 저장됨

## 실시간 자동 판정 (백그라운드)

```bash
python consumer/consumer.py --nginx <로그경로> --model models/model_web_v3.1.joblib --interval 60
```

60초마다 새 로그를 읽고 이상 탐지.

## 폴더 구조 (필수만)

```
ml_detection/
├── ml/                      ← 핵심 코드
├── models/
│   ├── model_web_v3.1.joblib  ← 웹 탐지 모델
│   └── db_model.joblib        ← DB 탐지 모델
├── consumer/                ← 자동 반복 판정
├── edge/                    ← 분산 방식
├── inbox/                   ← 로그 넣는 곳
└── requirements.txt
```

## 로그 수집 (외부 VM → 이 PC)

실시간 수집 설정은 `deploy/collect/` 참고.
- Filebeat → nginx 로그 수집 (`filebeat-lab-web.yml`)
- Fluent-bit → Wazuh 로그 수집 (`wazuh-archives.conf`)
- Logstash → 받아서 `inbox/live/` 에 저장 (`ml-ingest.conf`)

자세한 내용은 `docs/29` 참고.
