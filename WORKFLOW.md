# 전체 작업 흐름

```
[외부 VM] → 로그 수집 → [데스크탑: 학습] → git push → [노트북: 튜닝] → git push
```

---

## 1단계 — 로그 수집 (외부 VMware VM → 데스크탑)

외부 VM에 Filebeat 또는 Fluent-bit 설치 후 데스크탑 Logstash로 전송.
로그는 자동으로 `inbox/live/` 에 쌓임.

**데스크탑에서 Logstash 실행:**
```bash
logstash -f deploy/collect/logstash/ml-ingest.conf
```

**외부 VM(nginx 로그)에 Filebeat 설치:**
```bash
# VM에서
sudo cp deploy/collect/filebeat/filebeat-lab-web.yml /etc/filebeat/filebeat.yml
# filebeat.yml 안의 hosts: ["10.16.1.1:5044"] → 데스크탑 외부 IP로 변경
sudo systemctl start filebeat
```

**외부 VM(Wazuh 로그)에 Fluent-bit 설치:**
```bash
# VM에서
sudo cp deploy/collect/fluent-bit/wazuh-archives.conf /etc/fluent-bit/fluent-bit.conf
# conf 안의 host ML_PC_ADDRESS → 데스크탑 외부 IP로 변경
sudo systemctl start fluent-bit
```

인증서가 필요하면 데스크탑에서 먼저:
```bash
bash deploy/collect/make_certs.sh
# 생성된 certs/ 를 각 VM에 scp로 복사
```

---

## 2단계 — 데스크탑에서 학습

`inbox/live/` 에 로그가 쌓이면 학습 실행:

```bash
python ml/ingest.py inbox/live/lab/nginx_shopapi --retrain
```

- `--retrain` : 새 로그로 모델 재학습 + 저장
- 결과 : `REPORT.md` 에 탐지 결과 저장
- 모델 : `models/model_web_v3.1.joblib` 갱신됨

학습 완료 후 깃에 올리기:
```bash
git add models/model_web_v3.1.joblib models/db_model.joblib
git commit -m "실로그 재학습"
git push
```

---

## 3단계 — 노트북에서 튜닝

```bash
git pull   # 데스크탑에서 학습한 최신 모델 받기
```

**핵심 파라미터 (ml/models.py):**

| 파라미터 | 현재값 | 설명 |
|----------|--------|------|
| `contamination` | `0.1` | 이상으로 볼 비율. 오탐 많으면 낮추고, 탐지 못하면 올리기 |
| `n_estimators` | `300` | IsolationForest 트리 수. 높을수록 정확, 느림 |
| `n_neighbors` | LOF 자동 | 이웃 수. 작으면 국소 이상에 예민 |

**튜닝 실행:**
```bash
# contamination 바꿔보기 (0.05 ~ 0.2 사이)
python ml/models.py data/features.csv --methods iforest lof --contamination 0.05
```

오탐이 많으면 contamination 낮추기, 탐지를 못하면 올리기.

튜닝 완료 후 깃에 올리기:
```bash
git add ml/models.py models/
git commit -m "하이퍼파라미터 튜닝"
git push
```

---

## 실시간 자동 판정 (운영)

```bash
python consumer/consumer.py \
  --nginx <로그경로> \
  --model models/model_web_v3.1.joblib \
  --interval 60
```

60초마다 새 로그 읽고 이상 탐지. 결과는 터미널에 출력.

---

## 요약

| 머신 | 역할 | 주요 명령 |
|------|------|-----------|
| 데스크탑 | 로그 수집 + 학습 | `ingest.py --retrain` → `git push` |
| 노트북 | 튜닝 | `git pull` → `models.py --contamination X` → `git push` |
| 어디서든 | 결과 확인 | `REPORT.md` |
