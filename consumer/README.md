# consumer/ — ML 소비자 (단순 버전, 엣지 없음)

수동으로 하던 `features.py → predict.py`를 **반복 실행으로 자동화**한 것. 한 호스트(분석 PC)에서 돈다.

```
로그 파일 ─▶ consumer.py (주기 반복) ─▶ 저장모델(.joblib) 판정 ─▶ 🚨 경보
            원본 로그 전체를 이 프로세스가 읽음
```

- **엣지 추출 안 함** — 원본 로그 전체를 소비자가 직접 읽는다. (호스트에서 피처만 뽑아 보내는 방식은 `../edge/`)
- 이미 끝난 구간만 판정, 같은 (ip, 구간)은 한 번만 경보(중복 방지).

## 사용

```bash
# 한 번만 (확인용)
python consumer/consumer.py --nginx data/attack_access.log --model models/model.joblib --once

# 상주(60초마다 새 로그 판정)
python consumer/consumer.py --nginx /var/log/nginx/juiceshop_access.log \
    --model models/model.joblib --interval 60 --alert-out data/alerts.csv
```

출력 예(느린 BOLA가 LOF로 잡힘 — 자동 파이프라인에서도 재현):
```
🚨 2026-10-23T08:20:00Z 10.16.1.214  이상(LOF) · RF분류=bola
```

## 언제 이걸 쓰나

- 로그가 한 곳(분석 PC)에 모여 있고, 원본을 그대로 읽어도 될 때
- 가장 단순한 자동화. 호스트가 여러 대거나 원본을 내보내기 싫으면 `../edge/`
