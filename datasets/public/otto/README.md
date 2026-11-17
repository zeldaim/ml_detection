# OTTO 세션 샘플 (정상 행동 재현용)

> 용도: `docs/34` — 공공 클릭스트림 세션을 Juice Shop 요청으로 매핑해 정상 출발지를 재현

## 출처 · 라이선스

- **OTTO Recommender Systems Dataset** — Philipp Normann, Sophie Baumeister, Timo Wilm (2023), Kaggle,
  DOI [10.34740/KAGGLE/DSV/4991874](https://doi.org/10.34740/KAGGLE/DSV/4991874) · https://github.com/otto-de/recsys-dataset
- 라이선스: **CC BY 4.0** (데이터. 코드는 MIT) — 저장소 README 의 "The OTTO dataset is released under the CC-BY 4.0 License" 기준.
  Kaggle 메타데이터에는 라이선스 칸이 비어 있다(2026-11-12 확인).
- 변경 사항(CC BY 표기 의무): 원본 `otto-recsys-train.jsonl` 에서 세션 일부만 골라 gzip 으로 다시 썼다. 이벤트 내용은 바꾸지 않았다.

## 파일

| 파일 | 내용 |
|---|---|
| `sample_sessions.jsonl.gz` | 원본과 같은 형식 `{"session","events":[{"aid","ts","type"}]}`, `crc32(session) % 1000 < 2` 인 세션 |
| `sample_stats.json` | 샘플의 분포 요약 (세션당 이벤트 수, 이벤트 간격, 깔때기 비율, ts 단위) |

원본(11.3GB)은 레포에 넣지 않는다(GitHub 파일 100MB 제한). 위치: `D:\data_external\otto\`.
`otto-recsys-train.jsonl.zip` (2,000,011,295 bytes) sha256 `ae11a23676ba29eeeb6e1348b81e353c530da3bc059353cad67247e9616acb2f` (2026-11-12 Kaggle)

샘플: 25,960세션 · 437,597이벤트 (전체 12,899,779세션 중). `ts` 는 밀리초.

## 다시 만들기

```bash
# Kaggle API 토큰 필요 (KAGGLE_API_TOKEN 환경변수, 레포·파일에 저장하지 말 것)
docker run --rm -e KAGGLE_API_TOKEN=... -v "D:/data_external/otto:/out" python:3.15.1-slim \
  bash -c "pip install -q kaggle six && kaggle datasets download otto/recsys-dataset -f otto-recsys-train.jsonl -p /out"
unzip -p D:/data_external/otto/otto-recsys-train.jsonl.zip | python tools/sample_otto.py - --per-mille 2 \
  --out datasets/public/otto/sample_sessions.jsonl.gz --stats datasets/public/otto/sample_stats.json
```
