# datasets/ — 재현용 보존 데이터 (repo에 포함)

> `data/`는 .gitignore(대용량·임시)지만, **결론의 근거가 된 정본 데이터는 여기에 보존**해 repo만으로 재현 가능하게 한다.
> (이전엔 실제 로그가 로컬에만 있어 재현 불가·유실 위험이었음 — 리뷰 #3 수정.)

## real_web/ — 웹 정본(canonical) 실제 데이터셋
전체 실제 로그를 **IP 역할로** 한 번에 정리한 검증 정본(= `docs/21` §L).
| 파일 | 내용 |
|---|---|
| `real_canon_features.csv` | IP×5분 피처 246구간(정상 214 + 9 공격종류) |
| `real_canon_answer.csv` | IP형 정답지(공격 전용 IP) |
| `real_canon_access.log.gz` | 원본 nginx 로그(gzip) — 피처 재추출용 |
| `nat_lab_access.log` | NAT 실측(사용자키 vs IP키, `docs/25` §5-2). user 필드 포함 |

재현:
```bash
zcat datasets/real_web/real_canon_access.log.gz > /tmp/c.log
python ml/features.py --nginx /tmp/c.log --out /tmp/c.csv
python ml/relative_features.py /tmp/c.csv --mode self --cols req_count max_req_1min --out /tmp/c_rel.csv
python ml/supervised.py /tmp/c_rel.csv --answer datasets/real_web/real_canon_answer.csv --group-by type --contamination 0.05
```

## real_db/ — DB 아크 데이터셋
| 파일 | 내용 |
|---|---|
| `db_arc_features.csv` · `db_arc_answer.csv` | DB 피처 + 정답지(scrape·bola·sqli + 하드네거티브) |
| `db_arc_general.log.gz` | 원본 general log(gzip) |

## 데이터셋 역할 구분 (리뷰 #1)
- **검증 정본 = `datasets/real_web/real_canon_*`** — 결론·모델 평가는 이걸로. (중복 없음, IP역할 깔끔)
- **플라이휠 누적 ledger = `data/dataset_web.csv`**(gitignore) — `accumulate.py`로 조각조각 append한 **흐름 기록**. 시간상 겹침 가능, **최종 지표 산출엔 쓰지 않음**. 플라이휠 축적 데모용.
- 합성 데이터는 생성기 seed로 재현(`tools/gen_synth_log.py --seed 7`, `tools/gen_db_arc.py --seed 5`).
