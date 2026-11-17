# human_collect — 실제 사람 정상 트래픽 모으기

> 왜: docs/35 결론 — 재생 정상이 도움이 되는지는 **실제 사람 정상으로 평가해야** 판정된다. 설계·평가 계획은 `docs/36`.
> 누가: **직접 실행**한다(참가자 모집·서버 켜고 끄기·기록표·결과 판단). 도구는 준비됨.

## 구성

| 파일 | 역할 |
|---|---|
| `docker-compose.yml` | Juice Shop(재생 실험과 같은 이미지) + nginx(기본 인증·로그) + 임시 공개 터널(선택) |
| `nginx.conf` | **실제 IP 를 기록하지 않음** — 첫 칸에 참가자 ID(p01 …)만 |
| `make_users.sh` | 참가자 계정 만들기 → `htpasswd`, `participants_secret.csv`(비밀번호, 레포 제외) |
| `참가자_안내문.md` | 참가자에게 보낼 한 장 |
| `참가자_기록표.csv` | 참가자·회차·시작/끝 시각·기기 — **직접 채운다** |
| `../tools/human_log_to_combined.py` | 수집 로그 → features.py 형식 (p01 → 가상 IP 10.40.0.1) |

## 순서 (한 줄씩, Git Bash 에서)

```bash
cd /d/ml_detection/human_collect

# 1) 참가자 계정 (예: 10명). 비밀번호는 participants_secret.csv 에서 한 명씩 따로 전달
bash make_users.sh 10

# 2) 내 PC 에서 먼저 확인 — 브라우저로 http://127.0.0.1:8080 → 로그인 창에 p01 / 비밀번호
docker compose up -d

# 3) 외부 참가자용 임시 주소 열기 (수집하는 동안만!)
docker compose --profile tunnel up -d
docker compose logs tunnel | grep trycloudflare      # → https://xxxx.trycloudflare.com 을 참가자에게
#   주소는 켤 때마다 바뀐다. 기본 인증이 앞에 있어서 주소가 새도 계정 없이는 못 들어온다.

# 4) 수집 끝나면 바로 닫기
docker compose --profile tunnel down

# 5) 변환 → 피처 (저장소 루트에서)
cd ..
python tools/human_log_to_combined.py human_collect/logs/access.log --out data/human_s1.log
```

예상 출력(5): `NNN줄 → data/human_s1.log` 다음에 참가자별 줄 수, 마지막에 `뺀 줄: {...}`(기본 인증 실패 등).

## 지킬 것

- **수집할 때만 터널을 연다.** Juice Shop 은 일부러 취약한 앱이다. 끝나면 4) 를 꼭 실행.
- `participants_secret.csv`, `htpasswd`, `logs/` 는 `.gitignore` — 레포에 올리지 않는다(원본 로그엔 브라우저 정보가 남는다). 변환한 `data/human_*.log` 는 IP 없이 참가자 번호만 있으므로 검토 후 커밋.
- 참가자가 삭제를 원하면: 해당 pNN 줄을 원본·변환본에서 지우고 다시 변환.
- 같은 사람이 다른 날 다시 하면 **같은 아이디**로. 기록표에 회차(session) 2 로 적는다.
