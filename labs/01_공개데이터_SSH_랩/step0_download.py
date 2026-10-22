#!/usr/bin/env python3
"""0단계: 공개 SSH 로그(Loghub OpenSSH 2k 샘플) 내려받기.

출처: LogPAI Loghub (https://github.com/logpai/loghub) — 실제 서버의 sshd 로그 2,000줄.
이용 조건은 Loghub 저장소 안내를 따른다. 원본은 저장소에 올리지 않는다(data/는 .gitignore).
"""
import pathlib
import urllib.request

URL = "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log"
OUT = pathlib.Path(__file__).parent / "data" / "OpenSSH_2k.log"


def main():
    OUT.parent.mkdir(exist_ok=True)
    if OUT.exists():
        print(f"이미 있음: {OUT}")
        return
    print(f"내려받는 중: {URL}")
    urllib.request.urlretrieve(URL, OUT)
    lines = OUT.read_text(encoding="utf-8", errors="replace").splitlines()
    print(f"완료: {OUT} ({len(lines)}줄)")
    print("첫 3줄:")
    for line in lines[:3]:
        print("  " + line)


if __name__ == "__main__":
    main()
