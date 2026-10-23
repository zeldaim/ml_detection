#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""판다스 실습 — 내 보안 ML 프로젝트 데이터로 배우는 pandas 한 바퀴.

책(두잇 판다스 / 파이썬 머신러닝 완벽 가이드)을 보기 전/후에 돌려보는 복습 교재.
남의 예제가 아니라 '내가 만든 features.csv'로 배우므로 바로 이해된다.

실행:  python learn/pandas_tutorial.py      (저장소 루트에서, PYTHONUTF8=1 권장)
순서:  위에서 아래로. 각 섹션은 'pandas 기능 → 내 프로젝트의 의미'로 짝지어 설명한다.
"""
import os
import pandas as pd

pd.set_option("display.width", 130)
pd.set_option("display.max_columns", 30)
pd.set_option("display.unicode.east_asian_width", True)  # 한글 컬럼 정렬

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
FEAT = os.path.join(ROOT, "data", "features_combined.csv")   # 웹 피처 (정상+공격)
ANS = os.path.join(ROOT, "data", "answer.csv")               # 정답지


def title(n, s):
    print("\n" + "=" * 72 + f"\n[{n}] {s}\n" + "=" * 72)


# ──────────────────────────────────────────────────────────────────────
title(1, "읽기 — CSV를 DataFrame(표)으로")
# pandas의 기본 단위는 DataFrame(2차원 표)과 Series(1차원 열).
df = pd.read_csv(FEAT)
print("shape(행,열):", df.shape)         # (구간 수, 피처 수)
print("columns:", list(df.columns))
print("dtypes(각 열의 자료형):")
print(df.dtypes)                          # 숫자(int/float) vs 문자(object) 구분
print("\nhead() 처음 3줄:")
print(df.head(3))
# 💡 내 프로젝트: 한 줄 = 'IP 하나의 5분 구간', 열 = features.py가 뽑은 피처.


# ──────────────────────────────────────────────────────────────────────
title(2, "열/행 고르기 — [], loc, iloc")
print("한 열(Series):", df["req_count"].head(3).tolist())
print("\n여러 열(DataFrame):")
print(df[["ip", "req_count", "uniq_objects"]].head(3))
print("\nloc[행이름, 열이름] — 라벨 기반:")
print(df.loc[0:2, ["ip", "max_req_1min"]])
print("\niloc[행번호, 열번호] — 위치 기반:")
print(df.iloc[0:2, 0:3])
# 💡 [] = 열 선택, loc/iloc = 행+열. 헷갈리면 loc(이름)·iloc(번호)로 기억.


# ──────────────────────────────────────────────────────────────────────
title(3, "필터 — 조건으로 행 고르기 (boolean indexing)")
busy = df[df["max_req_1min"] >= 100]      # 1분에 100번 넘은 구간
print("1분 100회 이상 구간:")
print(busy[["ip", "window_start", "max_req_1min", "err_ratio"]])
print("\n조건 두 개 결합(&, | 와 괄호 필수):")
bola = df[(df["uniq_objects"] >= 10) & (df["err_ratio"] < 0.5)]
print(bola[["ip", "uniq_objects", "err_ratio"]])
# 💡 and/or 아니라 &/| 쓰고, 각 조건을 () 로 감싼다 — pandas 규칙.


# ──────────────────────────────────────────────────────────────────────
title(4, "정렬 — sort_values")
print("uniq_objects 큰 순 상위 5 (BOLA 의심):")
print(df.sort_values("uniq_objects", ascending=False)
        .head(5)[["ip", "window_start", "uniq_objects", "max_req_1min"]])


# ──────────────────────────────────────────────────────────────────────
title(5, "groupby + agg — 핵심! IP별로 묶어 요약 (features.py가 하는 일)")
# groupby('ip') → IP마다 그룹 → agg로 그룹별 통계
per_ip = df.groupby("ip").agg(
    구간수=("window_start", "count"),
    총요청=("req_count", "sum"),
    최대분당=("max_req_1min", "max"),
    최대객체=("uniq_objects", "max"),
    평균에러=("err_ratio", "mean"),
).round(3)
print(per_ip)
# 💡 이 한 줄이 '로그 → IP 단위 피처'의 본질. 공격 IP가 숫자로 튄다.


# ──────────────────────────────────────────────────────────────────────
title(6, "새 열 만들기 — 계산·apply")
# 벡터 연산: 열 전체에 한 번에 적용 (빠름)
per_ip["요청당객체"] = (per_ip["최대객체"] / per_ip["총요청"]).round(3)
# apply + 함수: 복잡한 규칙
per_ip["판정"] = per_ip["최대분당"].apply(lambda x: "의심" if x >= 100 else "보통")
print(per_ip[["총요청", "최대분당", "최대객체", "요청당객체", "판정"]])


# ──────────────────────────────────────────────────────────────────────
title(7, "merge(join) — 두 표 합치기 (옵션 A 웹-DB 상관의 원리)")
# 정답지(IP→공격여부)를 피처 요약에 붙인다 = SQL JOIN과 같은 개념
ans = pd.read_csv(ANS)
label = ans[["src", "type"]].rename(columns={"src": "ip", "type": "공격종류"})
merged = per_ip.reset_index().merge(label, on="ip", how="left")  # left join
merged["공격종류"] = merged["공격종류"].fillna("정상")            # 안 붙은 건 정상
print(merged[["ip", "최대분당", "최대객체", "공격종류"]])
# 💡 how='left' = 왼쪽(per_ip) 다 남기고 오른쪽(label) 매칭되는 것만 붙임.
#    매칭 안 되면 NaN → fillna로 '정상' 채움. DB·웹 로그 합칠 때 똑같이 쓴다.


# ──────────────────────────────────────────────────────────────────────
title(8, "결측치·집계 — fillna, value_counts, describe")
print("공격종류별 개수 (value_counts):")
print(merged["공격종류"].value_counts())
print("\n종류별 평균 피처 (groupby + mean):")
print(merged.groupby("공격종류")[["최대분당", "최대객체"]].mean().round(1))
# 💡 '종류별로 피처가 어떻게 다른가'가 한눈에 — 이게 ML이 학습하는 패턴.


# ──────────────────────────────────────────────────────────────────────
title(9, "실전 연결 — P/R/F1을 pandas로 직접 (evaluate.py의 개념)")
true_attack = set(ans["src"])
m = per_ip.reset_index()
m["예측"] = m["최대객체"] >= 10          # 규칙 예: 객체 10개 이상이면 공격
m["실제"] = m["ip"].isin(true_attack)
TP = ((m["예측"]) & (m["실제"])).sum()
FP = ((m["예측"]) & (~m["실제"])).sum()
FN = ((~m["예측"]) & (m["실제"])).sum()
TN = ((~m["예측"]) & (~m["실제"])).sum()
P = TP / (TP + FP) if TP + FP else 0
R = TP / (TP + FN) if TP + FN else 0
F1 = 2 * P * R / (P + R) if P + R else 0
print(f"규칙: 최대 uniq_objects >= 10 이면 공격")
print(f"TP={TP} FP={FP} FN={FN} TN={TN}")
print(f"Precision={P:.2f}  Recall={R:.2f}  F1={F1:.2f}")
print("→ '분당요청>=100' 규칙과 비교해보라: 그건 빠른 공격을, 이건 BOLA를 잡는다.")
print("  피처마다 잡는 공격이 다르다 → 그래서 ML이 여러 피처를 한꺼번에 본다.")


# ──────────────────────────────────────────────────────────────────────
title(10, "저장 — to_csv")
out = os.path.join(ROOT, "data", "per_ip_summary.csv")
merged.to_csv(out, index=False, encoding="utf-8")
print("저장:", out)

print("\n" + "=" * 72)
print("끝. 직접 바꿔볼 것 (책 보기 전 손풀기):")
print(" 1) STEP 9의 규칙을 '최대분당 >= 50' 으로 바꿔 P/R/F1 변화 보기")
print(" 2) STEP 5 agg에 '평균interval_cv=(\"interval_cv\",\"mean\")' 추가해보기")
print(" 3) data/features_db.csv 로 FEAT 경로 바꿔 DB 피처도 같은 흐름으로 보기")
print("=" * 72)
