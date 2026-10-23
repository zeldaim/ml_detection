#!/usr/bin/env python3
"""ML 상위 후보 → LLM 트리아지·설명.  (docs/07 §6 ③④, docs/10 §3-5, labs/01 4단계 구조)

models.py가 이상으로 고른 구간 중 점수 상위 N개를 골라, 그 구간의 피처 값과
"평소 값"(학습 구간 중앙값)을 **숫자 요약으로만** LLM에 보낸다.
경로·User-Agent 같은 원문 문자열은 보내지 않는다 → 로그 조작(프롬프트 인젝션) 위험을 줄임.

LLM은 block_30m(30분 차단) / observe(관찰) / ignore(무시) 중 하나를 추천하고 이유를 쓴다.
최종 조치는 룰·점수가 결정하고 LLM은 의견만 낸다 (docs/03 §3-6, docs/04).

anthropic SDK와 자격증명이 있으면 Claude API를 호출하고(요금 발생), 없거나 --dry-run이면 프롬프트를 출력한다.

사용:
  python ml/explain_llm.py data/detections.csv data/features_alerts.csv --dry-run
  python ml/explain_llm.py data/detections.csv data/features_alerts.csv --method lof --top 5
  python ml/explain_llm.py data/detections.csv data/features_alerts.csv --answer samples/sample_answer_if.csv
"""
import argparse
import csv
import json
import statistics
import sys
from collections import defaultdict

MODEL = "claude-opus-5-5"

SYSTEM = (
    "당신은 SOC 분석 보조자다. 웹·SSH 로그에서 출발지 IP의 5분 구간 행동을 숫자로 요약한 자료를 받는다. "
    "각 후보마다 block_30m(30분 차단), observe(관찰), ignore(무시) 중 하나를 추천하고, "
    "평소 값과 비교해 어떤 수치가 왜 이상한지 한국어로 짧게 설명한다. "
    "자료에 없는 사실은 추측하지 말고, 수치만으로 판단이 어려우면 observe를 고른다."
)

SCHEMA = {
    "type": "object",
    "properties": {
        "decisions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "verdict": {"type": "string", "enum": ["block_30m", "observe", "ignore"]},
                    "pattern": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["id", "verdict", "pattern", "reason"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["decisions"],
    "additionalProperties": False,
}

FEATURE_KO = {
    "alert_count": "알럿 수", "rule_level_max": "최고 룰 레벨", "uniq_rules": "서로 다른 룰 수",
    "auth_fail": "인증 실패 수", "uniq_users": "서로 다른 계정 수",
    "req_count": "요청 수", "uniq_paths": "서로 다른 경로 수", "uniq_objects": "서로 다른 객체 ID 수",
    "err_ratio": "오류 응답 비율", "write_ratio": "쓰기 요청 비율",
    "interval_cv": "요청 간격 변동계수(0에 가까울수록 기계적)",
    "endpoint_entropy": "경로 분포 엔트로피", "ssh_fail": "SSH 실패 수",
}


def load_candidates(det_path, method, top):
    dets = list(csv.DictReader(open(det_path, encoding="utf-8")))
    methods = sorted({d["method"] for d in dets})
    if method not in methods:
        sys.exit(f"detections에 '{method}' 결과가 없음 (있는 것: {', '.join(methods)})")
    agree = defaultdict(list)  # 같은 구간을 이상으로 본 다른 방법들
    for d in dets:
        if d["is_anomaly"] == "1":
            agree[(d["ip"], d["window_start"])].append(d["method"])
    picked = sorted((d for d in dets if d["method"] == method and d["is_anomaly"] == "1"),
                    key=lambda d: -float(d["score"]))[:top]
    train_keys = {(d["ip"], d["window_start"]) for d in dets
                  if d["method"] == method and d["in_train"] == "1"}
    return picked, agree, train_keys, methods


def build_prompt(picked, feats, agree, train_keys, methods, method):
    cols = [c for c in next(iter(feats.values())) if c not in ("ip", "window_start")]
    base_rows = [r for k, r in feats.items() if k in train_keys] or list(feats.values())
    baseline = {c: statistics.median(float(r[c] or 0) for r in base_rows) for c in cols}

    lines = ["평소 값(학습 구간 중앙값):"]
    lines += [f"  {FEATURE_KO.get(c, c)}: {baseline[c]:g}" for c in cols]
    lines.append(f"\n후보 ({method} 이상 점수 상위 {len(picked)}개, 비교한 방법: {', '.join(methods)}):")
    for i, d in enumerate(picked, 1):
        r = feats[(d["ip"], d["window_start"])]
        vals = ", ".join(f"{FEATURE_KO.get(c, c)} {float(r[c] or 0):g}" for c in cols)
        lines.append(f"- id C{i}: 구간 시작 {d['window_start']}, 이상 점수 {float(d['score']):.3f}, "
                     f"이상으로 본 방법 {'/'.join(agree[(d['ip'], d['window_start'])])} | {vals}")
    lines.append("\n각 id에 대해 verdict, pattern(의심 행동 유형 한 줄), reason을 답하라.")
    return "\n".join(lines)


def call_claude(prompt):
    import anthropic

    client = anthropic.Anthropic()  # ANTHROPIC_API_KEY 또는 `ant auth login` 프로필 사용
    resp = client.beta.messages.create(
        model=MODEL,
        max_tokens=4000,
        system=SYSTEM,
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",  # 안전 분류기가 거절하면 서버가 권장 모델로 재시도
        output_config={"effort": "low", "format": {"type": "json_schema", "schema": SCHEMA}},
        messages=[{"role": "user", "content": prompt}],
    )
    if resp.stop_reason == "refusal":
        sys.exit("모델이 요청을 거절했습니다(stop_reason=refusal).")
    text = next(b.text for b in resp.content if b.type == "text")
    return json.loads(text)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="ML 상위 후보를 LLM으로 트리아지·설명")
    ap.add_argument("detections", help="ml/models.py 출력 CSV")
    ap.add_argument("features", help="ml/features.py 출력 CSV (detections와 같은 것)")
    ap.add_argument("--method", default="iforest", help="후보를 고를 방법 (기본 iforest)")
    ap.add_argument("--top", type=int, default=6, help="LLM에 보낼 후보 수")
    ap.add_argument("--answer", help="정답지 CSV — 결과 옆에 정답 표시 (IP형·시간 구간형 모두)")
    ap.add_argument("--dry-run", action="store_true", help="API를 부르지 않고 프롬프트만 출력")
    args = ap.parse_args()

    feats = {(r["ip"], r["window_start"]): r
             for r in csv.DictReader(open(args.features, encoding="utf-8"))}
    picked, agree, train_keys, methods = load_candidates(args.detections, args.method, args.top)
    if not picked:
        sys.exit(f"{args.method}가 이상으로 본 구간이 없음")
    missing = [d for d in picked if (d["ip"], d["window_start"]) not in feats]
    if missing:
        sys.exit("detections와 features가 맞지 않음 — 같은 피처 CSV를 넣었는지 확인")
    prompt = build_prompt(picked, feats, agree, train_keys, methods, args.method)
    ids = {f"C{i}": d for i, d in enumerate(picked, 1)}  # IP는 LLM에 보내지 않고 여기서만 매핑

    def print_prompt(why):
        print(why + " → API 대신 프롬프트를 출력합니다.\n")
        print("=== 시스템 지시 ===\n" + SYSTEM + "\n\n=== 사용자 메시지 ===\n" + prompt)
        print("\n=== id ↔ IP ===")
        for k, d in ids.items():
            print(f"{k}: {d['ip']}  {d['window_start']}")

    if args.dry_run:
        print_prompt("--dry-run")
        return
    try:
        import anthropic
    except ImportError:
        print_prompt("anthropic 미설치 (설치: pip install anthropic)")
        return
    try:
        out = call_claude(prompt)
    except anthropic.AuthenticationError:
        print_prompt("API 키가 올바르지 않음 (ANTHROPIC_API_KEY 확인)")
        return
    except TypeError as e:
        # 자격증명이 하나도 없으면 SDK가 요청 전에 TypeError를 낸다
        if "authentication" not in str(e).lower():
            raise
        print_prompt("API 자격증명 없음 (ANTHROPIC_API_KEY 설정 또는 `ant auth login`)")
        return

    truth = {}
    if args.answer:
        for r in csv.DictReader(open(args.answer, encoding="utf-8")):
            ip = r.get("ip") or r.get("src")
            if r.get("label", "attack") == "attack":
                truth[ip] = r.get("type", "attack")
    print(f"[후보 방법: {args.method}, {len(picked)}개]\n")
    for dec in out["decisions"]:
        d = ids.get(dec["id"])
        if not d:
            continue
        mark = f"  ← 정답: {truth[d['ip']]}" if d["ip"] in truth else ("  ← 정답: 정상" if truth else "")
        print(f"{d['ip']:<16} {d['window_start']}  {dec['verdict']:<10} [{dec['pattern']}] "
              f"{dec['reason']}{mark}")


if __name__ == "__main__":
    main()
