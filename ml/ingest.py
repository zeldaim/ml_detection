#!/usr/bin/env python3
"""폴더에 넣은 로그를 알아서 알아보고 → 피처 → 판정 → 보고서까지.  (inbox/README.md)

다른 인프라의 로그를 받아 실험할 때의 단일 입구. 파일 이름이 아니라 **내용**을 보고 종류를 정한다:
  nginx 액세스 로그(combined)      → 웹 피처   (ml/features.py --nginx)
  Wazuh archives.json             → 웹 피처   (ml/features.py --archives)
  MySQL general log               → DB 피처   (edge/db_features.py)
  Prometheus query_range JSON     → 호스트 피처 (edge/host_metrics.py --matrix)
  node_exporter 스냅샷 폴더(*.prom) → 호스트 피처 (edge/host_metrics.py --snapshots)
  이미 뽑은 피처 CSV(ip,window_start,…) → 피처셋(web/db/host)을 열로 알아보고 그대로 사용
  정답지 CSV(attack_id,src,start,end,type 또는 ip,label,type) → 있으면 채점

두 가지 모드:
  (기본) 판정   : 저장된 모델(models/)로 판정만. "우리 모델이 이 인프라에서도 통하나?"
  --retrain     : 이 인프라의 정상으로 다시 학습 → 판정. 다른 환경엔 이게 정석(MODEL_CARD §7).
                  정답지가 있으면 정상 시간순 앞 70%로 학습한 모델로 나머지를 채점(처음 보는 데이터),
                  없으면 --baseline-until 이전을 평소로 학습(없으면 전체를 평소로 가정 — 경고).

각 단계는 기존 스크립트를 그대로 호출하고, **실제로 돌린 명령을 화면과 out/REPORT.md 에 남긴다**
(손으로 똑같이 따라 칠 수 있게). 결과는 전부 <폴더>/out/ 에 쌓인다.

사용:
  python ml/ingest.py inbox/company_a
  python ml/ingest.py inbox/company_a --retrain
  python ml/ingest.py inbox/company_a --retrain --baseline-until 2026-11-01T00:00:00Z
설정(선택): <폴더>/meta.json  {"owned_paths": ["/api/orders/{id}"], "window": 5, "contamination": 0.05}
"""
import argparse
import csv
import glob
import gzip
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from evaluate import load_answer  # noqa: E402
from feature_spec import columns  # noqa: E402
from supervised import label_windows  # noqa: E402

MODELS = {"web": "models/model_web_v3.1.joblib", "db": "models/db_model.joblib", "host": None}
NGINX_RE = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "[A-Z]+ \S+')
GENERAL_RE = re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]+Z?\s+\d+\s+(Connect|Query|Quit|Execute|Prepare|Init DB)\b")
REL_COLS = ["req_count", "max_req_1min"]
LAYER_KO = {"web": "웹(API 행위)", "db": "DB(쿼리)", "host": "호스트 지표"}


def show(path):
    """화면·보고서용 경로: 저장소 안이면 상대경로, 밖(다른 드라이브 포함)이면 절대경로. 구분자는 /."""
    path = os.path.abspath(path)
    try:
        rel = os.path.relpath(path, ROOT)
        path = path if rel.startswith("..") else rel
    except ValueError:      # Windows: 다른 드라이브(C: vs D:)면 상대경로 계산 불가
        pass
    return path.replace(os.sep, "/")


# ── 1. 파일 알아보기 ────────────────────────────────────────────────────────────
def head_text(path, n_bytes=4096):
    opener = gzip.open if path.endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            return f.read(n_bytes)
    except (OSError, EOFError):
        return ""


def sniff(path):
    """파일 하나 → (종류, 설명). 내용 기준."""
    text = head_text(path)
    lines = [ln for ln in text.splitlines() if ln.strip()][:20]
    if not lines:
        return "unknown", "빈 파일/읽기 실패"
    first = lines[0]
    if path.endswith((".csv", ".csv.gz")):
        header = set(next(csv.reader([first])))
        if {"attack_id", "src", "start", "end"} <= header or {"ip", "label"} <= header:
            return "answer", "정답지"
        if {"ip", "window_start"} <= header:
            for layer, need in (("db", columns("db_v1")), ("host", columns("host_v1")),
                                ("web", [c for c in columns("web_v1") if not c.startswith("rel_")])):
                if set(need) <= header:
                    return f"features_{layer}", f"{LAYER_KO[layer]} 피처 CSV(이미 추출됨)"
        return "unknown", "CSV 지만 정답지/피처 형식 아님"
    if '"resultType"' in text:
        return "matrix", "Prometheus query_range JSON"
    if first.lstrip().startswith("{"):
        try:
            obj = json.loads(first)
        except json.JSONDecodeError:
            obj = {}
        if "alerts" in os.path.basename(path).lower():
            return "unknown", "Wazuh alerts.json — 룰에 걸린 것만이라 학습엔 archives 를 쓴다(docs/08 §2-4)"
        if "full_log" in obj:
            return "archives", "Wazuh archives.json"
        return "unknown", "JSON 이지만 archives/Prometheus 형식 아님"
    if sum(bool(NGINX_RE.match(ln)) for ln in lines) >= len(lines) * 0.6:
        return "nginx", "nginx 액세스 로그(combined)"
    if any(GENERAL_RE.match(ln) for ln in lines):
        return "general", "MySQL general log"
    return "unknown", "형식을 모름"


def discover(folder):
    found, notes = [], []
    prom_roots = set()
    for path in sorted(glob.glob(os.path.join(folder, "**", "*"), recursive=True)):
        rel = os.path.relpath(path, folder)
        if rel.split(os.sep)[0] == "out" or os.path.isdir(path):
            continue
        name = os.path.basename(path)
        if name in ("meta.json", "README.md") or name.startswith("."):
            continue
        if name.endswith(".prom"):          # node_exporter 스냅샷: <root>/<host>/<epoch>.prom
            prom_roots.add(os.path.dirname(os.path.dirname(path)))
            continue
        kind, desc = sniff(path)
        (found if kind != "unknown" else notes).append((kind, path, desc))
    for root in sorted(prom_roots):
        found.append(("snapshots", root, "node_exporter 스냅샷 폴더"))
    return found, notes


# ── 2. 실행·기록 ────────────────────────────────────────────────────────────────
class Runner:
    def __init__(self, out):
        self.out, self.log = out, []
        os.makedirs(os.path.join(out, "logs"), exist_ok=True)

    def step(self, title, args):
        """기존 스크립트를 그대로 호출. 명령을 보여주고, 출력은 logs/ 에 저장."""
        shown = "python " + " ".join(self._rel(a) for a in args)
        print(f"\n▶ {title}\n  $ {shown}")
        r = subprocess.run([sys.executable] + args, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", env={**os.environ, "PYTHONUTF8": "1"})
        logname = f"{len(self.log) + 1:02d}_{os.path.basename(args[0]).replace('.py', '')}.txt"
        with open(os.path.join(self.out, "logs", logname), "w", encoding="utf-8") as f:
            f.write(r.stdout + ("\n[stderr]\n" + r.stderr if r.stderr.strip() else ""))
        last = [ln for ln in r.stdout.splitlines() if ln.strip()][-1:] or ["(출력 없음)"]
        ok = r.returncode == 0
        print(f"  {'✓' if ok else '✗ 실패'} {last[0][:160]}")
        if not ok:
            err = [ln for ln in r.stderr.splitlines() if ln.strip()][-1:] or [""]
            print(f"    {err[0][:200]}  (전체: out/logs/{logname})")
        self.log.append((title, shown, ok, logname))
        return ok

    @staticmethod
    def _rel(a):
        a = str(a)
        if os.path.isabs(a):
            a = show(a)
        return f'"{a}"' if (" " in a or "{" in a) else a


# ── 3. 채점·요약 ────────────────────────────────────────────────────────────────
def read_csv(path):
    return list(csv.DictReader(open(path, encoding="utf-8")))


def write_rows(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def score(pred_rows, answer, window, exclude=frozenset()):
    """예측(ip, window_start, anomaly) × 정답지 → 종류별 탐지·정상 오탐. exclude = 학습에 쓴 (ip, ws)."""
    rows = [r for r in pred_rows if (r["ip"], r["window_start"]) not in exclude]
    labels = label_windows(rows, load_answer(answer), timedelta(minutes=window))
    by_type, fp, n_norm = {}, 0, 0
    for r, lab in zip(rows, labels):
        hit = r["anomaly"] == "1"
        if lab is None:
            n_norm += 1
            fp += hit
        else:
            t = by_type.setdefault(lab[1], [0, 0])
            t[0] += hit
            t[1] += 1
    return by_type, fp, n_norm


def split_by_time(rows, labels, frac=0.7):
    """정상 구간 시간순 앞 frac = 학습. (학습 정상 rows, 학습 키 집합)"""
    normal = sorted((r for r, lab in zip(rows, labels) if lab is None), key=lambda r: r["window_start"])
    train = normal[:int(len(normal) * frac)]
    return train, {(r["ip"], r["window_start"]) for r in train}


# ── 4. 계층별 파이프라인 ─────────────────────────────────────────────────────────
def build_features(layer, files, run, out, meta, window):
    """원본 → 피처 CSV 경로 (없으면 None)."""
    w = ["--window", str(window)]
    if layer == "web":
        pre = [p for k, p, _ in files if k == "features_web"]
        if pre:
            src = pre[0]
        else:
            nginx = [p for k, p, _ in files if k == "nginx"]
            arch = [p for k, p, _ in files if k == "archives"]
            if not (nginx or arch):
                return None
            if nginx and arch:
                print("  (nginx 와 archives 가 둘 다 있음 → 같은 요청을 두 번 세지 않게 nginx 만 사용)")
            src = os.path.join(out, "features_web.csv")
            args = ["ml/features.py"] + sum([["--nginx", p] for p in nginx] or [["--archives", p] for p in arch], [])
            args += sum([["--owned-path", p] for p in meta.get("owned_paths", [])], [])
            if not run.step("웹 로그 → 출발지×구간 피처 (행위 8개)", args + w + ["--out", src]):
                return None
        if not all(c in read_csv(src)[0] for c in columns("web_v1")):
            rel = os.path.join(out, "features_web_rel.csv")
            if not run.step("UEBA 상대 피처 추가 (각 출발지의 평소 대비 배수)",
                            ["ml/relative_features.py", src, "--mode", "self", "--cols"] + REL_COLS + ["--out", rel]):
                return None
            src = rel
        return src
    if layer == "db":
        pre = [p for k, p, _ in files if k == "features_db"]
        if pre:
            return pre[0]
        logs = [p for k, p, _ in files if k == "general"]
        if not logs:
            return None
        if len(logs) > 1:
            print(f"  (general log {len(logs)}개 중 첫 파일만 사용: {logs[0]})")
        src = os.path.join(out, "features_db.csv")
        run.step("MySQL general log 파싱 점검 (미파싱·출발지 수)", ["edge/db_features.py", "--log", logs[0], "--check"])
        return src if run.step("MySQL general log → DB 피처", ["edge/db_features.py", "--log", logs[0]] + w + ["--out", src]) else None
    if layer == "host":
        pre = [p for k, p, _ in files if k == "features_host"]
        if pre:
            return pre[0]
        mats = [p for k, p, _ in files if k == "matrix"]
        snaps = [p for k, p, _ in files if k == "snapshots"]
        if not (mats or snaps):
            return None
        src = os.path.join(out, "features_host.csv")
        args = ["edge/host_metrics.py"] + (sum([["--matrix", p] for p in mats], []) if mats else ["--snapshots", snaps[0]])
        return src if run.step("node_exporter 지표 → 호스트×구간 피처", args + w + ["--out", src]) else None


def predict(run, model, feats, out_csv, title):
    return run.step(title, ["ml/predict.py", model, feats, "--out", out_csv])


def train(run, feats, out_model, fset, contamination, answer=None, title="학습"):
    args = ["ml/train_export.py", feats, "--feature-set", fset, "--contamination", str(contamination), "--out", out_model]
    if answer:
        args += ["--answer", answer]
    return run.step(title, args)


def process_layer(layer, feats, answer, args, run, out, window, contamination, report):
    fset = {"web": "web_v1", "db": "db_v1", "host": "host_v1"}[layer]
    sec = {"layer": layer, "features": feats, "rows": len(read_csv(feats))}
    if not sec["rows"]:
        sec["note"] = "피처가 0행 — 로그는 알아봤지만 구간을 못 만듦(형식·시각 확인, out/logs/ 의 파싱 출력)"
        report.append(sec)
        return
    keys = [None]
    if layer == "host":     # 호스트 지표는 호스트별 기준선 모델(docs/27 §3-4)
        rows = read_csv(feats)
        keys = sorted({r["ip"] for r in rows})
        os.makedirs(os.path.join(out, "host_by_host"), exist_ok=True)
        for k in keys:
            write_rows(os.path.join(out, "host_by_host", f"{k}.csv"), [r for r in rows if r["ip"] == k])

    preds, exclude = [], set()
    for key in keys:
        f = feats if key is None else os.path.join(out, "host_by_host", f"{key}.csv")
        tag = layer if key is None else f"host_{key}"
        pred_csv = os.path.join(out, f"pred_{tag}.csv")
        if not args.retrain:
            if MODELS[layer] is None:
                sec["note"] = "저장된 호스트 모델 없음(호스트마다 평소가 달라 그 인프라에서 학습해야 함) → --retrain 으로 다시 실행"
                break
            if not predict(run, MODELS[layer], f, pred_csv, f"저장 모델로 판정 ({MODELS[layer]})"):
                continue
        else:
            model = os.path.join(out, f"model_{tag}.joblib")
            rows = read_csv(f)
            if answer:
                labels = label_windows(rows, load_answer(answer), timedelta(minutes=window))
                tr_rows, tr_keys = split_by_time(rows, labels)
                if len(tr_rows) < 5:
                    print(f"  ({tag}: 정상 학습 구간 {len(tr_rows)}개 — 건너뜀)")
                    continue
                tr_csv = os.path.join(out, f"train_{tag}.csv")
                write_rows(tr_csv, tr_rows)
                eval_model = os.path.join(out, f"model_{tag}_eval.joblib")
                if not (train(run, tr_csv, eval_model, fset, contamination,
                              title=f"[채점용] 정상 앞 70%({len(tr_rows)}구간)로 학습 — 나머지는 처음 보는 데이터")
                        and predict(run, eval_model, f, pred_csv, "[채점용] 판정")):
                    continue
                exclude |= tr_keys
                has_attack = any(lab is not None for lab in labels)   # 공격 없는 키(호스트)엔 정답지를 안 넘김(train_export 가 멈춤)
                train(run, f, model, fset, contamination, answer if has_attack else None,
                      title="[보관용] 정상 전부" + (" + 정답지로 최종 모델 학습(RF 종류 분류 포함)" if has_attack else "로 최종 모델 학습"))
            else:
                base = rows
                if args.baseline_until:
                    base = [r for r in rows if r["window_start"] < args.baseline_until]
                    sec["baseline"] = f"{args.baseline_until} 이전 {len(base)}구간을 평소로 학습"
                else:
                    sec["baseline"] = "정답지·기준 시각 없음 → 전체를 평소로 가정(이상 비율≈contamination 만큼 표시됨)"
                if len(base) < 5:
                    print(f"  ({tag}: 평소 구간 {len(base)}개 — 건너뜀)")
                    continue
                base_csv = os.path.join(out, f"baseline_{tag}.csv")
                write_rows(base_csv, base)
                if not (train(run, base_csv, model, fset, contamination, title=f"평소 {len(base)}구간으로 학습")
                        and predict(run, model, f, pred_csv, "판정")):
                    continue
                if args.baseline_until:
                    exclude |= {(r["ip"], r["window_start"]) for r in base}
        preds += read_csv(pred_csv)

    if preds:
        if len(keys) > 1:
            write_rows(os.path.join(out, f"pred_{layer}.csv"), preds)
        shown = [p for p in preds if (p["ip"], p["window_start"]) not in exclude]
        sec["flagged"] = sorted((p for p in shown if p["anomaly"] == "1"), key=lambda p: (p["window_start"], p["ip"]))
        sec["judged"] = len(shown)
        if answer:
            sec["score"] = score(preds, answer, window, frozenset(exclude))
    report.append(sec)


# ── 5. 보고서 ───────────────────────────────────────────────────────────────────
def write_report(out, folder, found, notes, answers, run, report, args):
    L = [f"# 실험 보고서 — `{show(folder)}`", "",
         f"- 실행: {datetime.now().strftime('%Y-%m-%d %H:%M')} · 모드: **{'다시 학습(--retrain)' if args.retrain else '저장 모델로 판정'}**", "",
         "## 1. 알아본 파일", "", "| 종류 | 파일 |", "|---|---|"]
    L += [f"| {d} | `{os.path.relpath(p, folder)}` |" for _, p, d in found]
    L += [f"| ⚠ 안 씀: {d} | `{os.path.relpath(p, folder)}` |" for _, p, d in notes]
    L += ["", "## 2. 돌린 명령 (그대로 따라 칠 수 있음)", "", "```bash"]
    L += [f"# {t}{'' if ok else '   ← 실패, logs/' + lg}\n{c}" for t, c, ok, lg in run.log]
    L += ["```", "", "## 3. 결과"]
    for s in report:
        L += ["", f"### {LAYER_KO[s['layer']]}  (피처 {s['rows']}구간)"]
        if "note" in s:
            L += ["", f"- {s['note']}"]
            continue
        if "baseline" in s:
            L += ["", f"- 학습 기준: {s['baseline']}"]
        if "score" in s:
            by_type, fp, n_norm = s["score"]
            tp = sum(v[0] for v in by_type.values())
            n_att = sum(v[1] for v in by_type.values())
            L += ["", f"- **탐지 {tp}/{n_att}** · **정상 오탐 {fp}/{n_norm}** (IF|LOF|AE 합집합, 학습에 안 쓴 구간만)", "",
                  "| 공격 종류 | 탐지 |", "|---|---|"]
            L += [f"| {t} | {v[0]}/{v[1]} |" for t, v in sorted(by_type.items())]
            if not n_att:
                L += ["", "- ⚠ 정답지의 공격이 이 계층 구간과 하나도 안 맞음 — 출발지(ip)/시각/구간 길이 확인"]
        fl = s.get("flagged", [])
        L += ["", f"- 이상 표시 {len(fl)}/{s.get('judged', 0)}구간" + (" — 앞 20개:" if fl else "")]
        if fl:
            L += ["", "| 출발지 | 구간 시작(UTC) | IF | LOF | AE | RF 종류 |", "|---|---|---|---|---|---|"]
            L += [f"| {p['ip']} | {p['window_start']} | {p['iforest']} | {p['lof']} | {p['autoencoder']} | {p.get('rf_class', '')} |"
                  for p in fl[:20]]
    L += ["", "## 4. 읽는 법", "",
          "- 저장 모델 판정은 **우리 랩 기준의 '평소'** 로 본 결과다. 다른 인프라에선 평소가 달라 오탐이 많을 수 있다 → `--retrain` 과 비교.",
          "- 정답지가 없으면 '이상 표시'는 **조사 후보**일 뿐이다. 경보 등급(합집합=티켓, LOF&AE=고신뢰)은 `models/MODEL_CARD.md` §4.",
          "- `train_*.csv`·`baseline_*.csv` 는 ingest 가 직접 고른 학습용 행(정상 시간순 앞 70% / 기준 시각 이전)이다 — 위 명령의 입력.",
          "- 단계별 전체 출력은 `out/logs/`."]
    with open(os.path.join(out, "REPORT.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="폴더의 로그 → 피처 → 판정 → 보고서")
    ap.add_argument("folder", help="로그를 넣은 폴더 (예: inbox/company_a)")
    ap.add_argument("--retrain", action="store_true", help="이 인프라의 정상으로 다시 학습")
    ap.add_argument("--baseline-until", help="--retrain + 정답지 없음: 이 시각(UTC ISO) 이전을 평소로 학습")
    args = ap.parse_args()

    folder = os.path.abspath(args.folder)
    if not os.path.isdir(folder):
        sys.exit(f"폴더 없음: {args.folder}")
    meta_path = os.path.join(folder, "meta.json")
    meta = json.load(open(meta_path, encoding="utf-8")) if os.path.exists(meta_path) else {}
    window, contamination = float(meta.get("window", 5)), float(meta.get("contamination", 0.05))
    out = os.path.join(folder, "out")
    os.makedirs(out, exist_ok=True)

    found, notes = discover(folder)
    print(f"[{show(folder)}] 알아본 파일:")
    for _, p, d in found:
        print(f"  - {os.path.relpath(p, folder):<40} {d}")
    for _, p, d in notes:
        print(f"  - {os.path.relpath(p, folder):<40} ⚠ 안 씀: {d}")
    answers = [p for k, p, _ in found if k == "answer"]

    def answer_for(layer):   # answer_web.csv 처럼 계층 이름이 있으면 그것, 아니면 공통 정답지
        named = [p for p in answers if layer in os.path.basename(p).lower()]
        generic = [p for p in answers if not any(x in os.path.basename(p).lower() for x in ("web", "db", "host"))]
        return (named or generic or [None])[0]

    run, report = Runner(out), []
    for layer in ("web", "db", "host"):
        feats = build_features(layer, found, run, out, meta, window)
        if feats:
            print(f"\n── {LAYER_KO[layer]} ──")
            process_layer(layer, feats, answer_for(layer), args, run, out, window, contamination, report)
    if not report:
        sys.exit("처리할 로그를 못 찾음 — 위 '안 씀' 이유와 inbox/README.md 의 지원 형식 확인")

    write_report(out, folder, found, notes, answers, run, report, args)
    print(f"\n보고서: {show(os.path.join(out, 'REPORT.md'))}")
    for s in report:
        if "score" in s:
            by_type, fp, n_norm = s["score"]
            print(f"  {LAYER_KO[s['layer']]}: 탐지 {sum(v[0] for v in by_type.values())}/{sum(v[1] for v in by_type.values())}"
                  f" · 정상 오탐 {fp}/{n_norm}")
        elif "flagged" in s:
            print(f"  {LAYER_KO[s['layer']]}: 이상 표시 {len(s['flagged'])}/{s['judged']}구간 (정답지 없음 — 조사 후보)")
        elif "note" in s:
            print(f"  {LAYER_KO[s['layer']]}: {s['note']}")


if __name__ == "__main__":
    main()
