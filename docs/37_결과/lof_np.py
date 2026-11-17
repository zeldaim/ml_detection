# numpy-only LOF (novelty) — sklearn 과 같은 정의: k=20, 표준화, 임계 = 학습 점수 하위 contamination 분위
import csv, sys, random
import numpy as np
FE = ["req_count","max_req_1min","uniq_paths","uniq_objects","err_ratio","write_ratio","interval_cv","endpoint_entropy"]
def load(p): return list(csv.DictReader(open(p)))
canon, boost = load(sys.argv[1]), load(sys.argv[2])
ans = {r['ip']: r['type'] for r in load(sys.argv[3])}
ans.update({r['ip']: 'bola_slow(boost)' for r in load(sys.argv[4])})
X = lambda rows: np.array([[float(r[f]) for f in FE] for r in rows])
def lof_fit(T, k):
    D = np.linalg.norm(T[:,None]-T[None], axis=2); np.fill_diagonal(D, np.inf)
    idx = np.argsort(D, axis=1)[:, :k]; nd = np.take_along_axis(D, idx, 1); kd = nd[:, -1]
    lrd = 1/(np.maximum(nd, kd[idx]).mean(1)+1e-10)
    return idx, kd, lrd, -(lrd[idx].mean(1)/lrd)
def lof_score(T, kd, lrd, Q, k):
    D = np.linalg.norm(Q[:,None]-T[None], axis=2); idx = np.argsort(D, axis=1)[:, :k]; nd = np.take_along_axis(D, idx, 1)
    l = 1/(np.maximum(nd, kd[idx]).mean(1)+1e-10); return -(lrd[idx].mean(1)/l)
normal = [r for r in canon if r['ip'] not in ans]; attack = [r for r in canon if r['ip'] in ans] + boost
ips = sorted({r['ip'] for r in normal}); C = 0.05
tot = {}; fp = [0,0]; thr_fp=[0,0]
for seed in range(5):
    rnd = random.Random(seed); test = set(rnd.sample(ips, max(1, round(len(ips)*0.3))))
    tr = np.unique(X([r for r in normal if r['ip'] not in test]), axis=0); te = [r for r in normal if r['ip'] in test]
    mu, sd = tr.mean(0), tr.std(0); sd[sd==0] = 1; Z = lambda a: (a-mu)/sd
    k = min(20, len(tr)-1); _, kd, lrd, nof = lof_fit(Z(tr), k); off = np.percentile(nof, 100*C)
    f = lof_score(Z(tr), kd, lrd, Z(X(te)), k) < off; fp[0] += int(f.sum()); fp[1] += len(te)
    thr_fp[0] += sum(float(r['uniq_objects'])>=5 for r in te); thr_fp[1] += len(te)
    a = lof_score(Z(tr), kd, lrd, Z(X(attack)), k) < off
    for r, hit in zip(attack, a):
        t = ans[r['ip']]; d = tot.setdefault(t, [0,0,0]); d[0] += 1; d[1] += int(hit); d[2] += float(r['uniq_objects'])>=5
print(f"정상 출발지 {len(ips)}개, 출발지 분할 seed 0~4 합계")
print(f"{'종류':20}{'구간':>6}{'LOF 탐지':>10}{'uniq_objects>=5 룰':>20}")
for t, (n, h, th) in sorted(tot.items()): print(f"{t:20}{n:6}{h:10}{th:20}")
print(f"정상 오탐  LOF {fp[0]}/{fp[1]} ({fp[0]/fp[1]:.1%})   uniq_objects>=5 룰 {thr_fp[0]}/{thr_fp[1]} ({thr_fp[0]/thr_fp[1]:.1%})")
