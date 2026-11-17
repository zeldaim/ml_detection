import re, sys, csv
from collections import defaultdict
from datetime import datetime
LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3})')
OWNED = re.compile(r'^/(?:rest/basket|api/BasketItems|api/Users|api/Cards|api/Addresss)/(\d+)(?:[/?]|$)')
ans = {r['ip']: r['type'] for f in sys.argv[2:] for r in csv.DictReader(open(f))}
ev = defaultdict(list)
for line in open(sys.argv[1], encoding='utf-8', errors='replace'):
    m = LINE.match(line)
    if not m: continue
    ip, ts, meth, path, code = m.groups()
    if not OWNED.match(path): continue
    t = datetime.strptime(ts, '%d/%b/%Y:%H:%M:%S %z').timestamp()
    ev[ip].append((t, path.split('?')[0], code))
def fires(evs, n, tf, ok_only):
    evs = sorted(e for e in evs if (e[2][0] == '2') or not ok_only)
    best = 0; j = 0
    for i in range(len(evs)):
        while evs[i][0] - evs[j][0] > tf: j += 1
        best = max(best, len({e[1] for e in evs[j:i+1]}))
    return best
def win(evs, sec):
    w = defaultdict(set)
    for t, p, c in evs: w[int(t // sec)].add(p)
    return sorted(len(v) for v in w.values())
print(f"{'ip':13}{'type':13}{'n':>5}{'2xx':>5}{'uniq':>5}  max distinct: 120s(2xx) 120s(any) 600s 3600s | 5min-window uniq (sorted)")
rows = []
for ip, evs in ev.items():
    rows.append((ans.get(ip, 'normal'), ip, evs))
for typ, ip, evs in sorted(rows):
    ok = sum(e[2][0] == '2' for e in evs)
    w5 = win(evs, 300)
    print(f"{ip:13}{typ:13}{len(evs):5}{ok:5}{len({e[1] for e in evs}):5}   {fires(evs,10,120,True):8} {fires(evs,10,120,False):9} {fires(evs,10,600,False):5} {fires(evs,10,3600,False):5} | {w5[-8:]}")
