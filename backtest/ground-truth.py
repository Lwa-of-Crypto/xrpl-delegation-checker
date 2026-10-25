# Ground truth for the backtest: every Delegate object in one validated Mainnet ledger,
# read with ledger_data (a full-state sweep), independent of the tool's code.
# The 256-bit key space is split into ranges swept in parallel; each range stops at its upper bound.
import json, sys, time, urllib.request, threading

SERVERS = ['https://xrplcluster.com/', 'https://xrpl.ws/']
WORKERS = int(sys.argv[1]) if len(sys.argv) > 1 else 8

def call(url, params):
    req = urllib.request.Request(url, data=json.dumps({'method': 'ledger_data', 'params': [params]}).encode(),
                                 headers={'Content-Type': 'application/json'})
    return json.load(urllib.request.urlopen(req, timeout=90))['result']

def rpc(params, n):
    for i in range(40):
        url = SERVERS[(n + i) % len(SERVERS)]
        try:
            r = call(url, params)
            if r.get('status') == 'success':
                return r
        except Exception:
            pass
        time.sleep(2 + 2 * min(i, 10))
    raise RuntimeError('rpc failed repeatedly')

ledger = rpc({'ledger_index': 'validated', 'type': 'delegate', 'limit': 1}, 0)['ledger_index']
bounds = [i * (2**256 // WORKERS) for i in range(WORKERS)] + [2**256]
lock = threading.Lock()
objs, stats, errors = [], {'calls': 0, 'done': 0}, []
progress = [0.0] * WORKERS

def worker(w):
    lo, hi = bounds[w], bounds[w + 1]
    marker = None if w == 0 else format(lo, '064X')
    n = w
    while True:
        p = {'ledger_index': ledger, 'type': 'delegate', 'limit': 2048}
        if marker: p['marker'] = marker
        try:
            r = rpc(p, n)
        except Exception as e:
            errors.append(f'worker {w}: {e}'); return
        n += 1
        keep = [o for o in r.get('state', []) if lo <= int(o['index'], 16) < hi]
        marker = r.get('marker')
        with lock:
            objs.extend(keep); stats['calls'] += 1
            progress[w] = 1.0 if not marker else min(1.0, (int(marker, 16) - lo) / (hi - lo))
            if stats['calls'] % 100 == 0:
                print(f"calls={stats['calls']} found={len(objs)} progress={sum(progress)/WORKERS:.1%}", flush=True)
        if not marker or int(marker, 16) >= hi:
            with lock: stats['done'] += 1; progress[w] = 1.0
            return
        time.sleep(0.15)

t0 = time.time()
ts = [threading.Thread(target=worker, args=(w,)) for w in range(WORKERS)]
[t.start() for t in ts]; [t.join() for t in ts]
uniq = {o['index']: o for o in objs}
json.dump({'ledger': ledger, 'calls': stats['calls'], 'workers_completed': stats['done'], 'errors': errors,
           'objects': list(uniq.values())}, open('backtest/ground-truth-mainnet.json', 'w'), indent=1)
print(f"DONE ledger={ledger} calls={stats['calls']} workers_ok={stats['done']}/{WORKERS} errors={len(errors)} delegate_objects={len(uniq)} secs={time.time()-t0:.0f}", flush=True)
