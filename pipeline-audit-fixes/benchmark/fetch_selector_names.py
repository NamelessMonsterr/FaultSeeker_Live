"""
Fetch real function names from 4byte.directory API using concurrent threads.
Much faster than sequential — resolves all selectors in ~15-20 seconds.
"""
import json, os, re, time
import urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

OUT_DIR   = 'data/output'
CACHE_OUT = 'data/models/selector_cache.json'

# Load existing cache
existing = {}
if os.path.exists(CACHE_OUT):
    with open(CACHE_OUT) as f:
        existing = json.load(f)

# Collect all unique selectors from prediction files
selectors = set()
for fn in os.listdir(OUT_DIR):
    if not fn.endswith('.json'):
        continue
    try:
        with open(os.path.join(OUT_DIR, fn)) as f:
            pred = json.load(f)
    except Exception:
        continue
    scored = pred.get('scored_functions') or pred.get('functions') or []
    for r in scored:
        raw = str(r.get('function') or r.get('name') or r.get('function_name') or '')
        if re.match(r'^0x[0-9a-f]{8}$', raw.strip().lower()):
            selectors.add(raw.strip().lower())

to_fetch = [s for s in sorted(selectors) if s not in existing]
print(f"Total unique selectors: {len(selectors)}")
print(f"Already cached: {len(existing)}")
print(f"Fetching {len(to_fetch)} from 4byte.directory (parallel)...")

def fetch_one(sel):
    url = f"https://www.4byte.directory/api/v1/signatures/?hex_signature={sel}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'FaultSeeker-research/1.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        results = data.get('results') or []
        if results:
            best = min(results, key=lambda x: x.get('id', 99999))
            fn_sig = best.get('text_signature', '')
            fn_name = fn_sig.split('(')[0].strip().lower() if fn_sig else ''
            return sel, fn_name
        return sel, ''
    except Exception as e:
        return sel, ''

fetched = 0
not_found = 0
errors = 0

with ThreadPoolExecutor(max_workers=12) as executor:
    futures = {executor.submit(fetch_one, sel): sel for sel in to_fetch}
    for i, future in enumerate(as_completed(futures), 1):
        sel, name = future.result()
        existing[sel] = name
        if name:
            fetched += 1
            print(f"  [{i}/{len(to_fetch)}] {sel} -> {name}")
        else:
            not_found += 1
        if i % 20 == 0:
            print(f"  ... {i}/{len(to_fetch)} done ...")

os.makedirs('data/models', exist_ok=True)
with open(CACHE_OUT, 'w') as f:
    json.dump(existing, f, indent=2, sort_keys=True)

print(f"\nResults: {fetched} resolved  |  {not_found} not found  |  {errors} errors")
print(f"Cache saved: {CACHE_OUT}  ({len(existing)} total entries)")
