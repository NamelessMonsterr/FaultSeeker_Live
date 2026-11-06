"""Detailed per-transaction hit/miss breakdown after selector resolution."""
import json, os, re

GT_DIR  = 'benchmark/ground_truth'
OUT_DIR = 'data/output'
CACHE   = 'data/models/selector_cache.json'

with open(CACHE) as f:
    cache = json.load(f)

def norm(v):
    return str(v or '').strip().lower().split('(')[0]

def is_sel(s):
    return bool(re.match(r'^0x[0-9a-f]{8}$', s.strip().lower()))

def resolve(raw):
    low = str(raw or '').strip().lower()
    if is_sel(low):
        return cache.get(low, low) or low
    return norm(raw)

hits, misses = [], []

for fn in sorted(os.listdir(GT_DIR)):
    if not fn.endswith('.json'):
        continue
    with open(os.path.join(GT_DIR, fn)) as f:
        gt = json.load(f)
    loc = gt.get('location') or {}
    gt_fns = set()
    for entry_list in loc.values():
        for entry in entry_list:
            parts = str(entry).split('#')
            if len(parts) >= 3:
                member = parts[-1].strip()
                if ':' not in member and member:
                    gt_fns.add(norm(member))
                    if is_sel(member):
                        rn = cache.get(member.lower(), '')
                        if rn:
                            gt_fns.add(norm(rn))
    if not gt_fns:
        continue

    out_path = os.path.join(OUT_DIR, fn)
    if not os.path.exists(out_path):
        continue
    with open(out_path) as f:
        pred = json.load(f)
    scored = pred.get('scored_functions') or pred.get('functions') or []
    if not scored:
        continue

    def score_of(x):
        return float(x.get('score') or x.get('confidence') or x.get('_faegl_score') or 0)

    ranked = sorted(scored, key=score_of, reverse=True)
    pred_resolved = []
    for r in ranked[:10]:
        raw = r.get('function') or r.get('name') or r.get('function_name') or ''
        pred_resolved.append(resolve(raw))

    top1 = pred_resolved[0] if pred_resolved else ''

    found_rank = None
    for i, p in enumerate(pred_resolved):
        if p in gt_fns:
            found_rank = i + 1
            break

    if top1 in gt_fns:
        hits.append({'txn': fn[:22], 'gt': sorted(gt_fns), 'top1': top1})
    else:
        misses.append({
            'txn': fn[:22],
            'gt': sorted(gt_fns),
            'top1': top1,
            'top5': pred_resolved[:5],
            'found_at': found_rank,
            'top1_is_raw': is_sel(top1),
        })

print(f"Evaluated: {len(hits)+len(misses)}  Hits: {len(hits)}  Misses: {len(misses)}")
print(f"Top-1: {len(hits)/(len(hits)+len(misses)):.4f}")

print("\n--- ALL HITS ---")
for h in hits:
    print(f"  {h['txn']}  GT:{h['gt']}  -> Top1:{h['top1']}")

named_misses = [m for m in misses if not m['top1_is_raw']]
raw_misses   = [m for m in misses if m['top1_is_raw']]

print(f"\n--- Misses: Top-1 still raw selector ({len(raw_misses)}) ---")
for m in raw_misses[:10]:
    print(f"  GT:{m['gt']}  Top1:{m['top1']}  Top5:{m['top5']}")

print(f"\n--- Misses: Top-1 is named but wrong ({len(named_misses)}) ---")
for m in named_misses[:15]:
    print(f"  GT:{m['gt']}  Top1:{m['top1']}  Top5:{m['top5']}  rank:{m['found_at']}")

# Summary
gt_found_in_top5  = sum(1 for m in misses if m['found_at'] and m['found_at'] <= 5)
gt_found_in_top10 = sum(1 for m in misses if m['found_at'] and m['found_at'] <= 10)
gt_absent         = sum(1 for m in misses if not m['found_at'])
print(f"\nAmong {len(misses)} misses:")
print(f"  GT found at rank 2-5:  {gt_found_in_top5}")
print(f"  GT found at rank 6-10: {gt_found_in_top10 - gt_found_in_top5}")
print(f"  GT not in top-10:      {gt_absent}")
print(f"  Top-1 still raw sel:   {len(raw_misses)}")
print(f"  Top-1 is named/wrong:  {len(named_misses)}")
