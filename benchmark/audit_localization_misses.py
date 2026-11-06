"""Audit all localization mismatches: extract root-cause categories from real data."""
import json, os, re, sys

GT_DIR   = 'benchmark/ground_truth'
OUT_DIR  = 'data/output'

WRAPPER_NAMES = {
    'execute', 'swap', 'swapexacttokensfortokens', 'swapexactethtokens',
    'swaptokensforexacteth', 'multicall', 'aggregate', 'fallback',
    'receive', 'transfer', 'transferfrom', 'call', 'delegatecall',
    'exactinputsingle', 'exactinput', 'exactoutput', 'exactoutputsingle',
}

def norm(v):
    return str(v or '').strip().lower().split('(')[0]

def is_raw_selector(s):
    return bool(re.match(r'^0x[0-9a-f]{8}$', s.strip().lower()))

def top_scored(pred_obj):
    scored = pred_obj.get('scored_functions') or pred_obj.get('functions') or []
    if not scored:
        return []
    def score_of(x):
        return float(x.get('score') or x.get('confidence') or x.get('_faegl_score') or 0)
    return sorted(scored, key=score_of, reverse=True)

hits, misses = [], []
selector_miss, wrapper_miss, other_miss, no_pred_miss = [], [], [], []

for fn in sorted(os.listdir(GT_DIR)):
    if not fn.endswith('.json'):
        continue
    txn = fn[:-5]
    gt_path  = os.path.join(GT_DIR, fn)
    out_path = os.path.join(OUT_DIR, fn)

    with open(gt_path) as f:
        gt = json.load(f)

    loc = gt.get('location') or {}
    gt_fns = set()
    for entry_list in loc.values():
        for entry in entry_list:
            parts = str(entry).split('#')
            if len(parts) >= 3:
                member = parts[-1].strip()
                if ':' not in member:
                    gt_fns.add(norm(member))
    if not gt_fns:
        continue

    if not os.path.exists(out_path):
        r = {'txn': txn[:20], 'reason': 'no_prediction', 'gt': sorted(gt_fns), 'pred_top1': 'N/A', 'pred_top5': []}
        misses.append(r); no_pred_miss.append(r); continue

    with open(out_path) as f:
        pred = json.load(f)

    ranked = top_scored(pred)
    if not ranked:
        r = {'txn': txn[:20], 'reason': 'empty', 'gt': sorted(gt_fns), 'pred_top1': 'EMPTY', 'pred_top5': []}
        misses.append(r); no_pred_miss.append(r); continue

    pred_top1_raw = ranked[0].get('function') or ranked[0].get('name') or ranked[0].get('function_name') or ''
    pred_top1     = norm(pred_top1_raw)
    pred_topk     = [norm(r.get('function') or r.get('name') or r.get('function_name') or '') for r in ranked[:10]]

    if pred_top1 in gt_fns:
        hits.append({'txn': txn[:20], 'gt': sorted(gt_fns), 'pred_top1': pred_top1_raw})
    else:
        r = {'txn': txn[:20], 'gt': sorted(gt_fns), 'pred_top1': pred_top1_raw, 'pred_top5': pred_topk[:5]}
        # Check if GT appears anywhere in top-10
        gt_rank = None
        for i, p in enumerate(pred_topk):
            if p in gt_fns:
                gt_rank = i + 1
                break
        r['gt_in_top10_rank'] = gt_rank

        if is_raw_selector(pred_top1):
            r['category'] = 'RAW_SELECTOR'
            selector_miss.append(r)
        elif pred_top1 in WRAPPER_NAMES:
            r['category'] = 'WRAPPER_FUNCTION'
            wrapper_miss.append(r)
        else:
            r['category'] = 'OTHER_NAMED'
            other_miss.append(r)
        misses.append(r)

total = len(hits) + len(misses)
print(f"\n{'='*65}")
print(f"LOCALIZATION MISMATCH AUDIT — {total} transactions")
print(f"{'='*65}")
print(f"  Top-1 Hits:   {len(hits):4d}  ({len(hits)/total*100:.1f}%)")
print(f"  Top-1 Misses: {len(misses):4d}  ({len(misses)/total*100:.1f}%)")
print(f"\nMiss Root-Cause Breakdown:")
print(f"  Raw 4-byte selector at Top-1:  {len(selector_miss):4d}  ({len(selector_miss)/total*100:.1f}%)")
print(f"  Known wrapper fn at Top-1:     {len(wrapper_miss):4d}  ({len(wrapper_miss)/total*100:.1f}%)")
print(f"  Other named fn mismatch:       {len(other_miss):4d}  ({len(other_miss)/total*100:.1f}%)")
print(f"  No prediction / empty:         {len(no_pred_miss):4d}  ({len(no_pred_miss)/total*100:.1f}%)")

print(f"\n{'='*65}")
print(f"CONFIRMED HITS (Top-1 correct)")
print(f"{'='*65}")
for h in hits:
    print(f"  {h['txn']} | GT: {h['gt']} | Top1: {h['pred_top1']}")

print(f"\n{'='*65}")
print(f"CATEGORY 1: RAW SELECTOR at Top-1 ({len(selector_miss)} misses)")
print(f"{'='*65}")
for m in selector_miss:
    print(f"  {m['txn']}")
    print(f"    GT target:     {m['gt']}")
    print(f"    Top-1 pred:    {m['pred_top1']}  <-- RAW SELECTOR")
    print(f"    Top-5 preds:   {m['pred_top5']}")
    if m['gt_in_top10_rank']:
        print(f"    GT appears at rank #{m['gt_in_top10_rank']} in top-10")

print(f"\n{'='*65}")
print(f"CATEGORY 2: WRAPPER FUNCTION at Top-1 ({len(wrapper_miss)} misses)")
print(f"{'='*65}")
for m in wrapper_miss:
    print(f"  {m['txn']}")
    print(f"    GT target:     {m['gt']}")
    print(f"    Top-1 pred:    {m['pred_top1']}  <-- WRAPPER")
    print(f"    Top-5 preds:   {m['pred_top5']}")
    if m['gt_in_top10_rank']:
        print(f"    GT appears at rank #{m['gt_in_top10_rank']} in top-10")

print(f"\n{'='*65}")
print(f"CATEGORY 3: OTHER NAMED FUNCTION MISMATCH ({len(other_miss)} misses)")
print(f"{'='*65}")
for m in other_miss[:20]:
    print(f"  {m['txn']}")
    print(f"    GT target:     {m['gt']}")
    print(f"    Top-1 pred:    {m['pred_top1']}")
    print(f"    Top-5 preds:   {m['pred_top5']}")
    if m['gt_in_top10_rank']:
        print(f"    GT appears at rank #{m['gt_in_top10_rank']} in top-10")

# Summary of GT-in-topk across all misses
for k in [3, 5, 10]:
    found_in_k = sum(1 for m in misses if m.get('gt_in_top10_rank') and m['gt_in_top10_rank'] <= k)
    print(f"\nAcross {len(misses)} misses: GT found within Top-{k}: {found_in_k}")
