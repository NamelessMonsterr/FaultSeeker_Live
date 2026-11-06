"""
FaultSeeker++ Evaluation Harness
================================
Runs the signal extraction + rule classification layer against
benchmark_classification_fixed.csv and produces accuracy metrics.

IMPORTANT: The benchmark CSV is exploit-only. "Detection rate" is
not a useful metric (predicting EXPLOIT always = 100%). Focus on:
  - Rule coverage: % of exploits our rules confidently classify
  - Type accuracy: % where we guess the right vulnerability type
  - Per-signal P/R/F1: how accurately each signal fires vs ground truth
  - Confusion matrix: which types get misclassified as which

BSC NOTE: BSC public nodes do NOT support debug_traceTransaction.
Run evaluation on ETH first (142 entries in the dataset):
    python benchmark/run_eval.py --chain eth --limit 20 --save

Usage:
    python benchmark/run_eval.py --chain eth --limit 20 --save
    python benchmark/run_eval.py --signals-only --limit 50
    python benchmark/run_eval.py --chain eth --limit 5   # quick smoke test
"""

import os
import sys
import csv
import json
import time
import argparse
from collections import defaultdict
from typing import Optional

# ── set project root so imports resolve ──────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from faultseeker.forensics.result import (
    extract_reentrancy_analysis,
    reentrancy_tier_weight,
    reentrancy_source,
    compute_priority_breakdown,
)

CSV_PATH    = os.path.join(_HERE, 'benchmark_classification_fixed.csv')
CACHE_DIR   = os.path.join(_ROOT, 'data', 'cache', 'forensics')
RESULTS_DIR = os.path.join(_HERE, 'eval_results')

# Vuln type normalisation - map ground-truth labels → canonical bucket
_CANON = {
    'price manipulation':           'Price Manipulation',
    'business logic flaw':          'Business Logic Flaw',
    'logic flaw':                   'Business Logic Flaw',
    'access control':               'Access Control',
    'lack of access control':       'Access Control',
    'reentrancy':                   'Reentrancy',
    'flash loan attack':            'Flash Loan Attack',
    'arbitrary external call':      'Arbitrary External Call',
    'precision loss':               'Precision Loss',
    'incorrect input validation':   'Input Validation',
}


def _canon(label: str) -> str:
    return _CANON.get(label.strip().lower(), label.strip())


# --- Ground Truth → Signal Mapping ---

GT_TO_SIGNAL = {
    # DASP categories
    "Reentrancy": ["reentrancy_detected"],
    "Access Control": ["access_control_bypass"],
    "Arithmetic": ["inflation_attack"],  # adjust if needed
    "Front-Running": ["price_read_write_sequences"],
    "Flash Loan": ["flash_loan_detected"],

    # SWC mappings (examples)
    "SWC-107": ["reentrancy_detected"],
    "SWC-105": ["access_control_bypass"],
    "SWC-101": ["inflation_attack"],
}

# Signals that REQUIRE multi-tx / external context → skip in eval
NON_EVALUABLE_SIGNALS = {
    "inflation_attack"
}


def _extract_result_reentrancy(result: dict) -> dict:
    grouped = result.get('reentrancy')
    if isinstance(grouped, dict):
        return extract_reentrancy_analysis({'reentrancy': grouped})
    return extract_reentrancy_analysis(result.get('signals', {}))


def _raw_signal_dict(signals) -> dict:
    if hasattr(signals, 'raw'):
        return getattr(signals, 'raw') or {}
    if isinstance(signals, dict):
        return signals
    return {}


def build_dataset_row(result: dict) -> dict:
    reentrancy = _extract_result_reentrancy(result)
    signal_flags = reentrancy.get('signals', {})
    context = reentrancy.get('context', {})
    signals = result.get('signals', {})
    if not signals and result.get('reentrancy'):
        signals = {'reentrancy': result.get('reentrancy', {})}
    priority = result.get(
        'priority',
        compute_priority_breakdown(signals, exploitability_score=result.get('confidence', 0.0)),
    )

    row = {
        'txn_hash': result.get('txn_hash', ''),
        'chain': result.get('chain', ''),
        'vuln_type': result.get('vuln_type', ''),
        'difficulty': result.get('difficulty', ''),
        'verdict': result.get('verdict', ''),
        'confidence': result.get('confidence', 0.0),
        'rule': result.get('rule', ''),
        'predicted_type': result.get('predicted_type', ''),
        'priority_score': result.get('priority_score', priority.get('total', 0.0)),
        'priority_reentrancy': priority.get('reentrancy', 0.0),
        'priority_flashloan': priority.get('flashloan', 0.0),
        'priority_price_manipulation': priority.get('price_manipulation', 0.0),
        'priority_liquidity_drain': priority.get('liquidity_drain', 0.0),
        'reentrancy_score': reentrancy.get('score', 0.0),
        'reentrancy_detected': reentrancy.get('detected', False),
        'reentrancy_tier': reentrancy.get('tier', 'NOT_REENTRANCY'),
        'reentrancy_fallback': context.get('fallback_mode', False),
        'reentrancy_source': reentrancy_source(reentrancy),
        'reentry_cross_fn': signal_flags.get('cross_function_reentry', False),
        'reentry_before_return': signal_flags.get('reentry_before_return', False),
        'reentry_state_slot': signal_flags.get('state_slot_reentry', False),
    }
    if 'elapsed_secs' in result:
        row['elapsed_secs'] = result.get('elapsed_secs', 0.0)
    return row


def normalize_signals(raw):
    reentrancy = extract_reentrancy_analysis(raw)
    return {
        "flash_loan_detected": bool(raw.get("flash_loan_detected", False)),
        "reentrancy_detected": bool(reentrancy.get("detected", False)),
        "access_control_bypass": bool(raw.get("access_control_bypass", False)),
        "price_read_write_sequences": bool(raw.get("price_read_write_sequences", 0) > 0),
        "inflation_attack": bool(raw.get("inflation_attack", False)),
    }

def get_expected_signals(row):
    expected = set()

    # From DASP
    dasp = str(row.get("dasp", "")).strip()
    if dasp in GT_TO_SIGNAL:
        expected.update(GT_TO_SIGNAL[dasp])

    # From SWC
    swc = str(row.get("swc", "")).strip()
    for k, v in GT_TO_SIGNAL.items():
        if k in swc:
            expected.update(v)

    return expected


def _load_csv(chain_filter: Optional[str] = None, limit: Optional[int] = None):
    rows = []
    with open(CSV_PATH, encoding='utf-8') as f:
        for row in csv.DictReader(f):
            if not row.get('txn_hash', '').strip():
                continue
            if chain_filter and row['chain'].strip().lower() != chain_filter.lower():
                continue
            entry = {
                'txn_hash':   row['txn_hash'].strip(),
                'chain':      row['chain'].strip().lower(),
                'vuln_type':  _canon(row.get('vuln_type', '')),
                'difficulty': row.get('class', '').strip(),
                # additional columns for signal ground truth
                'dasp':       row.get('dasp_classification', '').strip(),
                'swc':        row.get('swc_registry_classification', '').strip(),
                'uncategorized': row.get('uncategorized', '').strip(),
            }
            entry['expected_signals'] = get_expected_signals(entry)
            rows.append(entry)
            if limit and len(rows) >= limit:
                break
    return rows


# ── Offline mode: load cached forensics JSON and re-run signals ───────────────

def _eval_from_cache(rows):
    from faultseeker.forensics.signal_extractor import SignalExtractor
    from faultseeker.forensics import rule_classifier

    results = []
    for entry in rows:
        txn = entry['txn_hash']
        cache_file = os.path.join(CACHE_DIR, f'{txn}.json')
        if not os.path.exists(cache_file):
            print(f'  [SKIP] No cache: {txn[:16]}...')
            continue
        try:
            with open(cache_file) as f:
                data = json.load(f)
            internal = data.get('_internal', {})
            tx_analysis = {
                'flatten_trace':     internal.get('flatten_trace', []),
                'trace':             internal.get('trace', {}),
                'function_call_loc_memo': internal.get('function_call_loc_memo', {}),
                'function_calls_to_expand_loc': internal.get('function_calls_to_expand_loc', {}),
                'repeated_patterns': data.get('function_analysis', {}).get('repeated_patterns', {}),
                'address_calls_with_created_contract_in_params':
                    data.get('function_analysis', {}).get('calls_with_created_contracts', []),
                'potential_attacker': data.get('attack_analysis', {}).get('potential_attackers', []),
                'balance_change':    data.get('attack_analysis', {}).get('balance_changes', {}),
            }
            signals = SignalExtractor({}, tx_analysis, txn, entry['chain']).run()
            raw_signals = _raw_signal_dict(signals)
            verdict, conf, rule, vuln_hint = rule_classifier.classify(signals)
            reentrancy = extract_reentrancy_analysis(raw_signals)
            priority = compute_priority_breakdown(
                raw_signals,
                exploitability_score=conf,
            )
            results.append({
                **entry,
                'verdict':        verdict,
                'confidence':     conf,
                'rule':           rule,
                'predicted_type': vuln_hint,
                'reentrancy':     reentrancy,
                'priority':       priority,
                'priority_score': priority['total'],
                'signals':        raw_signals,
            })
            print(f"  [{verdict:<10}] {conf:.0%}  rule={rule:<35}  "
                  f"predicted={vuln_hint:<30}  actual={entry['vuln_type']}")
        except Exception as e:
            print(f'  [ERROR] {txn[:16]}...: {e}')
    return results


# ── Online mode: run full pipeline ────────────────────────────────────────────

def _eval_online(rows):
    """Runs the full FaultSeeker++ pipeline for each transaction."""
    try:
        from faultseeker.forensics.orchestrator import ForensicsOrchestrator
    except ImportError as e:
        print(f'Import error: {e}')
        sys.exit(1)

    results = []
    trace_failures = 0
    orch = ForensicsOrchestrator()
    for i, entry in enumerate(rows, 1):
        txn   = entry['txn_hash']
        chain = entry['chain']
        print(f'\n[{i}/{len(rows)}] {txn[:20]}... ({chain}) - {entry["vuln_type"]}')
        t0 = time.time()
        try:
            forensics_result, _, _ = orch.run(txn, chain)
            elapsed = time.time() - t0
            if forensics_result is None:
                trace_failures += 1
                print(f'  [FAIL] Pipeline returned None [{"TRACE FAIL" if elapsed < 15 else "TIMEOUT"}] ({elapsed:.1f}s)')
                continue
            raw_signals = _raw_signal_dict(getattr(forensics_result, 'signals', {}))
            priority = compute_priority_breakdown(
                raw_signals,
                exploitability_score=forensics_result.rule_confidence,
            )
            results.append({
                **entry,
                'verdict':        forensics_result.rule_verdict,
                'confidence':     forensics_result.rule_confidence,
                'rule':           forensics_result.matched_rule,
                'predicted_type': forensics_result.vuln_type_hint,
                'elapsed_secs':   round(elapsed, 1),
                'reentrancy':     extract_reentrancy_analysis(raw_signals),
                'priority':       priority,
                'priority_score': priority['total'],
                'signals':        raw_signals,
            })
            rule_label = forensics_result.matched_rule or ''
            print(f"  [{forensics_result.rule_verdict:<10}] "
                  f"{forensics_result.rule_confidence:.0%}  "
                  f"predicted={forensics_result.vuln_type_hint:<28}  "
                  f"actual={entry['vuln_type']}  ({elapsed:.1f}s)")
            if rule_label == 'multi_tx_context_required':
                print(f"      -> Likely part of multi-transaction exploit - insufficient local signals")
        except KeyboardInterrupt:
            print('\nInterrupted by user.')
            break
        except Exception as e:
            print(f'  [ERROR] {e}')
    if trace_failures:
        print(f'\n  [WARNING] {trace_failures}/{len(rows)} transactions failed (no archive trace).')
        print(f'     → Chain "{rows[0]["chain"] if rows else "??"}" requires a trace-enabled archive node.')
        print(f'       Alchemy (ETH) or Ankr (with API key) support debug_traceTransaction.')
    return results


# ── Per-signal precision / recall helpers ─────────────────────────────────────


def _compute_signal_metrics(results: list) -> tuple:
    metrics = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0, "support": 0})
    failures = []
    skipped = 0

    for r in results:
        raw = r.get('signals', {})
        if not isinstance(raw, dict) or not raw:
            skipped += 1
            continue

        pred = normalize_signals(raw)
        expected = get_expected_signals(r)

        if not expected:
            skipped += 1
            continue

        for signal in pred.keys():
            if signal in NON_EVALUABLE_SIGNALS:
                continue

            gt = signal in expected
            pr = pred[signal]

            if gt:
                metrics[signal]["support"] += 1

            if gt and pr:
                metrics[signal]["TP"] += 1
            elif not gt and pr:
                metrics[signal]["FP"] += 1
            elif gt and not pr:
                metrics[signal]["FN"] += 1
                failures.append({
                    "tx": r.get('txn_hash'),
                    "signal": signal,
                    "expected": True,
                    "predicted": False,
                    "raw": raw
                })

    return dict(metrics), failures, skipped

def compute_scores(m):
    tp, fp, fn = m["TP"], m["FP"], m["FN"]
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0
    return precision, recall, f1


def _compute_reentrancy_metrics(results: list) -> dict:
    support = 0
    weighted_tp = 0.0
    weighted_predicted = 0.0
    detected_hits = 0
    fallback_hits = 0
    storage_hits = 0
    score_total = 0.0

    for result in results:
        reentrancy = _extract_result_reentrancy(result)
        expected = get_expected_signals(result)
        is_gt = 'reentrancy_detected' in expected
        weight = reentrancy_tier_weight(reentrancy.get('tier', ''))

        if reentrancy.get('detected', False):
            weighted_predicted += weight

        if not is_gt:
            continue

        support += 1
        score_total += float(reentrancy.get('score', 0.0))
        if reentrancy.get('detected', False):
            detected_hits += 1
            weighted_tp += weight
            if reentrancy.get('context', {}).get('fallback_mode', False):
                fallback_hits += 1
            if reentrancy.get('context', {}).get('storage_trace_available', False):
                storage_hits += 1

    weighted_precision = weighted_tp / weighted_predicted if weighted_predicted else 0.0
    weighted_recall = weighted_tp / support if support else 0.0
    detected_recall = detected_hits / support if support else 0.0
    fallback_detection_rate = fallback_hits / support if support else 0.0
    storage_trace_detection_rate = storage_hits / support if support else 0.0
    avg_score = score_total / support if support else 0.0

    return {
        'support': support,
        'weighted_precision': round(weighted_precision, 4),
        'weighted_recall': round(weighted_recall, 4),
        'detected_recall': round(detected_recall, 4),
        'fallback_detection_rate': round(fallback_detection_rate, 4),
        'storage_trace_detection_rate': round(storage_trace_detection_rate, 4),
        'avg_score': round(avg_score, 4),
    }


def _top_reentrancy_candidates(results: list, limit: int = 5) -> list:
    candidates = []
    for result in results:
        reentrancy = _extract_result_reentrancy(result)
        if not reentrancy.get('detected', False):
            continue
        row = build_dataset_row(result)
        active_signals = [
            key for key, active in reentrancy.get('signals', {}).items()
            if active
        ]
        candidates.append({
            'txn_hash': row['txn_hash'],
            'chain': row['chain'],
            'priority_score': row['priority_score'],
            'priority_reentrancy': row['priority_reentrancy'],
            'priority_flashloan': row['priority_flashloan'],
            'priority_price_manipulation': row['priority_price_manipulation'],
            'priority_liquidity_drain': row['priority_liquidity_drain'],
            'reentrancy_score': row['reentrancy_score'],
            'reentrancy_tier': row['reentrancy_tier'],
            'reentrancy_fallback': row['reentrancy_fallback'],
            'reentrancy_source': row['reentrancy_source'],
            'active_signals': active_signals,
        })
    candidates.sort(key=lambda item: item['priority_score'], reverse=True)
    return candidates[:limit]


# ── Classification metrics ────────────────────────────────────────────────────

def _compute_metrics(results):
    total = len(results)
    if not total:
        return {}

    exploit_detected  = sum(1 for r in results if r['verdict'] == 'EXPLOIT')
    uncertain_total   = sum(1 for r in results if r['verdict'] == 'UNCERTAIN')
    context_required  = sum(1 for r in results
                            if r.get('rule') == 'multi_tx_context_required')
    llm_required      = sum(1 for r in results
                            if r['verdict'] == 'UNCERTAIN'
                            and r.get('rule') != 'multi_tx_context_required')
    false_benign      = sum(1 for r in results if r['verdict'] == 'BENIGN')

    rule_coverage = exploit_detected / total

    type_total    = exploit_detected
    type_correct  = sum(1 for r in results
                        if r['verdict'] == 'EXPLOIT'
                        and r['predicted_type'] == r['vuln_type'])

    # Confusion matrix
    confmat: dict = defaultdict(lambda: defaultdict(int))
    for r in results:
        actual    = r['vuln_type']
        predicted = r['predicted_type'] if r['verdict'] == 'EXPLOIT' else f'[{r["verdict"]}]'
        confmat[actual][predicted] += 1

    # By difficulty
    by_diff: dict = defaultdict(lambda: {'total': 0, 'rule_classified': 0, 'type_correct': 0})
    for r in results:
        d = r.get('difficulty', 'Unknown')
        by_diff[d]['total'] += 1
        if r['verdict'] == 'EXPLOIT':
            by_diff[d]['rule_classified'] += 1
            if r['predicted_type'] == r['vuln_type']:
                by_diff[d]['type_correct'] += 1

    # By vuln type
    by_type: dict = defaultdict(lambda: {'total': 0, 'rule_classified': 0, 'type_correct': 0})
    for r in results:
        vt = r['vuln_type']
        by_type[vt]['total'] += 1
        if r['verdict'] == 'EXPLOIT':
            by_type[vt]['rule_classified'] += 1
            if r['predicted_type'] == vt:
                by_type[vt]['type_correct'] += 1

    avg_latency = (sum(r.get('elapsed_secs', 0) for r in results) / total
                   if any('elapsed_secs' in r for r in results) else None)

    # Signal-level metrics
    signal_metrics, failures, skipped = _compute_signal_metrics(results)
    reentrancy_metrics = _compute_reentrancy_metrics(results)
    top_reentrancy_candidates = _top_reentrancy_candidates(results)

    return {
        'total':              total,
        'exploit_detected':   exploit_detected,
        'uncertain_total':    uncertain_total,
        'context_required':   context_required,
        'llm_required':       llm_required,
        'false_benign':       false_benign,
        'rule_coverage':      round(rule_coverage, 4),
        'type_total':         type_total,
        'type_correct':       type_correct,
        'type_accuracy':      round(type_correct / type_total, 4) if type_total else 0,
        'avg_latency_secs':   avg_latency,
        'signal_metrics':     signal_metrics,
        'reentrancy_metrics': reentrancy_metrics,
        'top_reentrancy_candidates': top_reentrancy_candidates,
        'failures':           failures,
        'skipped':            skipped,
        'confusion_matrix':   {k: dict(v) for k, v in confmat.items()},
        'by_difficulty':      dict(by_diff),
        'by_vuln_type':       dict(by_type),
    }


def _print_report(metrics: dict) -> None:
    if not metrics or metrics.get('total', 0) == 0:
        print('\n  [ERROR] No transactions were evaluated.')
        print('  Cause: All RPC trace calls failed (archive node required).')
        print('  Fix  : Set ETH_RPC_URL in .env to an Alchemy or Ankr (with key) endpoint.')
        print('         Example: ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY')
        return

    print('\n' + '=' * 66)
    print('  FaultSeeker++ Evaluation Report')
    print('=' * 66)
    print(f"\n  Transactions evaluated : {metrics['total']}")
    print(f"  Rule coverage          : {metrics['exploit_detected']}  "
          f"({metrics['rule_coverage']:.1%})  <-- exploits confidently classified by rules")
    print(f"  Context required       : {metrics['context_required']}  "
          f"({metrics['context_required'] / metrics['total']:.1%})  "
          f"<-- likely multi-tx exploit, insufficient local signals")
    print(f"  UNCERTAIN (LLM needed) : {metrics['llm_required']}  "
          f"({metrics['llm_required'] / metrics['total']:.1%})")
    print(f"  False-BENIGN (missed)  : {metrics['false_benign']}  "
          f"(target: <5%)")
    if metrics.get('avg_latency_secs'):
        print(f"  Avg latency / txn      : {metrics['avg_latency_secs']:.1f}s")

    print(f"\n  Type accuracy (rule-classified subset):")
    print(f"    {metrics['type_correct']}/{metrics['type_total']}  "
          f"= {metrics['type_accuracy']:.1%}")

    # ── Per-signal precision / recall / F1 ────────────────────────────────────
    reentrancy_metrics = metrics.get('reentrancy_metrics', {})
    if reentrancy_metrics.get('support', 0):
        print("\n  Reentrancy analysis:")
        print(f"    Support                    : {reentrancy_metrics['support']}")
        print(f"    Weighted precision         : {reentrancy_metrics['weighted_precision']:.2f}")
        print(f"    Weighted recall            : {reentrancy_metrics['weighted_recall']:.2f}")
        print(f"    Detection recall           : {reentrancy_metrics['detected_recall']:.1%}")
        print(f"    Fallback detection rate    : {reentrancy_metrics['fallback_detection_rate']:.1%}")
        print(f"    Storage-trace detection    : {reentrancy_metrics['storage_trace_detection_rate']:.1%}")
        print(f"    Avg GT reentrancy score    : {reentrancy_metrics['avg_score']:.3f}")

    top_reentrancy_candidates = metrics.get('top_reentrancy_candidates', [])
    if top_reentrancy_candidates:
        print("\n  Top reentrancy candidates:")
        for candidate in top_reentrancy_candidates:
            active = ', '.join(candidate['active_signals']) if candidate['active_signals'] else 'none'
            print(
                f"    {candidate['txn_hash'][:18]}... "
                f"{candidate['chain']:<10} "
                f"priority={candidate['priority_score']:.3f} "
                f"(r={candidate['priority_reentrancy']:.3f} "
                f"f={candidate['priority_flashloan']:.3f} "
                f"pm={candidate['priority_price_manipulation']:.3f} "
                f"ld={candidate['priority_liquidity_drain']:.3f}) "
                f"score={candidate['reentrancy_score']:.3f} "
                f"tier={candidate['reentrancy_tier']} "
                f"source={candidate['reentrancy_source']} "
                f"signals=[{active}]"
            )

    sm = metrics.get('signal_metrics', {})
    if sm:
        print("\n  Signal-level detection (vs. DASP/SWC ground truth):")
        print(f"    {'Signal':<35} {'Prec':>6} {'Rec':>6} {'F1':>6} {'TP':>4} {'FP':>4} {'FN':>4} {'(n)':>6}")
        print("    " + "-" * 76)
        
        has_printed_any = False
        for signal, m in sm.items():
            if m["support"] < 3:
                continue  # ignore low-support noise
            has_printed_any = True
            p, r, f1 = compute_scores(m)
            print(f"    {signal:<35} {p:6.2f} {r:6.2f} {f1:6.2f} {m['TP']:4} {m['FP']:4} {m['FN']:4} {m['support']:6}")
            
        if not has_printed_any:
            print("    [ No signals had support >= 3 ]")

        skipped_count = metrics.get('skipped', 0)
        print(f"\n  Skipped (no GT mapping): {skipped_count}")

        failures = metrics.get('failures', [])
        if failures:
            print("\n  Top Failures (first 10):")
            for f in failures[:10]:
                print(f"    TX: {f['tx']}")
                print(f"    Signal missed: {f['signal']}")
                print(f"    Raw signals: {f['raw']}")
                print("    " + "-" * 50)


    print('\n  By difficulty:')
    for diff, m in sorted(metrics['by_difficulty'].items()):
        cov  = m['rule_classified'] / m['total'] if m['total'] else 0
        tacc = m['type_correct'] / m['rule_classified'] if m['rule_classified'] else 0
        print(f"    {diff:<25} n={m['total']:<3}  "
              f"rule_cov={cov:.0%}  type_acc={tacc:.0%}")

    print('\n  By vulnerability type:')
    for vt, m in sorted(metrics['by_vuln_type'].items(),
                        key=lambda x: -x[1]['total']):
        cov  = m['rule_classified'] / m['total'] if m['total'] else 0
        tacc = m['type_correct'] / m['rule_classified'] if m['rule_classified'] else 0
        print(f"    {vt:<40} n={m['total']:<3}  cov={cov:.0%}  type_acc={tacc:.0%}")

    # Confusion matrix (compact)
    confmat = metrics.get('confusion_matrix', {})
    if confmat:
        all_preds = sorted({p for preds in confmat.values() for p in preds})
        col_w = max(len(p) for p in all_preds) + 2
        print('\n  Confusion matrix (actual → predicted):')
        header = f"    {'Actual':<38}" + ''.join(f"{p:<{col_w}}" for p in all_preds)
        print(header)
        print('    ' + '-' * (len(header) - 4))
        for actual, preds in sorted(confmat.items()):
            row = f"    {actual:<38}" + ''.join(
                f"{preds.get(p, 0):<{col_w}}" for p in all_preds
            )
            print(row)

    print('\n' + '=' * 66 + '\n')


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='FaultSeeker++ Evaluation Harness')
    parser.add_argument('--limit',        type=int,  default=None,  help='Max entries to evaluate')
    parser.add_argument('--chain',        type=str,  default=None,  help='Filter by chain (eth, bsc, …)')
    parser.add_argument('--signals-only', action='store_true',       help='Use cached JSONs, no RPC calls')
    parser.add_argument('--save',         action='store_true',       help='Save results to eval_results/ dir')
    args = parser.parse_args()

    print(f'\nLoading dataset from {CSV_PATH}')
    rows = _load_csv(chain_filter=args.chain, limit=args.limit)
    print(f'Entries to evaluate: {len(rows)}')

    if args.signals_only:
        print('Mode: offline (cached forensics JSONs)\n')
        results = _eval_from_cache(rows)
    else:
        print('Mode: online (full pipeline - will make RPC calls)\n')
        results = _eval_online(rows)

    metrics = _compute_metrics(results)
    _print_report(metrics)

    if args.save and results:
        os.makedirs(RESULTS_DIR, exist_ok=True)
        ts = time.strftime('%Y%m%d_%H%M%S')
        dataset_rows = [build_dataset_row(result) for result in results]

        out = os.path.join(RESULTS_DIR, f'eval_{ts}.json')
        with open(out, 'w', encoding='utf-8') as f:
            json.dump({'metrics': metrics, 'results': results}, f, indent=2, default=str)
        print(f'Results saved to {out}')

        csv_out = os.path.join(RESULTS_DIR, f'eval_{ts}.csv')
        with open(csv_out, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=dataset_rows[0].keys())
            writer.writeheader()
            writer.writerows(dataset_rows)
        print(f'Dataset rows saved to {csv_out}')


if __name__ == '__main__':
    main()
