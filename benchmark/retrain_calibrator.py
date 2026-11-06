"""Retrain calibrator on real measured features from the benchmark.

Uses:
  - benchmark/benchmark_classification_fixed.csv  (exploit, label=1)
  - benchmark/imported/benign_traces.csv           (benign, label=0)

Both files contain real trace features measured from the Ethereum blockchain
via debug_traceTransaction. No synthetic data.
"""
import sys, os, csv, json
sys.path.insert(0, '.')
from dotenv import load_dotenv
load_dotenv()

from faultseeker.research.calibration import LogisticConfidenceCalibrator

EXPLOIT_CSV   = 'benchmark/benchmark_classification_fixed.csv'
BENIGN_TRACES = 'benchmark/imported/benign_traces.csv'
MODEL_OUT     = 'data/models/calibrator.json'

TRACE_FEATURES = ['functioncall_count', 'address_count', 'max_depth', 'gas_cost']

# --- Feature normalization ceilings (same as proxy scorers) ---
CEILINGS = {
    'functioncall_count': 300.0,
    'address_count':       25.0,
    'max_depth':           15.0,
    'gas_cost':       1_500_000.0,
}

def normalize(row):
    """Normalize raw trace features to [0,1] matching the proxy scorer logic."""
    normed = {}
    for feat, ceiling in CEILINGS.items():
        try:
            v = float(row.get(feat) or 0.0)
        except (TypeError, ValueError):
            v = 0.0
        normed[feat] = max(0.0, min(1.0, v / ceiling)) if ceiling > 0 else 0.0
    # Map to the calibrator's 8-feature space
    # 4 trace features → proxy for pattern_match, code_evidence, txn_consistency, llm_confidence
    fc  = normed['functioncall_count']
    ac  = normed['address_count']
    md  = normed['max_depth']
    gas = normed['gas_cost']
    return {
        'pattern_match':      round((fc * 0.5 + md * 0.5), 6),
        'code_evidence':      round(ac, 6),
        'txn_consistency':    round((fc * 0.4 + gas * 0.6), 6),
        'llm_confidence':     round((md * 0.4 + fc * 0.3 + gas * 0.3), 6),
        'trace_entropy':      round(md, 6),
        'call_depth':         round(md, 6),
        'state_delta':        round((fc * 0.6 + ac * 0.4), 6),
        'token_flow_anomaly': round(gas, 6),
    }

def load_exploit_features():
    rows = []
    with open(EXPLOIT_CSV, encoding='utf-8-sig') as f:
        for raw in csv.DictReader(f):
            status = str(raw.get('collection_status') or raw.get('pool_status') or '').lower()
            rows.append(normalize(raw))
    print(f'Loaded {len(rows)} exploit rows from {EXPLOIT_CSV}')
    return rows

def load_benign_features():
    rows = []
    with open(BENIGN_TRACES, encoding='utf-8-sig') as f:
        for raw in csv.DictReader(f):
            if str(raw.get('collection_status','').strip().lower()) == 'ok':
                rows.append(normalize(raw))
    print(f'Loaded {len(rows)} benign rows from {BENIGN_TRACES}')
    return rows

exploit_feats = load_exploit_features()
benign_feats  = load_benign_features()

X = exploit_feats + benign_feats
y = [1] * len(exploit_feats) + [0] * len(benign_feats)

print(f'\nTraining on {sum(y)} exploit + {len(y)-sum(y)} benign = {len(y)} total real transactions')

cal = LogisticConfidenceCalibrator()
cal.fit(X, y, epochs=1000, learning_rate=0.05, l2=0.001)

# Evaluate
metrics = cal.evaluate(X, y)
print(f'Brier score: {metrics.brier_score:.4f}')
print(f'ECE:         {metrics.expected_calibration_error:.4f}')

# Threshold metrics
threshold = 0.5
exploit_scores  = [cal.predict_proba(r) for r in exploit_feats]
benign_scores   = [cal.predict_proba(r) for r in benign_feats]
tp = sum(1 for s in exploit_scores if s >= threshold)
fp = sum(1 for s in benign_scores  if s >= threshold)
fn = len(exploit_scores) - tp
tn = len(benign_scores)  - fp
precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
fpr       = fp / len(benign_scores) if benign_scores else 0.0
print(f'Threshold={threshold}: P={precision:.4f} R={recall:.4f} F1={f1:.4f} FPR={fpr:.4f}')
print(f'  TP={tp} FP={fp} TN={tn} FN={fn}')

os.makedirs('data/models', exist_ok=True)
cal.save(MODEL_OUT)
print(f'\nSaved calibrator to {MODEL_OUT}')
print(f'Weights: {[round(w,4) for w in cal.weights]}')
print(f'Bias:    {round(cal.bias,4)}')

# Write calibration metrics to a file
cal_metrics = {
    'dataset': {
        'exploit_rows': len(exploit_feats),
        'benign_rows':  len(benign_feats),
        'total':        len(X),
        'data_source':  'real RPC debug_traceTransaction',
    },
    'training': {
        'epochs': 1000, 'learning_rate': 0.05, 'l2': 0.001,
    },
    'metrics': {
        'brier_score': round(metrics.brier_score, 4),
        'ece':         round(metrics.expected_calibration_error, 4),
        'precision':   round(precision, 4),
        'recall':      round(recall, 4),
        'f1':          round(f1, 4),
        'fpr':         round(fpr, 4),
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
        'threshold': threshold,
    },
    'weights': [round(w,6) for w in cal.weights],
    'bias':    round(cal.bias, 6),
    'feature_names': cal.feature_names,
}
with open('data/models/calibrator_metrics.json', 'w') as f:
    json.dump(cal_metrics, f, indent=2)
print('Saved metrics to data/models/calibrator_metrics.json')
