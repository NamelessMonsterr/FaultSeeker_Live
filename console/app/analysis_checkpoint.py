"""Atomic, redacted report snapshots. Recovery preserves evidence, not execution state."""
import json
import os
from pathlib import Path
import re
import tempfile


def _paths(root, run_id):
    if not isinstance(run_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', run_id):
        raise ValueError('Invalid checkpoint run identifier')
    root = Path(root)
    return root / (run_id + '.checkpoint.json'), root / (run_id + '.json')


def _atomic_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            json.dump(value, output, ensure_ascii=True, allow_nan=False)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_checkpoint(root, run_id, report, *, redact):
    path, _ = _paths(root, run_id)
    safe = redact(report)
    if not isinstance(safe, dict) or safe.get('analysis_status') != 'partial':
        raise ValueError('Checkpoint must be an explicitly partial report')
    _atomic_write(path, {'version': 1, 'run_id': run_id, 'report': safe})


def recover_checkpoint(root, run_id):
    path, final = _paths(root, run_id)
    if final.exists():
        return False
    try:
        payload = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return False
    if (not isinstance(payload, dict) or payload.get('version') != 1
            or payload.get('run_id') != run_id or not isinstance(payload.get('report'), dict)):
        return False
    report = payload['report']
    if report.get('analysis_status') != 'partial':
        return False
    report['classification'] = {'rule_verdict': 'INCONCLUSIVE'}
    report['sections'] = {**report.get('sections', {}), 'scoring': 'skipped'}
    report['failure'] = {'kind': 'interrupted', 'message': 'Recovered the last saved checkpoint after interruption.'}
    report.setdefault('limitations', []).append(
        'Recovered checkpoint: later work may be missing. Findings are preliminary, unranked and unverified; execution was not resumed.')
    for name in ('scored_functions', 'evidence_cards', 'priority', 'priority_score', 'calibration'):
        report.pop(name, None)
    _atomic_write(final, report)
    return True
