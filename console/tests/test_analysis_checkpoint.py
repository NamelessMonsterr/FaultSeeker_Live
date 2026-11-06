import json

import pytest

from app import analysis_checkpoint as store


def report():
    return {'analysis_status': 'partial', 'classification': {'rule_verdict': 'INCONCLUSIVE'},
            'sections': {'scoring': 'skipped'},
            'preliminary_findings': [{'target': 'test_target', 'status': 'unranked/unverified',
                                      'evidence': ['dummy-secret observation']}],
            'trace_provenance': {'transaction_hash': '0x'+'a'*64}}


def test_checkpoint_survives_new_reader_and_redacts_before_disk(tmp_path):
    store.save_checkpoint(tmp_path, 'abc123', report(),
        redact=lambda value: json.loads(json.dumps(value).replace('dummy-secret', '***')))
    assert 'dummy-secret' not in (tmp_path/'abc123.checkpoint.json').read_text()
    assert store.recover_checkpoint(tmp_path, 'abc123')
    result = json.loads((tmp_path/'abc123.json').read_text())
    assert result['analysis_status'] == 'partial'
    assert result['preliminary_findings'][0]['status'] == 'unranked/unverified'
    assert result['trace_provenance']['transaction_hash'] == '0x'+'a'*64
    assert result['failure']['kind'] == 'interrupted'


def test_atomic_failure_keeps_prior_checkpoint(tmp_path, monkeypatch):
    store.save_checkpoint(tmp_path, 'abc123', report(), redact=lambda value: value)
    prior = (tmp_path/'abc123.checkpoint.json').read_bytes()
    def fail(*args):
        raise OSError('simulated interrupted replacement')
    monkeypatch.setattr(store.os, 'replace', fail)
    with pytest.raises(OSError):
        store.save_checkpoint(tmp_path, 'abc123', {'analysis_status': 'partial'}, redact=lambda value: value)
    assert (tmp_path/'abc123.checkpoint.json').read_bytes() == prior


def test_checkpoint_does_not_replace_final_report_or_accept_wrong_run(tmp_path):
    store.save_checkpoint(tmp_path, 'abc123', report(), redact=lambda value: value)
    (tmp_path/'abc123.json').write_text('{"analysis_status":"completed"}')
    assert not store.recover_checkpoint(tmp_path, 'abc123')
    assert json.loads((tmp_path/'abc123.json').read_text())['analysis_status'] == 'completed'
    (tmp_path/'other.checkpoint.json').write_bytes((tmp_path/'abc123.checkpoint.json').read_bytes())
    assert not store.recover_checkpoint(tmp_path, 'other')
    with pytest.raises(ValueError):
        store.recover_checkpoint(tmp_path, '../outside')


def test_server_restart_recovers_checkpoint_and_honest_history(tmp_path, monkeypatch):
    from app import server
    monkeypatch.setattr(server, 'RUNS_DIR', str(tmp_path))
    monkeypatch.setattr(server, 'HISTORY_PATH', str(tmp_path/'index.json'))
    monkeypatch.setattr(server, 'runs', {})
    store.save_checkpoint(tmp_path, 'abc123', report(), redact=lambda value: value)
    (tmp_path/'index.json').write_text(json.dumps([{'run_id': 'abc123', 'status': 'running'}]))
    server._reconcile_history()
    assert json.loads((tmp_path/'index.json').read_text())[0]['status'] == 'interrupted'
    assert json.loads((tmp_path/'abc123.json').read_text())['analysis_status'] == 'partial'


def test_abrupt_subprocess_exit_leaves_recoverable_checkpoint(tmp_path):
    import subprocess
    import sys
    from pathlib import Path
    code = (
        'import sys,os,json\n'
        'def deny(event,args):\n'
        ' if event.startswith("socket."): raise RuntimeError("network forbidden")\n'
        'sys.addaudithook(deny)\n'
        'from app.analysis_checkpoint import save_checkpoint\n'
        f'save_checkpoint({str(tmp_path)!r}, "abrupt", {report()!r}, redact=lambda value:value)\n'
        'os._exit(23)\n')
    result = subprocess.run([sys.executable, '-B', '-c', code],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=15)
    assert result.returncode == 23
    assert not (tmp_path/'abrupt.json').exists()
    assert store.recover_checkpoint(tmp_path, 'abrupt')
    assert json.loads((tmp_path/'abrupt.json').read_text())['preliminary_findings']
