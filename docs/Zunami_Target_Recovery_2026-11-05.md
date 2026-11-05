# Unobserved finding target recovery

## Verified incident

The saved report for run `9e7062303bb3` records `analysis_status: partial`, `failure.kind: retrieval_contract`, and safe diagnostics with reason `unobserved_target`. The saved stack reaches `_update_potentially_vulnerable_function` → `_get_function_call_depth` → `_observed_calls`. Seventeen preliminary findings are present. This establishes checkpoint survival, not zero loss of in-flight work or successful exploit localization.

## Implemented behavior

- Keep strict trace identity/depth validation. Never return fabricated depth zero or guess a selector/address.
- An unobserved-target finding reply gets at most one repair request. The full original task is retained, with bounded observed target examples (not falsely described as exhaustive).
- In the console runtime, reserve that repair atomically from the same `ModelEndpointSession.retries_left` allowance used by transport recovery. A failed endpoint, exhausted allowance or spent time budget cannot create a new repair ladder. HTTP execution continues through the existing shared time accounting and SDK retry override.
- If the repaired reply remains unobserved, atomically reject that reply's findings, retain existing accepted findings, record an explicit unresolved observation, and allow the loop/caller to continue independent work. No invalid target is scored and no valid subset of the rejected reply is silently promoted as complete.
- Rejected observations contain reason, status, attempt number, safe request shape and SHA-256 of the reply. Raw response bodies, evidence text and credentials are not copied into rejection diagnostics. Retention is bounded (100 local / 200 runtime records) with omission counts; these are diagnostic records, not full raw-response archives.
- A successful repair is disclosed as recovered. A later transport/parse/other exception is disclosed as repair_failed and still propagates. Corrupted paths/identity mismatches remain terminal contract errors; this patch does not hide trace corruption.
- Unresolved observations increment existing unavailable-evidence tracking. Console checkpoints/final reporting and standalone pipeline reporting preserve partial/INCONCLUSIVE status; any scores from independent work remain unverified. The UI continues to show the integrity records and incomplete status.
- Temporary query interception is restored on every exit, including exceptions. The immutable pipeline checkout is unchanged; runtime hooks supply the shared helper, while actual candidate-analyzer behavior is tested separately.

## Files

- `pipeline-audit-fixes/faultseeker/function_analysis/retrieval_contract.py` and identical `FaultSeeker_Live/app/retrieval_contract.py`: bounded recovery and safe rejection records.
- `pipeline-audit-fixes/faultseeker/function_analysis/function_analyzer.py`: separate one-attempt parsing from recovery; reset/report rejection metadata per run.
- `FaultSeeker_Live/app/pipeline_guards.py`: shared allowance reservation, integration hooks, checkpoint/final integrity records.
- `pipeline-audit-fixes/faultseeker/core/pipeline.py`: preserve rejection records in standalone reports.
- `pipeline-audit-fixes/tests/test_finding_target_recovery.py`: real analyzer with controlled model replies, strict trace binding and exception propagation.
- Candidate transport integration, real Stage 3 reporting and frontend regressions cover shared-budget consumption, retained independent findings and partial-state disclosure. One prompt-only test fixture was initialized with the same empty finding map created by the real constructor; its assertions were retained.

## Executed verification

From `FaultSeeker_Live`:

```powershell
$env:FAULTSEEKER_TEST_PIPELINE_REPO='C:\Users\91701\Downloads\faultseeker-demo-console-main\pipeline-pin-offline-verified'
$env:FAULTSEEKER_TEST_CANDIDATE_REPO='C:\Users\91701\Downloads\faultseeker-demo-console-main\pipeline-audit-fixes'
$env:FAULTSEEKER_TEST_CANDIDATE_SHA='bac131efb08752772b129c571965042e4e5b55bd'
python -B tests/run_offline.py --tb=short -rs
```

**498 passed, 0 failed, 0 skipped** (23.65s), including enabled local exact-pin and candidate integration tests. External HTTP is mocked and network blocked; this is not live-provider or Docker-container verification.

From `pipeline-audit-fixes`:

```powershell
python -B tests/run_offline_depth.py tests
```

**582 passed, 0 failed, 0 skipped** (16.81s).

From `FaultSeeker_Live`:

```powershell
node tests/run_frontend_offline.cjs
python -B tools/sync_static.py --check
git diff --check
```

Frontend: **30 passed, 0 failed, 0 skipped**. Static-copy check passed. Diff checks passed in both repositories. Kluster tools are unavailable; no Kluster review is claimed.

No live inference, live RPC, server restart, new validation run, commit, push, merge or deployment was performed for this correction. Existing dirty branches are retained. A fresh live process is required before testing this change; the old process does not prove it loaded the new code.

## Limits

This fixes handling of unobserved finding identities; it does not establish why the model invented that identity or that Zunami's exploit mechanism was correctly found. Other malformed finding formats still fail explicitly. No workload/ranking redesign or calibration weakening was added. The full live run remains unverified.
