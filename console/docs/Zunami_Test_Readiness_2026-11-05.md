# Zunami local test readiness — 2026-11-05

Status: offline gates passed; ready for one bounded local end-to-end validation. A successful, ground-truth-correct live run is NOT established. No live RPC/model calls, installs, pushes, merges or deployments were performed for this remediation.

## Working trees and environment

- Console: `FaultSeeker_Live`, branch `fix/all-chain-validation`, base HEAD `2830235b18e5f99b7d0700ad8e9fb372345b8fec`, with uncommitted corrections.
- Development pipeline: `pipeline-audit-fixes`, branch `fix/combined-audit-remediation`, base HEAD `bac131efb08752772b129c571965042e4e5b55bd`, with uncommitted corrections.
- Immutable pipeline checkout: `pipeline-pin-offline-verified`, HEAD `fb57c3fad63784b7a63dc7fdf1845364c76ce0b7`, clean and unmodified.
- Installed environment: Python 3.11.9, OpenAI SDK 2.36.0, HTTPX 0.28.1. No actual OpenAI 3.37/httpx2 compatibility run is claimed.

## Corrections and evidence

1. **Shared-budget invalid-completion recovery.** The existing three-pillar changes classify eligible unusable completions for bounded recovery inside `ModelEndpointSession`. Recovery consumes the shared retry/time budget; wrapper-specific retry ladders and silent Mercury/Itera input slicing are absent. Removed the remaining nonsticky invalid-response bypass: the old pinned agent swallowed nonretryable failures into `{}`. Mocked HTTP regressions reproduced that failure for invalid roles and missing messages, then passed after correction. Null/empty-response exhaustion remains explicit and terminal rather than a valid empty finding set.

2. **Per-unit snapshots before a later failure.** Runtime hooks around the real pinned/candidate function-analysis entry points snapshot returned analysis units before the caller advances to the next function. Evidence from separate units is merged; batch metadata no longer overwrites accumulated observations. The snapshot labels conclusions `unranked/unverified`; no calibrated score or exploit verification is invented.

3. **Atomic, redacted persistence.** `app/analysis_checkpoint.py` writes a versioned, run-bound checkpoint through a temporary file, flush/fsync and atomic replacement. The server redacts credentials before data reaches disk. The prior checkpoint survives a failed replacement. Recovery rejects mismatched run IDs and never replaces an existing final report.

4. **Interruption recovery.** The worker guard recovers a checkpoint before publishing history if a worker dies without a final result. Startup history reconciliation also restores interrupted snapshots. Recovery remains partial and INCONCLUSIVE, with scoring skipped. Tested through the actual parent guard, fresh-reader recovery, server restart reconciliation and a subprocess using abrupt `os._exit` with networking forbidden.

5. **Visible preliminary observations.** Both server and generated static UI render retained observations separately, labelled unranked and unverified, with pagination and text-safe rendering. They do not become ordinary scored findings.

6. **Finding identity integrity.** Candidate analysis no longer treats a readiness-only metadata response as an empty successful finding set. Address-only findings resolve only when the observed function-call memo contains one unique matching function/address pair. Task-text regex guesses are removed; ambiguous or unobserved identities fail explicitly. `{}` remains an allowed explicit no-finding response.

7. **Real import isolation for integration tests.** Removed collection-time candidate imports from the three-pillar tests. The pinned fixture clears and restores pipeline modules and verifies their loaded path belongs to the requested checkout. The candidate fixture independently isolates its modules. A passing fixture SHA alone is no longer used as proof that the correct module was imported.

## Exact verification

From `C:\Users\91701\Downloads\faultseeker-demo-console-main\FaultSeeker_Live`:

```powershell
$env:FAULTSEEKER_TEST_PIPELINE_REPO='C:\Users\91701\Downloads\faultseeker-demo-console-main\pipeline-pin-offline-verified'
$env:FAULTSEEKER_TEST_CANDIDATE_REPO='C:\Users\91701\Downloads\faultseeker-demo-console-main\pipeline-audit-fixes'
$env:FAULTSEEKER_TEST_CANDIDATE_SHA='bac131efb08752772b129c571965042e4e5b55bd'
python -B tests/run_offline.py --tb=short -rs
```

Final result: **490 executed, 490 passed, 0 failed, 0 skipped**, 40.95 seconds. This includes 52 cases collected in `test_pinned_pipeline.py` and `test_candidate_pipeline_transport.py`. Integration uses the real local pipeline code with mocked HTTP and controlled task boundaries; it is not live provider or Docker execution.

From `C:\Users\91701\Downloads\faultseeker-demo-console-main\pipeline-audit-fixes`:

```powershell
python -B tests/run_offline_depth.py tests
```

Result: **533 executed, 533 passed, 0 failed, 0 skipped**, 31.05 seconds.

From the console:

```powershell
node tests/run_frontend_offline.cjs
python -B tools/sync_static.py --check
git diff --check
git -C '..\pipeline-audit-fixes' diff --check
```

Frontend result: **28 executed, 28 passed, 0 failed, 0 skipped**, 151.983 milliseconds on the final invocation. These are offline DOM-harness tests, not a fresh browser/live-server test. Static synchronization and both diff checks passed.

The new regressions were observed failing before their fixes: lost first-function checkpoint on both pipeline paths, readiness metadata and ambiguous target guesses, batch-end evidence overwrite, malformed completion swallowed by the pinned agent, and preliminary observations absent from the UI. An initial complete-suite invocation exposed two publication tests whose isolated runtime is intentionally None; the configuration helper now preserves that existing optional-runtime contract without weakening their assertions.

## Boundaries for the complete test

- Start a fresh local server so the worker imports these corrections. Do not reuse an old process or run another test concurrently.
- Use the approved Mercury API route and existing secure credentials; do not switch providers or increase budgets automatically after failures.
- Validate Ethereum transaction `0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb` as Zunami, not Hedgey. Compare the final target, trace/source provenance and exploit mechanism against the documented ground truth. A completed status, high confidence or merely mentioning a related oracle is insufficient.
- Oversized complete input still fails explicitly. The tests do not prove every request a live model might generate fits the input policy.
- Checkpoints preserve completed observations for inspection; they do NOT automatically resume execution, rank partial findings or certify vulnerability correctness. Recovery requires the same files to remain available; persistence across destruction of a hosted container/volume is not established.
- The exact Docker-pinned pipeline was exercised through integration hooks, not modified or run inside Docker. Candidate-only pipeline changes are not thereby deployed into the Docker pin. No chain has a verified production correctness pass as a result of these offline tests.
- Kluster is unavailable in the enabled tool inventory. Its requested review could not run; no Kluster verification is claimed.
