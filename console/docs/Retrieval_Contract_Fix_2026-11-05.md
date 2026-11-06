# Retrieval-contract correction — 2026-11-05

The reproduced retrieval defects are corrected and the offline gates pass. This does not establish live exploit-localization correctness or recover the missing historical traceback for `25bbf40e7e4f`.

## Changes

- A shared retrieval contract validates request shape, path indexes (including rejecting boolean indexes), frame schema, function identity and the requested contract address before returning call evidence. Cached summaries are resolved against actual frames as well. All call occurrences remain available rather than being identified only by matching parameters.
- Valid leaf calls return an explicitly `available_empty` result. Malformed requests, unknown targets, invalid paths, identity mismatches, absent source and unrecorded balances are explicitly `unavailable`. They cannot silently become an empty trace or an inferred zero balance.
- The generation prompt provides a concrete JSON target-object schema. Supported legacy target aliases normalize through the same validator; no selector is guessed from prose.
- Missing evidence is retained in model context and safe diagnostics. Console output becomes partial/INCONCLUSIVE with missing-evidence coverage. Standalone candidate pipeline output also preserves the unavailable-evidence status rather than losing it during final report assembly. Existing findings are retained, with their scores explicitly unvalidated in that state.
- Candidate pattern navigation validates the declared target. Created-contract groups use the path for each contract rather than reusing the first contract's path.
- The console ships an identical retrieval module and installs it through runtime hooks for the immutable external pipeline as well as the candidate. Hook restoration removes methods added to the immutable class. A regression checks that the standalone and console copies remain byte-identical.
- Saved failures include safe stack locations (file basename, function, line), exception type, and bounded retrieval shape/path diagnostics in `analysis_integrity`. Diagnostic events are also saved. Public failure classification remains compatible. Exception bodies, locals, raw prompts, source bodies and unknown model field names are excluded from the new diagnostics; the existing redactor still applies before persistence.
- Retrieval diagnostics are checkpointed even before an analysis unit completes, preserving the previous completed observations. Stored diagnostic lists are bounded and console omission counts are explicit.

## Regression evidence

New tests were observed failing against the earlier code before corrections:

- Mismatched requested selector accepted at a valid path.
- Same-selector/wrong-address retrieval accepted.
- Invalid path indistinguishable from a valid empty leaf.
- Malformed requests silently omitted rather than explicitly unavailable.
- Retrieval failure leaving an apparently completed console report.
- Missing safe traceback metadata in reports and events.
- Candidate created-contract review reusing the first address's path.
- Candidate pattern review accepting a different contract at its path.
- Standalone Stage 3 dropping unavailable-evidence status.
- Generation prompt lacking the explicit target-object schema.

Older unsafe bounds-test assertions were replaced with assertions for explicit contract errors. Same-address retrieval unit tests now use actual trace frames instead of stubbed retrieval results. Existing public failure-message assertions were retained by placing new diagnostics under `analysis_integrity`, not changing the public `failure` shape.

## Saved Zunami trace fixture

`pipeline-audit-fixes/tests/fixtures/zunami_retrieval_trace.json` contains the saved local canonical trace converted to the legacy representation, with its original source SHA256 and recorded provenance. It was not fetched again, relabelled as independently complete, or changed to match an expected exploit result. Its source declares `completeness_proven: false`.

The actual TraceAnalyzer and retrieval methods check all **785 memo paths across 243 function/address keys** against matching frames. A separate test corrupts a copy of the price-cache call's path and verifies explicit identity mismatch rather than returning a different call. This is structural/provenance regression coverage, not ABI verification or an exploit-accuracy benchmark.

## Exact test commands and final results

Console working directory:
`C:\Users\91701\Downloads\faultseeker-demo-console-main\FaultSeeker_Live`

```powershell
$env:FAULTSEEKER_TEST_PIPELINE_REPO='C:\Users\91701\Downloads\faultseeker-demo-console-main\pipeline-pin-offline-verified'
$env:FAULTSEEKER_TEST_CANDIDATE_REPO='C:\Users\91701\Downloads\faultseeker-demo-console-main\pipeline-audit-fixes'
$env:FAULTSEEKER_TEST_CANDIDATE_SHA='bac131efb08752772b129c571965042e4e5b55bd'
python -B tests/run_offline.py --tb=short -rs
```

**495 executed, 495 passed, 0 failed, 0 skipped**, 81.24 seconds. Includes isolated imports from the real immutable-pin and candidate checkouts with mocked HTTP; not Docker or real provider verification.

Pipeline working directory:
`C:\Users\91701\Downloads\faultseeker-demo-console-main\pipeline-audit-fixes`

```powershell
python -B tests/run_offline_depth.py tests
```

**562 executed, 562 passed, 0 failed, 0 skipped**, 77.28 seconds.

From the console:

```powershell
node tests/run_frontend_offline.cjs
python -B tools/sync_static.py --check
git diff --check
git -C '..\pipeline-audit-fixes' diff --check
```

Frontend: **29 executed, 29 passed, 0 failed, 0 skipped**, 138.2829 milliseconds. This is an offline DOM harness, not a new browser or live model test. Static synchronization and both diff checks passed.

The immutable pipeline checkout remains at `fb57c3fad63784b7a63dc7fdf1845364c76ce0b7`. Candidate-only changes have not been published into that Docker pin. No dependency installation, push, merge or deployment was performed.

## Live command disposition and limits

The supplied `run_complete_zunami_validation.py` command was inspected but not executed. One duplicate-prevention request found another run, `93c038adc3d6`, active on port 8766. That server/run was not restarted, cancelled or continuously monitored. Its use of this exact completed code snapshot is not established. A fresh test requires an idle server and a fresh process importing these corrections.

Unavailable requested evidence conservatively leaves the report partial; workflow completion is not a correctness pass. Provider trace completeness, historical ABI/source binding, model conclusions, and the true Zunami localization still require the bounded live correctness check. No raw API response or traceback exists to establish the exact historical `25bbf40e7e4f` failing expression retroactively.

Kluster tooling was unavailable; no Kluster review is claimed.
