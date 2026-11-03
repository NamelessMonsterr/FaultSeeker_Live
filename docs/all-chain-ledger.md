# All-chain analysis evidence ledger

## Current status

Draft PR: https://github.com/NamelessMonsterr/FaultSeeker_Live/pull/5, base development main, head fix/all-chain-validation. Created and verified at head 1980a692638c6bdccbc398dbd8e63da1a02f7ac4; subsequent ledger updates stay on that fix branch. Repository/base were checked in GitHub before creation. Render was rechecked immediately before publication: main1 auto-deploy On Commit, PR previews Off. No merge or deployment; Instinct review and user repo/base/deployment approvals remain outstanding.

Current result: 330 offline backend passed / 0 skipped against the exact pinned pipeline; 13 frontend passed. Two live Ethereum attempts failed in preflight and persisted honestly; zero full analyses or correctness passes across 16 chains on either build. No active run. GPT is blocked by current OAuth refresh_token_reused evidence; Qwen had one timeout with cause unverified. User explicitly approved the exact pipeline download; source acquisition and the previous 31 integration skips are now resolved. The corrected development process has no configured Itera key; no corrected live inference is claimed.

Sections below preserve the chronological evidence and earlier snapshots; later terminal outcomes supersede pending states. The broader goal remains incomplete.

## Current scope and identity (2026-11-02)

Goal: a real, suitable transaction analysis on development and approved live for every chain advertised by the console. A pass requires completed stages, scored functions, evidence, persisted/reopened history and conclusions checked against available ground truth. No chain has passed this cycle yet. At the initial baseline no model requests had been made; the two later attempts are recorded below.

- Development baseline: `aacec55916e94325d3fe5753db22d65969926e08`; working branch `fix/all-chain-validation`.
- Render service: `srv-dbcntfcs728c73fm1tsg`, `faultseeker-live`.
- Render dashboard directly confirms branch `main1`, Live deployment `dep-dbg6uuvb9u1s73fv8sq0`, console `947db7d508f5b93eb603e075b77a77408a91779d`.
- Live source Dockerfile blob: `bb30ad17804159d2d0c6c5db47080575cc4eaf8c`; pipeline pin `fb57c3fad63784b7a63dc7fdf1845364c76ce0b7`, with detached checkout and HEAD equality enforcement. Runtime pipeline SHA is not directly attested; build view reports Build not found.
- Render auto-deploy: On Commit for main1. PR previews: Off. No deployment/settings changes performed.
- Live health GET: HTTP 200, `{ "ok": true }`; unauthenticated homepage redirects to /gate. These are reachability checks, not analysis passes.
- Render environment names checked without revealing values: ETH/BSC RPC settings, DEMO_GATE_PASSWORD, model budget, history token, GOOGLE_API_KEY, ITERA_API_KEY, OPENAI_API_KEY and XAI_API_KEY. No Blockscout PRO key is listed. Configured names do not establish endpoint capability, balance or free access.
- Model RPM/TPM limits and reset state have not been verified. Model calls must wait for that check; no key rotation to evade quota.

## Coverage

Each row covers both builds. DEV/LIVE BLOCKED means no full run has started, not that an attempted transaction failed. Hashes remain unset until selected and verified on the matching chain. No arbitrary transfers will be used as function-analysis substitutes.

| Chain | Development trace adapter in source | Hash | Dev / live status | Stage outcomes / verdict / persistence | Timing / evidence |
| --- | --- | --- | --- | --- | --- |
| eth | Blockscout instance; RPC trace | 0x2606d459a50ca4920722a111745c2eeced1d8a01ff25ee762e22d5d4b1595739 | DEV BLOCKED / LIVE 2 FAILED PREFLIGHT | all analysis stages skipped; INCONCLUSIVE; both reports reopened | L-ETH-001 / L-ETH-002 below; no current on-chain verification |
| bsc | RPC trace required | unset | BLOCKED / BLOCKED | not run | provider trace capability pending |
| polygon | RPC trace required | unset | BLOCKED / BLOCKED | not run | free route unverified |
| arbitrum | RPC trace required | unset | BLOCKED / BLOCKED | not run | free route unverified |
| optimism | Blockscout instance; RPC trace | unset | BLOCKED / BLOCKED | not run | current endpoint capability unverified |
| avalanche | RPC trace required | unset | BLOCKED / BLOCKED | not run | free route unverified |
| base | RPC trace required | unset | BLOCKED / BLOCKED | not run | source excludes PRO free route; current plan not verified |
| fantom | RPC trace required | unset | BLOCKED / BLOCKED | not run | free route unverified |
| zksync | RPC trace required | unset | BLOCKED / BLOCKED | not run | source excludes PRO free route; current plan not verified |
| linea | RPC trace required | unset | BLOCKED / BLOCKED | not run | free route unverified |
| scroll | Blockscout PRO adapter; RPC trace | unset | BLOCKED / BLOCKED | not run | no PRO variable listed in Render |
| gnosis | Blockscout PRO adapter; RPC trace | unset | BLOCKED / BLOCKED | not run | no PRO variable listed in Render |
| celo | Blockscout PRO adapter; RPC trace | unset | BLOCKED / BLOCKED | not run | no PRO variable listed in Render |
| cronos | RPC trace required | unset | BLOCKED / BLOCKED | not run | free route unverified |
| moonbeam | RPC trace required | unset | BLOCKED / BLOCKED | not run | free route unverified |
| aurora | Blockscout instance; RPC trace | unset | BLOCKED / BLOCKED | not run | current endpoint capability unverified |

Explorer adapters are present only in development. Source presence is not provider availability proof, trace completeness proof or a correctness pass. Ground truth remains unassessed for all rows. Exact per-run console/pipeline SHA, model route, hash, stage outcomes, timing and artifact paths will be recorded when a real run is authorized by verified free-route limits and configured access.

## Baseline reproduction

Commands use installed dependencies, temporary storage, dummy credentials and blocked external networking:

- `python -B tests/run_offline.py --tb=short -rs`: 288 passed, 1 failed, 31 skipped (320 collected; 289 executed), 12.44 seconds.
- Failure: `tests/test_packaging.py::test_static_surface_matches_generated_server_sources`: api/config checkout contains CRLF, generator emits LF. core.autocrlf=true and no existing eol attribute. Content is generated deterministically; the failure is reproducible checkout normalization, not a forensic/provider failure.
- Fix: explicit `api/config text eol=lf` repository attribute. Existing byte comparison is retained as the regression; static generator rewrites local config to its expected bytes.
- `node tests/run_frontend_offline.cjs`: 13 passed, 0 failed, 0 skipped.
- 31 backend skips require the exact pinned external pipeline. Existing local checkout is f92a5ab20a878903f99d4e83b1f5908235a6fd55 and lacks the pinned object. No skip is counted as verified integration.

After the line-ending fix: `python -B tests/run_offline.py --tb=short -rs` returned **289 passed, 0 failed, 31 skipped**, 11.47 seconds. `python -B tools/sync_static.py --check` and `git diff --check` passed. These results do not include real transaction analyses or the skipped external-pipeline integrations.

## Provider limits checked

Itera's official https://iteracompute.com/free/ page, checked 2026-11-02, publishes Qwen3.8-27B free tier: 30M tokens/month, 160,000 TPM, 128K total context, maximum 8,192 output tokens; input/output/reasoning count across all account keys. Reset is first day of month at 00:00 UTC. There is no automatic paid overage; exhausted monthly allowance returns 429. Free capacity may queue. No numeric RPM or current account remaining allowance was established from this page. Account-specific limits/usage remain unverified; no model requests were sent.

## Dependency acquisition approval blocker

Automatic approval review rejected a temporary checkout of NamelessMonsterr/FaultSeeker- because the earlier no-download restriction is retained. The checkout did not execute. A narrowly scoped user approval request is pending for the exact pinned source only, without installs or changes to live branches. Do not bypass the rejection using another download mechanism.

## Audit cycle: conflicting explorer frame hashes

Confirmed defect in development `app/explorer_trace.py::rows_from_parity`: `{**row, **ident}` silently replaced a provider-supplied transactionHash/blockHash even when it contradicted the independently read RPC transaction. Root from/to/input and tree shape checks alone did not reject that contradiction. This could turn mixed/wrong provider data into apparently verified provenance; no real historical run is asserted to have suffered it.

Reproduction uses copies of the existing recorded Ethereum trace fixture, changes one hash in root or child, and expects refusal. `python -B tests/run_offline.py tests/test_explorer_trace.py -k conflicting_frame_provenance --tb=short` produced **4 failed, 321 deselected** before the fix: all four unexpectedly accepted the contradictory identity. No fixture files or expected ground truth were rewritten.

Fix: reject any non-null provider transactionHash/blockHash differing from RPC identity before constructing bound rows. Missing optional hashes remain allowed; matching hashes are accepted case-insensitively and canonicalized to the RPC representation. Five new regression cases cover four conflicts plus matching explicit identity. Existing root/chain/tree checks remain intact.

After fix, `python -B tests/run_offline.py --tb=short -rs`: **294 passed, 0 failed, 31 skipped**, 7.66 seconds (325 collected, 294 executed). The pipeline-dependent skips remain blocked by source acquisition approval. These local adapter results do not prove the full console flow, on-chain correctness or live deployment behavior. Live console SHA remains 947db7d508f5b93eb603e075b77a77408a91779d; it has not received this development fix.

The user delegated the checkout decision, but automatic approval review rejected a second attempt because that answer did not explicitly lift the no-download restriction. No download occurred; explicit approval is still required. Continue only with available local files until that changes.

## Resume point

Verify the line-ending fix, obtain exact pinned pipeline for integration, verify free model quotas, authenticate live app without exposing its gate password, then select and verify an Ethereum contract transaction as the first full-flow candidate. Preserve current live revision; no merge/deploy before Instinct review, user repo/base check and explicit PR deployment approval. No live model conclusions or historical 401 root cause are claimed.

## Live read-only UI evidence E-live-ui-001 (2026-11-02)

Chrome profile reconnected and Render remained authenticated. Existing live app initially displayed Render's cold-start page, then reached its gate. Gate credential was used only through the browser for this app; no value was printed or saved to the repository. Automation initially read label text rather than the form value and had rejected attempts; these are not evidence of an application authentication defect. The copied clipboard value and transient credential variables were cleared. Authenticated setup and archive subsequently loaded.

Live Network menu lists all 16 chains in the coverage table. Recent runs opened and persisted report `6edfc282c9cd` was reopened through its View report control. No Analyze transaction action was triggered. This historical run is dated 2026-10-24 and is NOT a new live correctness pass for the current deployment.

Observed report fields:

- Transaction: Ethereum `0x2606d459a50ca4920722a111745c2eeced1d8a01ff25ee762e22d5d4b1595739`.
- analysis_status=completed; reported verdict INCONCLUSIVE; analysis_mode=live-pipeline; stage_completed=stage-3.
- One scored function and one evidence card, both rendered; selector `0xe32a9a37`, address `0xc793113f1548b97e37c409f39244ee44241bf2b3`.
- trace_provenance: structured_rpc_or_cache; eth_getTransactionByHash + eth_chainId identity cross-check; block hash `0xadc062e388f2cb069f54f398a7b26c41c8484004deba471c78864a5c732363d3`; block number `0x12c69d2`; abi_verified=false.
- analysis_integrity: calldata_selector identities; five ranked selector/address pairs; unverified_targets empty. No top-level SHA/version/revision fields are present.
- Historical confidence is internally inconsistent: overall=0.9941 while its explanation says 60.2% (moderate). Preserve this evidence; root cause in the historical pipeline/calibration path is not established and no correction is claimed.

Rendered report was visually inspected in the browser. Evidence is this observation record plus the persisted run ID on the existing live service; no secret-bearing screenshot or report download was written. Reopening establishes UI/history availability only, not current analysis-stage execution, source correctness or on-chain truth.

Itera usage dashboard at https://platform.iteracompute.com/ redirects to /sign-in. No account-specific balance, remaining quota or RPM verified. Google sign-in explicitly notes automatic account creation if absent; no account creation or terms acceptance attempted. User must sign into the existing account that owns the configured Itera key before account quota verification can proceed. Model requests remain zero.

Updated resume point: authenticated live UI/history inspection is complete at this limited scope; exact-pipeline download approval and existing Itera account quota access remain prerequisites for the first new full transaction run. Local line-ending and provenance fixes are saved at af55883355a3bf7262b7e1c5864112ca5e6bfab1 and 8b895b02363b1dbca4316b7d11d69081effcc2d3; neither is deployed. Real analysis passes remain 0/16 development and 0/16 live.

## Provider correction: GPT proxy only (2026-11-02)

User clarified that tests should use the existing GPT proxy only. This supersedes the Itera testing plan and Itera-sign-in prerequisite above. No Itera model calls were made; its dashboard/limits were read only. No provider configuration was changed. Keep gpt-6.1-sol-low for planned model calls.

Render service switcher identified codex-proxy-render, service srv-dbd0se6q1p3s73dip3s0, endpoint https://codex-proxy-render.onrender.com/. Render identifies deployed wrapper repository NamelessMonsterr/codex-proxy-render, branch main, commit 070d9d61d3bd9140a5ea71707582781a32ce65f3. Proxy environment variable names are ADMIN_API_KEY, CODEX_AUTH_JSON and ENV; no values were displayed.

The wrapper Dockerfile at that exact commit clones dvcrn/codex-oauth-proxy with --depth 1 and no source revision pin. Thus the wrapper SHA does not identify the built upstream implementation revision. No proxy changes or deployments were made.

The proxy root showed Render's application-loading screen on the first browser request. After startup, its documented /health endpoint returned {"status":"ok"}. This confirms current reachability only; it does not prove model authentication, remaining Codex allowance or the cause of historical 502 failures. No continuous keep-warm service was introduced.

Current upstream documentation (https://github.com/dvcrn/codex-oauth-proxy) describes Codex OAuth forwarding, authenticated /v1/models and /health. Its current documentation is not proof of the unpinned implementation built into this older deployment. Remaining GPT/Codex quota and request limits have not been verified; no model calls started. The Itera quota evidence must not be used as allowance evidence for GPT.

Resume: inspect the GPT proxy's account usage/readiness without model charges, resolve exact pipeline source acquisition approval, then run the first suitable transaction with the GPT proxy only. Real dev/live passes remain zero.

## Live attempt L-ETH-001: 70794a87be5d (2026-11-02)

User subsequently authorized Qwen if needed, retaining GPT proxy as primary, and instructed stopping repeated credit-dashboard checks to focus on execution. No provider settings changed. Render's configured Itera key suffix matched the key label on the inspected account; account dashboard showed 30M available, zero used/reserved, 128K context and 160K TPM. This does not establish GPT limits. Configured primary Ethereum RPC was classified privately as QuickNode; no endpoint value recorded. No payments, upgrades or quota-evading key rotation authorized or performed.

Exactly one new live Analyze transaction action was submitted with Ethereum hash `0x2606d459a50ca4920722a111745c2eeced1d8a01ff25ee762e22d5d4b1595739`, model gpt-6.1-sol-low, blank caller keys, blank caller RPC and replay=false. The transaction is a contract-call candidate with an existing recorded trace fixture; this attempt must independently establish current provenance before correctness is claimed.

Live console: 947db7d508f5b93eb603e075b77a77408a91779d. Configured pipeline pin: fb57c3fad63784b7a63dc7fdf1845364c76ce0b7 (runtime SHA not directly attested). Run ID: 70794a87be5d. Proxy wrapper: 070d9d61d3bd9140a5ea71707582781a32ce65f3, upstream implementation revision unpinned/unknown. First observed elapsed 00:21; UI explicitly waiting on model endpoint in preflight with retry-in-1s within shared budget. No new request was submitted to restart or duplicate the run. Outcome pending; no passed stage, score or persisted result claimed yet.

Counts so far: new live attempts 1, completed/correctness passes 0; development real attempts 0. Historical report reopen is separate UI evidence and excluded from analysis pass counts.

### L-ETH-001 terminal result

Persisted report for 70794a87be5d is failed / INCONCLUSIVE, stage_completed=none; deterministic_checks, function_analysis and scoring all skipped. Model endpoint summary reports upstream_http HTTP 503 in preflight, 26 attempts, preflight ok=0/failed=26, transport_seconds=116.727, shared budget=2400 seconds, retries_remaining=3 and reported token counters all zero. UI reached report retrieval around elapsed 02:13 and rendered the failed report rather than HTML or a successful verdict. Reported zero token counters do not independently establish provider billing.

Source at the deployed console SHA configures default preflight timeout=120 seconds, explaining the approximately two-minute preflight window. Its preflight retries do not consume the analysis retry counter. No additional GPT analysis was submitted after this failure.

### Current GPT proxy auth evidence

Read-only Render application logs for proxy service srv-dbd0se6q1p3s73dip3s0 (last-hour view) contain repeated failed-to-refresh messages and the structured OAuth error code refresh_token_reused, including the phrase already been used; HTTP 401/Unauthorized signals are also present. Raw log bodies and credentials were not printed or saved. Evidence location: Render service logs; observation summarized here.

This establishes a current OAuth refresh failure despite a successful /health response and supports an auth-related cause for the newly observed 503 preflight failure. It does not prove every 503 has that cause or solve historical 401/502 incidents. Reauthentication/replacement of the proxy's stored OAuth credentials requires account-owner action; no credentials were rotated, edited or refreshed manually by this session. Stop further GPT calls until resolved.

## Live attempt L-ETH-002: 8692ff7dc377 (2026-11-02)

After L-ETH-001 reached its persisted terminal failed report, submitted exactly one separate live request for the same Ethereum hash with model itera/qwen3.8-27b, blank caller keys/RPC and replay=false. User explicitly authorized Qwen if needed and stopping repeated quota dashboard checks. This is a separate provider test after an outage, not quota-evasion/key cycling or a silent fallback. Exact console/configured pipeline SHAs remain as recorded for L-ETH-001.

Run ID 8692ff7dc377. At elapsed 00:50 UI reports waiting on model endpoint in preflight; no stage or result claimed complete. Outcome pending; no duplicate/restart request submitted. Counts: live attempts 2, terminal failed 1, active 1, complete/correctness passes 0; development real attempts 0.

### L-ETH-002 terminal result and persistence checks

Persisted Qwen report is failed / INCONCLUSIVE, stage_completed=none. All three sections are skipped. Endpoint summary: attempts=1; preflight failed=1/ok=0; failure kind timeout, no HTTP status; transport_seconds=123.983; shared budget=6000 seconds; retries_remaining=3; reported token counters zero. UI elapsed stopped at 02:16. No model request was resubmitted after timeout.

Itera Logs initially hid the new failure under its default filter. Selecting All requests exposed request a3d3a245-0c3a-45e8-8c68-14c99c9bb40d, dated 2 Nov 2026 16:48 UTC, qwen/qwen3.8-27b, FAILED, zero input/cache/output counters and displayed charge $0.0000. This correlates with the console run's 16:48:20 UTC start. Server-side cause was not established from the available request-detail UI; do not label it a quota rejection, queue timeout or application defect without further evidence.

Live history now records 70794a87be5d (GPT) at 2026-11-02T16:45:06+00:00 and 8692ff7dc377 (Qwen) at 2026-11-02T16:48:20+00:00, both error. Reopened each from its own View report control: matching run ID, INCONCLUSIVE, correct 503/timeout classification and skipped stages persisted. GPT report showed no rendered raw HTML error. The rendered Qwen terminal report was visually inspected; history reopening uses status error while initial report status was failed, both visibly inconclusive.

Final attempt counts for this cycle: **2 new live runs, 2 terminal failures, 0 active runs, 0 completed transaction analyses, 0 correctness passes**. Reported preflight HTTP attempts total 27 (26 GPT + 1 Qwen), not 27 separate analyses. Both failed before deterministic/trace/function/scoring work; no current on-chain verification or source-ground-truth check completed. Development real attempts remain zero. Local offline backend baseline remains 294 passed / 31 skipped; frontend remains 13 passed. These are separate evidence categories.

User directed stopping repeated credit-dashboard checks; no more such checks were made. GPT calls stopped after proxy refresh_token_reused evidence. Qwen calls stopped after its single timeout. Restoring GPT requires owner reauthentication, and additional Qwen retries must be justified by changed external state or a diagnosed cause. No credential changes, payments, installs, deployment or retry loops were introduced.

Current next steps: restore the GPT proxy's existing Codex authentication through the account owner, obtain explicit permission for the exact pipeline checkout (two automatic approval rejections remain in force), then reproduce/validate development with that source and rerun a suitable transaction once readiness is restored. Keep the full 16-chain scope; all unattempted chains remain blocked, never silently removed.

## Exact pipeline acquisition and integration verification

User explicitly approved the pending pinned-checkout download. This supersedes the source acquisition blockers above, but does not authorize package installs, credential changes or deployment. Separate checkout: C:\Users\91701\AppData\Local\Temp\faultseeker-all-chain-pipeline, origin NamelessMonsterr/FaultSeeker-, clean detached HEAD fb57c3fad63784b7a63dc7fdf1845364c76ce0b7 (verified with git rev-parse HEAD and git status --short).

Initial exact-pinned run executed all 325 cases: 318 passed, 7 failed, 0 skipped. All seven failures were UnicodeDecodeError in tests/test_function_wall_guard.py::_fork_src: read_text() selected Windows CP1252 for UTF-8 source. Corrected that test reader to read_text(encoding="utf-8"); no expected assertion, fixture, pin or external source changed.

Final commands in the console worktree:

```powershell
$env:FAULTSEEKER_TEST_PIPELINE_REPO='C:\Users\91701\AppData\Local\Temp\faultseeker-all-chain-pipeline'
python -B tests/run_offline.py --tb=short -rs
node tests/run_frontend_offline.cjs
git diff --check
```

Results: **325 executed, 325 passed, 0 failed, 0 skipped**, 18.57 seconds; frontend **13 executed/passed, 0 failed/skipped**; diff check passed. Python 3.11.9, OpenAI2.36.0, HTTPX0.28.1. External sockets blocked, dummy keys and temporary run storage; no live model/RPC calls or installs. The previously skipped pinned tests are now actually executed, but remain controlled-boundary integrations, not real all-chain correctness passes.

Current pipeline main was independently checked as fca6b998fa0a01f3832be6a0f1aa1d768306da8f. Its calibration block has the same historical reporting defect as the Docker pin: it replaces confidence.overall after scoring without refreshing level or explanation. The original heuristic explanation therefore survives alongside calibrated overall. A separate fix/calibrated-confidence-reporting worktree was created at C:\Users\91701\Downloads\faultseeker-demo-console-main\faultseeker-pipeline-calibration-fix, based on that verified current main, with origin NamelessMonsterr/FaultSeeker-. The pinned checkout remains unchanged. Pipeline fix/testing is pending; no calibrated metric, paper content or historical report rewritten.

### Calibration reporting fix published for review

Pipeline draft PR: https://github.com/NamelessMonsterr/FaultSeeker-/pull/3, base main,
head c58bc699429e37e3a959ddc971b5b8c1713cb530 on fix/calibrated-confidence-reporting.
Two pre-fix regressions reproduced the stale level/explanation and partial
mutation on a later calibration failure through analyze_transaction with controlled
upstream stages. The fix derives labels from the stored probability, preserves the
original heuristic separately, rejects invalid probabilities and publishes all
calibrated results atomically. Components remain heuristic inputs.

`python -B tests/run_offline_calibration.py`: 47 executed, 47 passed, 0 failed,
0 skipped (23 new cases plus 24 existing confidence tests), 11.75 seconds.
`git diff --check` passed. No installs or live RPC/model calls. Installed pyreadline3
emitted an ignored Windows-handle error during interpreter shutdown; exit zero.
These tests exercise reporting/evidence-card ordering with controlled boundaries,
not on-chain provenance, trained-calibrator accuracy or full real analyses.

Before publication, Render settings still showed console main1 auto-deploy On
Commit, PR previews Off, deployed SHA 947db7d508f5b93eb603e075b77a77408a91779d.
Pipeline CI contains tests, no deploy step. Only fix refs were published; pipeline
main remained fca6b998fa0a01f3832be6a0f1aa1d768306da8f. No merge, deployment,
Docker pin update, paper edit or historical report change. GPT owner reauthentication
and the Qwen timeout remain unresolved; real correctness passes remain 0/16 for
development and 0/16 for live.

## Itera documented request contract (2026-11-03)

Official https://iteracompute.com/docs.html first-free-call examples specify
qwen/qwen3.8-27b, Chat Completions, reasoning=false and a 180-second client
timeout. The rate-limit section documents up to 120 seconds of queue waiting,
with provider_rate_limit shared between capacity refusals and queue timeout.
The public docs do not establish reasoning_effort=none as the Qwen control.

A new regression through the real SDK and MockTransport failed before the fix:
the preflight serialized reasoning_effort=none and omitted reasoning=false.
The adapter now emits the documented field and removes conflicting effort
fields only for the isolated Itera route. Other providers stay unchanged.
Existing route, self-test and pinned provider-agent assertions were updated to
the documented contract. This is not evidence that inference now succeeds.

Validation with the clean exact-pinned pipeline checkout:
`python -B tests/run_offline.py --tb=short -rs` with
FAULTSEEKER_TEST_PIPELINE_REPO set to that checkout: **326 executed/passed,
0 failed, 0 skipped**, 20.20 seconds. Frontend command
`node tests/run_frontend_offline.cjs`: **13 executed/passed, 0 failed/skipped**.
`git diff --check` passed. A sandboxed backend attempt stopped emitting output
and was explicitly interrupted; it is not counted as a pass. The subsequent
socket-blocked run outside the Windows sandbox completed with exit zero.

The 120-second preflight deadline versus the documented 180-second example is
a separate compatibility concern. No timeout configuration was changed here.
The historical timeout had no HTTP status or provider error code; queueing is
consistent with timing but remains unproven. No new model request, payment,
credential change or deployment was performed. Real-chain passes remain zero.

### Route-specific timeout follow-through

Development now defaults Itera's request/preflight allowances to 180 seconds,
matching the documented first-call example, while retaining explicit operator
FAULTSEEKER_MODEL_CALL_TIMEOUT_SECS / legacy FAULTSEEKER_LLM_TIMEOUT_SECS and
FAULTSEEKER_MODEL_PREFLIGHT_SECS precedence. Other model defaults stay 60-second
attempts and 120-second preflight. Self-test uses the same Itera attempt policy.

Independent read-only review caught an intermediate mixed-model regression:
the session-wide Itera allowance also raised GPT attempts to 180 seconds. Fixed
before publication with per-model attempt caps. SDK MockTransport regression
checks the actual HTTP timeout; reservation reconciliation only reduces it.
One mixed-run preflight deadline remains shared across all selected stages.
Shared total budget and retry counter are unchanged, SDK retries remain disabled.
Independent re-review found no further confirmed issue in changed paths.

Final exact-pinned offline command: `python -B tests/run_offline.py --tb=short -rs`
with FAULTSEEKER_TEST_PIPELINE_REPO set to the clean fb57c3f checkout:
**330 executed/passed, 0 failed/skipped**, 13.15 seconds.
Frontend: `node tests/run_frontend_offline.cjs`, **13 executed/passed, 0 failed/skipped**.
Diff check passed. An intermediate new test used a nonexistent retry_limit
attribute; corrected to the real retries_left counter before the final run.

Local process has no configured Itera key and no local env file was found;
no corrected live request was made. Explicit deployed limits may still override
the new defaults. Render rechecked main1 On Commit / previews Off and live SHA
947db7d508f5b93eb603e075b77a77408a91779d before publishing only the fix ref.
Provider recovery and full corrected-development/live flow remain unverified.

## Exact-pin path probe and transaction candidates (2026-11-03)

Executed `python -B tools/probe_local_pipeline.py --repo C:\Users\91701\AppData\Local\Temp\faultseeker-all-chain-pipeline`, exit zero. Reported exact_pin=true at fb57c3fad63784b7a63dc7fdf1845364c76ce0b7, synthetic inputs, network_calls=0. Creation via geth normalization, real sequencer, flattening and ranker preserved the expected created target; coverage ends before function/model analysis. Visitor RPC registry refreshed. All six tested depth-1024 operations returned (normalization, guard deepcopy, both conversions, TraceNode and JSON), with imported recursion limit 20000. This does not prove arbitrary-depth or complete forensic/model execution.

The same probe reproduced Parity creation address_matches=false and input_matches=false on the exact pin, resolving the old source-availability uncertainty. A separate pipeline fix is being isolated; no source fixture or ground truth was invented. The raw upstream RPC helper forwarded a synthetic private destination into a mocked opener; this does not bypass the console's visitor relay protections.

Optimism candidate, not a current-chain/full-analysis verification:
https://optimistic.etherscan.io/tx/0x3f53165786698b8f11c4a50636a3d8d2f6013b17711eba119f76a95ff33f3546
The indexed official explorer page records success at block118585730, 2024-04-10 17:30:37 UTC, swap(bytes) selector0x627dd56a to 0xCf32c5bB41F7A302298a2D2072155800871BaaD3, with swap logs. Direct page retrieval cache-missed; evidence came from exact-hash indexed explorer content. Needs current receipt, complete trace, source mapping, real console run and ground-truth assessment before promotion to a pass. Coverage-table hash stays unset until current on-chain verification.

Aurora example 0x36e2339784004c5dd40df74e663f1fe6683705a8ad665a05a9ad0aa4e11b559b is excluded: official https://doc.aurora.dev/blog/demystifying-transaction-failures/ diagnoses OutOfFund before execution. No suitable Aurora candidate was verified in the bounded research. Truncated hashes and inaccessible transaction pages were not promoted as evidence.

### Parity fix review and newer-main depth limitation

Pipeline draft https://github.com/NamelessMonsterr/FaultSeeker-/pull/4 targets
pipeline main, head c076a4cec07b35d022020653dc17f6e505cdaf96 on
fix/parity-creation-normalization. Direct and tree normalization now preserve
CREATE/CREATE2 action.init, result.address and provider type/error metadata.
No missing creation target is replaced with initcode. Independent read-only
review found no confirmed regression in the changed paths.

Parent independently executed:
`python -B tests/run_offline_parity.py tests/test_parity_creation_normalization.py tests/test_reentrancy_state_signals.py tests/test_pipeline_parse.py`
in that pipeline worktree: **48 executed/passed, 0 failed/skipped**, 5.32 seconds;
diff check passed. The installed pyreadline3 shutdown warning remains ignored
by Python; exit0. Controlled real replay fallback covers nested creation; no
live provider or on-chain ground-truth verification. Parent console probe at
that exact fix SHA reports Parity address/input preserved and the synthetic
creation sequencer/flattening/ranker target preserved. Docker pin unchanged.

Separate limitation discovered by the same probe: newer pipeline main uses
recursion limit1000, unlike exact pin's20000. At depth1024, normalization,
deepcopy, upstream conversion, TraceNode and JSON raise RecursionError; console
iterative conversion returns. Read-only base comparison confirms preexisting
behavior: fca6b998 has no recursionlimit setting, while fb57c3f function_analyzer.py:28
sets20000; isolated base and fix geth normalizers both raise at depth1024/limit1000.
The Parity patch does not introduce or resolve this depth limitation. A future
pipeline-pin update must account for it; do not claim current-main full-flow
depth support from the older pin's passing probe.
