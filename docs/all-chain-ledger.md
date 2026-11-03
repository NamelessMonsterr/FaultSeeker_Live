# All-chain analysis evidence ledger

## Current status

Draft PR: https://github.com/NamelessMonsterr/FaultSeeker_Live/pull/5, base development main, head fix/all-chain-validation. Created and verified at head 1980a692638c6bdccbc398dbd8e63da1a02f7ac4; subsequent ledger updates stay on that fix branch. Repository/base were checked in GitHub before creation. Render was rechecked immediately before publication: main1 auto-deploy On Commit, PR previews Off. No merge or deployment; Instinct review and user repo/base/deployment approvals remain outstanding.

Current result:354 console offline backend passed /0 skipped with the exact Docker pin and explicitly identified candidate;18 frontend passed. Latest combined pipeline suite:303 passed /0 skipped. Development e459ff0f30c9 received6 model analysis responses then stopped on HTTP429; partial/INCONCLUSIVE, scoring skipped. Full correctness passes remain0/16 development and0/16 live. GPT authentication remains unresolved. Further Itera calls are stopped pending actionable rate/capacity recovery guidance.

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
| eth | Blockscout instance; RPC trace | setup0xa17fdb804728f226fcd10e78eae5247abd984e0f03301312315b89cae25aa517; original cashout2606 below | DEV3 unsuccessful / LIVE2 failed preflight | latest dev partial429;0 scores/cards; history reopened | D-ETH-001..003; setup34 frames and cashout5 frames identity checked |
| bsc | RPC trace required | 0xebf83628ba893d35b496121fb8201666b8e09f3cbadf0e269162baa72efe3b8b | BLOCKED / BLOCKED | no full run; RPC identity/receipt checked | chain56,block21957793; tested official dataseed trace fails missing trie node |
| polygon | RPC trace required | unset | BLOCKED / BLOCKED | not run | free route unverified |
| arbitrum | RPC trace required | unset | BLOCKED / BLOCKED | not run | free route unverified |
| optimism | Blockscout instance; RPC trace | 0x3f53165786698b8f11c4a50636a3d8d2f6013b17711eba119f76a95ff33f3546 | MODEL BLOCKED / LIVE NOT RUN | no full run; RPC identity/receipt and37-frame trace checked | chain10,block118585730; public Optimism RPC + keyless explorer |
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
| aurora | Blockscout instance; RPC trace | 0xc413c63fd0a4224c3883ed2a906f80337e256759612951866f6b2134e4b6791f | MODEL BLOCKED / LIVE NOT RUN | no full run; RPC identity/receipt and24-frame trace checked | chain1313161554,block222859221; official RPC + keyless explorer |

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

### Depth fix published separately for review

Pipeline draft https://github.com/NamelessMonsterr/FaultSeeker-/pull/5 targets
main at fca6b998; head72e6ad77d7a8d7230b461189eba9bc033d631187 on
fix/deep-trace-processing. Normalization, TraceNode/object conversions, graph/text
traversal and flattening are iterative; frame-only copying avoids copying every
descendant subtree per node. Preorder identities and postorder repeated-pattern
collection remain intact. Cycle rejection permits reused sibling references.

The integrated application test still reproduced standard JSON/deepcopy failure
before an explicit application-entrypoint policy was added: main() establishes
a process-wide minimum recursion allowance20000, replacing the old pin's import
side effect. It never lowers a larger limit or temporarily resets it in production.
Direct library callers bypassing main() do not receive that allowance. No
arbitrary-depth, bounded-resource or live correctness guarantee is claimed.

Commands in the new pipeline worktree:
`python -B tests/run_offline_depth.py tests/test_deep_application_path.py tests/test_deep_rpc_normalization.py tests/test_deep_trace_objects.py tests/test_deep_trace_flattening.py tests/test_reentrancy_state_signals.py tests/test_pipeline_parse.py`
=> **66 executed/passed,0failed/skipped**,12.56s.
`python -B tests/run_offline_depth.py tests`
=> **232 executed/passed,0failed/skipped**,15.20s; diff check passed.
Installed pyreadline3 ignored shutdown-handle warning; exit0. Independent
read-only review found no confirmed regression. Sockets blocked, inherited keys
removed, temporary output storage, no installs or live provider calls.

The integrated test retains1024 frames through real normalization, cache JSON
roundtrip, deepcopy, sequencer, graph, flattening and main report JSON, with
analyze_transaction controlled around that path. It does not execute complete
forensic/function/model reasoning. Separate Parity/calibration drafts are not
folded in; future merge resolution must preserve all three. Pipeline main and
console Docker pin unchanged. No merge/deploy, real-chain passes still0/16.

## Combined development rehearsal (2026-11-03)

Local pipeline branch fix/pipeline-integration-validation at
d899c0f1d503e69c1e92834e38e46a0684b678ba combines the three queued patches
on main fca6b998 in a separate worktree; component branches and PRs unchanged.
No PR or protected branch merged. The rpc_provider.py patch overlap was
resolved by retaining iterative normalization plus the Parity creation helper,
tree metadata and guarded result.output. Independent read-only review found
neither fix lost. This validation branch is local, not published or deployed.

`python -B tests/run_offline_depth.py tests`: **269 executed/passed,
0failed/skipped**,15.17s; diff check passed. Added synthetic cross-patch coverage
for1024 Parity CREATE frames, target/initcode preservation, object conversion
and calibrated-report consistency. Sockets blocked, no installs/live calls.
Do not add this count to component counts as independent coverage; tests overlap.
The pipeline depth draft's GitHub UI now shows2/2 checks passed; observed directly.

Credential presence check: local ITERA_API_KEY absent; OPENAI_API_KEY present
but CODEX_PROXY_BASE_URL and OPENAI_BASE_URL absent. The latter key's intended
destination is not established; it was not sent to an assumed proxy. No values
printed, rotated or changed. The request for an approved local Itera route or
owner-restored GPT authentication remains unanswered.

Completion requirements still unproven:

| Requirement | Current evidence / blocker |
| --- | --- |
| Corrected development full real analysis on all16chains | 0passes; approved local model access missing, current trace/receipt/ground-truth checks incomplete |
| Corrected rendered console flow, scoring, evidence and saved/reopened history | Offline boundaries tested; full real development flow not verified |
| Approved live build and all16 real analyses | Live remains947db7d; two preflight failures,0passes; no deployment authorized |
| Actual deployed pipeline revision | Docker configured pinfb57c3f; runtime revision not independently attested |
| Instinct review and user repo/base check before merge | Instinct capability unavailable in this session; user review pending |
| Deployment approval, rollback tag and post-deploy verification | Not authorized or performed; no live changes |

The goal remains incomplete. Offline tests, candidate explorer pages and CI
checks do not substitute for these requirements.

## Development run D-ETH-001:50c53ee29ba1 (2026-11-03)

The user submitted this existing local run; it was inspected without duplicating
it. Console source13140e27e859cde7b6e7f0257ab8ce72b8e03b27, combined pipeline
d899c0f1d503e69c1e92834e38e46a0684b678ba, Ethereum Hedgey hash as above,
itera/qwen3.8-27b. Started11:08:30+05:30, ended11:11:48+05:30, duration198.0s.

Persisted endpoint summary:1attempt, preflight ok1/failed0, transport168.266s,
prompt15/completion2/reasoning0 reported tokens, retries_remaining3,
shared budget6000s, no endpoint failure. This verifies one real Qwen response
with corrected request settings; it does not establish general service health,
billing, old timeout cause or completed transaction analysis.

Terminal failure was RuntimeError from eth_getTransactionByHash: all attempted
RPC providers failed, last HTTP403 auth error. Deterministic/function/scoring
sections skipped; failed/INCONCLUSIVE. History persisted error and independently
reopened the same run as error/INCONCLUSIVE with skipped sections. The initial
stream displayed the RPC403 cause; reopening retains the generic recorded-error
limitation rather than the original stream message. No success inferred.

Bounded free diagnostics on the official PublicNode endpoint established chain1
and returned the exact transaction, block19687890, target
0xc793113f1548b97e37c409f39244ee44241bf2b3 and selector0xe32a9a37. Same
transaction read at https://ethereum.publicnode.com: default Python urllib
User-Agent -> HTTP403; explicit FaultSeeker-validation/1 -> transaction returned;
the final truthful product-only FaultSeeker header also returned the transaction.
One attempt per diagnostic variant, no keys, no model calls or blind retries.
Official endpoint evidence: https://ethereum.publicnode.com/ publishes
https://ethereum-rpc.publicnode.com as its free Ethereum RPC endpoint.

Current keyless Blockscout trace validated against RPC identity:5frames,
0frame errors, same root target and calldata. Provider block hash
0xadc062e388f2cb069f54f398a7b26c41c8484004deba471c78864a5c732363d3.
ABI unverified; completeness is explorer-reported and internally consistent,
not independently proven. Public evidence artifact:
C:\Users\91701\AppData\Local\Temp\faultseeker-local-validation-0745f5b807564267a7519daaaa694ea5\50c53ee29ba1.identity-probe.json.

Header fix990854cceb69a86e1a7063e279be1e35b51ee5b1 changes only _http_post's
truthful application User-Agent. Focused44tests passed; parent live comparison
verified that exact header. Incorporated locally into candidate
745ac7435b142a22c0eece81dac43a6cdb5f427c; full combined suite278passed,
0failed/skipped,67.45s; diff check passed. Installed pyreadline3 ignored shutdown
warning; exit0. No endpoint/auth/retry/timeout policy change in this header fix.

Only the local server was restarted, using preserved temporary history, public
ETH_RPC_URL=https://ethereum-rpc.publicnode.com and explicit keyless explorer
direct mode. The form cleared its API key after the first run as intended.
The next click was blocked by native required-field validation; no second
analyze request or model call started. Awaiting private key reentry, not another
approval to use it. Render/main1 unchanged; no merge/deploy.

Header draft published and repository/base verified in GitHub:
https://github.com/NamelessMonsterr/FaultSeeker-/pull/6, base pipeline main,
head990854cceb69a86e1a7063e279be1e35b51ee5b1. No protected branch changed.

### Hedgey multi-transaction ground-truth boundary

Protocol-authored postmortem:
https://medium.com/hedgey/hedgey-exploit-post-mortem-784e9860fd8d
and original Verichains analysis:
https://blog.verichains.io/p/approval-error-vulnerability-analyzing
identify two related transactions. The supplied2606d459... hash is the later
USDC cashout; the earlier setup flash transaction is
0xa17fdb804728f226fcd10e78eae5247abd984e0f03301312315b89cae25aa517.
The documented allowance bug involves createLockedCampaign/cancelCampaign
at0xbc452fdc8f851d7c5b72e1fe74dfb63bb793d511. Do not treat those functions as
observed in the later five-frame cashout trace: its targets are the attack
contract, USDC proxy and USDC implementation, not the vulnerable campaign contract.
This is a scope boundary, not permission to invent missing trace frames.

The earlier setup hash was independently resolved on Ethereum through free RPC
and keyless Blockscout. Validated trace has34frames and calls the documented
vulnerable contract with observed selectors0xf412e4c7 and0xefd86b62. Human-readable
selector mapping/execution-block ABI verification is still unproven. Artifact:
C:\Users\91701\AppData\Local\Temp\faultseeker-local-validation-0745f5b807564267a7519daaaa694ea5\hedgey-setup.identity-probe.json.
This is a suitable additional function-analysis candidate, not a completed model
analysis or correctness pass. No supplied preset, expected result or fixture was
changed to force a match. Original2606 input investigation remains preserved.

## Encrypted local key and D-ETH-002:1caf1c5827dd (terminal partial)

User explicitly authorized local key persistence, superseding the earlier
no-secret-disk-storage instruction for this existing Itera credential only.
One-time masked owner entry created
C:\Users\91701\AppData\Local\FaultSeeker\itera-key.dpapi.
Windows DPAPI encryption binds it to the current Windows account/machine;
inherited permissions disabled, two explicit owner/SYSTEM access rules.
Encryption/decryption and no-overwrite tests passed with dummy data. Actual
saved key readability checked without displaying it. No plaintext key saved,
printed, committed or uploaded. Helper/credential are outside the repository;
Render settings and credential value were not changed.

The local server now loads the encrypted key automatically into its process
environment; unknown inherited provider credentials/history tokens are cleared.
Public Ethereum RPC and direct keyless explorer trace routing remain as above.
No future manual key reentry is needed while this local encrypted credential is
valid. This is local configuration, not a production credential deployment.

Submitted exactly one new real development analysis1caf1c5827dd:
Ethereum0xa17fdb804728f226fcd10e78eae5247abd984e0f03301312315b89cae25aa517,
itera/qwen3.8-27b, no caller key/RPC override. Console70f49d544e0acaf1ec488338ed982395b75ec86d,
combined pipeline745ac7435b142a22c0eece81dac43a6cdb5f427c. Initial UI/model
events show one preflight request in progress with all analysis stages pending.
No duplicate/restart request submitted and no success inferred from activity.
Terminal result: partial / INCONCLUSIVE, stage_completed deterministic-checks.
Started2026-11-03T12:30:56+05:30; report timestamp12:34:52.364995 local.
Reported pipeline duration97.228seconds excludes preflight; persisted event
span229.8seconds (128 events, terminal end). Do not treat pipeline duration as
the whole run latency.
Preflight succeeded once (132.765 transport seconds; 15 prompt and 2 completion
tokens); analysis HTTP calls were zero, scored functions zero, evidence cards
zero. Function-analysis controller started/completed once but no per-function
analysis was observed. Sections explicitly say no_model_analysis / scoring
skipped. This is not a complete analysis or correctness pass.
Persisted result and events exist under the local validation history directory
as 1caf1c5827dd.json and 1caf1c5827dd.events.jsonl. Terminal rendered UI inspected;
history reopening checked through Recent runs / View report: partial,
INCONCLUSIVE, no_model_analysis, scoring skipped, Functions and evidence (0).
Heuristic estimates remain explicitly marked as not validated findings.

Source inspection found a routing mismatch in the candidate pipeline:
FunctionAnalyzer imports utils.utils.build_agent, whose legacy implementation
routes every non-gpt model to OllmaAgent. The provider-aware factory instead
lives in utils.agent, where the console registers the Itera prefix. Therefore
successful shared-transport preflight does not establish that this constructor
uses that transport. Offline reproduction confirmed all six FunctionAnalyzer
Itera agents instantiated as OllmaAgent, a simulated local error was swallowed
into an empty result, and no cloud transport calls occurred. Initial regression
tests: 4 failed / 2 passed, including wrong Gemini and o3 routing through the
legacy wrapper. Fix/testing underway; no new live request submitted while the
mismatch is unresolved.

## Routing regression and candidate compatibility follow-through

Exact Docker pin fb57c3f already delegates utils.build_agent to the provider
factory. Current development main fca6b99 regressed to GPT-or-Ollama routing.
A standalone fix/provider-factory-routing branch restores the delegation and
adds eight regression cases. Offline focused suite:38 passed,0 skipped;
combined candidate full pipeline suite:286 passed,0 skipped.
Standalone commit f43307f01960ae1ddc69a8cffc0923f3f1e66e16 pushed and verified
at https://github.com/NamelessMonsterr/FaultSeeker-/pull/7 (draft, user's fork,
base main). Pipeline main remains fca6b998fa0a01f3832be6a0f1aa1d768306da8f.
Local integration candidate committed as6a5b0befeb85bf1c19fcdf35fddb5967e58fdb96;
that integration branch remains local only. Render settings rechecked before
push: console repo FaultSeeker_Live, branch main1, On Commit, previews Off,
deployed947db7d508f5b93eb603e075b77a77408a91779d. No deployment triggered.

Added a console integration test that constructs all six actual FunctionAnalyzer
agents, mocks HTTP, and asserts Itera request adaptation plus six successful
analysis calls in the shared session. Exact-pin console suite:331 passed,
0 skipped; frontend13 passed,0 skipped. These are offline tests, not real passes.

Explicit invocation of that routing contract against the candidate found another
compatibility boundary: candidate agent.py lacks _parse_api_keys and
_llm_call_with_retry. The real server supplies model_keys, masking the former
during preflight; existing shared-transport installation depends on the latter.
Therefore a factory-only fix is insufficient for safe candidate analysis.
Candidate compatibility work remains in progress; no additional live model
request has been sent. An initial standalone offline command had a temporary
directory cleanup error after38 passing tests; rerun closes logging/restores
working directory and exits0 with38 passed. The failed candidate contract is
not included among passing integration counts.

Candidate transport regression initial run:5 failed,331 deselected. Actual
worker-supplied model_keys masked the missing parser but analysis bypassed
the session, sent the raw multi-key string and unadapted alias, and swallowed
502/429. The console now adapts older direct-SDK agents to session.call when
their retry helper is absent; pinned helper-based behavior is unchanged.
Legacy JSON query also swallowed propagated errors:2 regression failures
reproduced, then a query-boundary health check preserved the latched failure.
Fourteen candidate regressions now pass: actual analyzer transport/usage,
SDK retry cap, GPT proxy/direct route controls, parser fallback, auth rotation,
and mid-run502/429 propagation in string/JSON modes. No live requests used.

Final offline command (both distinct checkouts, no substitution of the pin):
FAULTSEEKER_TEST_PIPELINE_REPO=C:\Users\91701\AppData\Local\Temp\faultseeker-all-chain-pipeline
FAULTSEEKER_TEST_CANDIDATE_REPO=C:\Users\91701\Downloads\faultseeker-demo-console-main\faultseeker-pipeline-integration
FAULTSEEKER_TEST_CANDIDATE_SHA=6a5b0befeb85bf1c19fcdf35fddb5967e58fdb96
python -B tests/run_offline.py --tb=line -rs
Result345 passed,0 failed,0 skipped in13.29seconds, exit0. Candidate modules
are isolated/restored separately from the immutable pin. Frontend13 passed,
0 skipped; git diff --check passed. Pipeline PR7 CI:2/2 checks passed.

## D-ETH-003:e459ff0f30c9 (terminal partial / HTTP429)

Exactly one new real development analysis accepted after the routing and shared
transport corrections. Ethereum setup transaction
0xa17fdb804728f226fcd10e78eae5247abd984e0f03301312315b89cae25aa517,
itera/qwen3.8-27b, configured encrypted local key, no caller RPC/key override.
Console aac41c553c681c10bc52ac7c38114fe57bc6004c; combined pipeline
6a5b0befeb85bf1c19fcdf35fddb5967e58fdb96. Local server PID11180 / tool
session96730,127.0.0.1:8765. UI confirms Waiting on model endpoint / request
in progress. No stage, score, evidence or correctness completion inferred yet.
First persisted event2026-11-03T07:26:51.8Z (12:56:51.8+05:30).
Subsequent events confirm preflight ready and two analysis responses ready
through the shared session; fourth overall request is in progress. This proves
real analysis transport is now exercised, not completion of function findings
or correctness. Run remains active; no duplicate request submitted.
Persist events/result under the same local validation history directory with
run prefix e459ff0f30c9. Do not restart or duplicate while this run is active.

Terminal evidence supersedes the in-progress observations above: partial /
INCONCLUSIVE, deterministic_checks and address_classification completed,
function_analysis failed, scoring skipped. Eight HTTP attempts total:
preflight1 success; analysis6 successes,1 HTTP429 failure. No retry or key
rotation followed429; all3 shared retries remained unused. Transport430.625s;
persisted event span444.9s. Tokens7006 prompt/738 completion/0 reasoning.
Scored functions0,evidence cards0; function controller started1/completed0.
No Retry-After/reset guidance persisted; rate/capacity cause is not proven
beyond429. Further affected model calls stopped, with no duplicate submission.
This is not a complete transaction or correctness pass.

Terminal rendered report shows partial/INCONCLUSIVE, HTTP429 and skipped
scoring. Its legacy candidate fallback incorrectly labelled34 observed trace
calls as function findings despite0 scored functions/cards. Two synthetic UI
schema regressions reproduced2 failures/13 passes; corrected rendering keeps
actual findings separate from observed calls/unanalysed candidates, preserving
pagination and full JSON. Frontend15 passed,0 failed/skipped; static sync and
diff checks passed. Corrected rendered history verified: stored run reopens as
error/INCONCLUSIVE (run lifecycle error, persisted report partial), HTTP429,
function analysis failed/scoring skipped, Functions and evidence(0), separate
Observed calls / unanalysed candidates(34), explicitly not model findings.
Preview: dev-eth-003-observations-separated.jpg in the task visualization folder.
Post-fix offline backend rerun with both exact pin and explicit candidate:
345 passed,0 failed/skipped in41.90seconds; frontend15 passed,0 skipped.

Remaining independent defects reproduced offline, not yet fixed: Itera's
registered cloud prefix gets local prompt variants and8 function iterations
instead of3; selector-only memo dedup skips the same selector on a different
address. Separate work is isolated from candidate6a5b0be so this real run's
source revision stays attributable. Further Itera calls remain stopped after429;
GPT proxy authentication remains unresolved. No full analysis passes yet.

## Offline follow-through after the429 (2026-11-03)

Cloud policy fixed separately in b5624b29683b4dc628fab6319761f2f1c1537f6c,
draft https://github.com/NamelessMonsterr/FaultSeeker-/pull/8,base main.
Three initial failures/8 controls passed; final full standalone pipeline suite
212 passed,0 skipped in15.02s. Actual loop and prompt regressions use the live
provider registry, including replacement; no model calls. Existing local limits
remain unchanged. CI2/2 checks passed.

Target memo fixed separately in fac4a517d86cb2b65f8d9527755282cfd6635149,
draft https://github.com/NamelessMonsterr/FaultSeeker-/pull/9,base main.
Four initial failures/2 controls passed. Final standalone suite207 passed,
0 skipped in14.79s. Actual FunctionRanker→review preserves distinct addresses,
deduplicates exact pairs across groups, and preserves underscores/function case.
Synthetic schema tests do not establish on-chain findings.

Both patches applied to the local combined candidate without changing queued
branches or merging PRs. Combined commit e9d7166ba9362e5fbaeeb349158d0649efc5632d
remains local only. `python -B tests/run_offline_depth.py tests`:303 passed,
0 skipped in40.15s. Console command above rerun with explicit candidate SHA
e9d7166ba9362e5fbaeeb349158d0649efc5632d:345 passed,0 skipped in60.49s.
The exact Docker pin remains clean fb57c3fad63784b7a63dc7fdf1845364c76ce0b7;
no real analysis has used e9d7166 yet. UI fix ebe1ea4 pushed to console PR5;
main/main1 remain unchanged, no deployment.

Optimism readiness probe: PublicNode's documented public endpoint returned403
on eth_chainId. The separately documented public https://mainnet.optimism.io
returned chain10, matching candidate hash/receipt at block118585730, selector
0x627dd56a,status0x1. Keyless https://explorer.optimism.io raw trace yielded37
frames with RPC root identity and tree consistency checked. Completeness is
explorer-reported, not proven; ABI/benign-or-exploit ground truth unverified.
No model calls/full pass. Public artifacts in the local validation directory:
optimism-candidate.identity-probe.json (403) and
optimism-official-candidate.identity-probe.json (verified identity/trace).
Endpoint references: https://optimism.publicnode.com/ and
https://www.alchemy.com/docs/choosing-a-web3-network .

BSC readiness probe used the existing BSC Token Hub preset, not a fabricated
hash. Official public https://bsc-dataseed.bnbchain.org verified chain56,
hash/receipt/block21957793 and selector0x84013b6a. One callTracer request failed
JSON-RPC -32000,missing trie node. This tested endpoint lacks the necessary
historical state for that trace; other free routes remain unverified, not
declared impossible. Artifact:bsc-token-hub.identity-probe.json. Source:
https://docs.bnbchain.org/bnb-smart-chain/developers/json_rpc/json-rpc-endpoint/ .

Itera docs rechecked:429 recovery requires reading error.code; monthly,TPM and
capacity codes differ, and provider_rate_limit does not distinguish full queues
from queue timeouts. The current sanitized failure discarded this code and
Retry-After metadata, so this historical429 cannot be assigned a specific cause
or reset time. No new model attempt made. Source:
https://iteracompute.com/docs.html .

Aurora readiness: one explorer transaction-list GET supplied a successful,
non-transfer candidate (explorer label sweep,not ABI-verified), then official
https://mainnet.aurora.dev verified chain1313161554,matching hash/receipt at
block222859221,selector0x9857ba36,status0x1. Keyless explorer returned24 frames
whose root matches RPC identity and tree checks. This is not the earlier
OutOfFund candidate and is not a model/correctness pass. Artifacts:
aurora-candidate-discovery.json and aurora-sweep.identity-probe.json in local
validation history. Source:https://doc.aurora.dev/dev-reference/network-endpoints/ .

Provider log review (no inference call) correlated failed request
8388d813-3415-4d44-a395-85ec4f6d3d84 at2026-11-03T07:32:09.560Z;
expanded details provide no error.code or Retry-After. Precise429 cause stays
unknown. Safe recovery metadata fix now retains only the three documented
allowlisted limit codes, bounded numeric retry seconds or normalized HTTP-date;
arbitrary codes,body messages,types and headers are excluded. Automatic429
retry/rotation remains disabled. UI distinguishes reported monthly,TPM and
capacity codes, and labels retry hints as original failure-time information.
Historical reports are not retroactively rewritten or assigned a code.

Regression first:4 backend failures/5 controls passed; final9 focused passed.
Frontend first3 failures/15 controls passed; final18 passed,0 skipped.
Full offline command with exact pin and explicit candidate e9d7166:
`python -B tests/run_offline.py --tb=line -rs`:354 passed,0 skipped in61.77s.
Static sync/diff checks passed. No live request has used this metadata fix yet.

## D-ETH-004:8aa518128b22 (terminal partial / provider capacity)

After several hours without model calls following the429, exactly one new run
was accepted on the same approved free Itera route and existing encrypted local
key. This tests the newly corrected cloud policy/target identity and preserves
actionable metadata if preflight is rejected; no429 retry or parallel copy is
allowed. Ethereum setup hash remains
0xa17fdb804728f226fcd10e78eae5247abd984e0f03301312315b89cae25aa517.
Console c4fdbd2cca589e32d3f50e60dcabc736a118c555; pipeline
e9d7166ba9362e5fbaeeb349158d0649efc5632d. Local server PID20568,session77009,
127.0.0.1:8765. UI confirms accepted run8aa518128b22; no stage/finding pass
inferred. Monitor this same run through its terminal state; do not resubmit.

Terminal outcome supersedes acceptance above: partial/INCONCLUSIVE. Preflight1
success; analysis1 success/1 failure;3 total requests; transport370.687seconds.
Tokens403 prompt/4 completion/0 reasoning. All3 shared retries remained unused.
The real HTTP429 reported provider_code=provider_rate_limit and Retry-After2s;
the new sanitized metadata was retained and rendered. Per provider docs this
is a capacity refusal, not its monthly/TPM-specific code; queue-full versus
queue-timeout remains indistinguishable. No further model request submitted.
Deterministic checks completed; address classification failed; function
analysis/scoring skipped. Scored functions0,evidence cards0. No full pass.
Initial report and history reopening verified: partial then run lifecycle
error/INCONCLUSIVE; provider capacity explanation and original2-second retry
hint remain visible. Screenshot:dev-eth-004-capacity-reopened.jpg.
UI creation time2026-11-03T11:12:51Z; first persisted event11:13:14.5Z.
Terminal end2026-11-03T11:19:35.2Z; event span380.7seconds,56 events.
Function controller started0/completed0, so the new function-loop/target fixes
were not exercised by this failed real run.

## Read-only proxy bootstrap investigation

Signed-in source inspection confirmed entrypoint.sh at the last attested proxy
deployment commit070d9d61d3bd9140a5ea71707582781a32ce65f3 unconditionally writes
CODEX_AUTH_JSON over the XDG auth.json on every start. A local isolated Git Bash
test executed those six source lines with a stub proxy and dummy generation
markers: first start read seed,stub wrote rotated; second start again read seed.
This proves startup overwrites newer file state. No real auth,secret,provider
request or proxy change was used. Artifact:proxy-bootstrap-reproduction.json.

Upstream documentation describes a rotating credential file; device auth admin
routes are Workers-only and cannot be assumed present on this Render build.
The bootstrap overwrite is a confirmed persistence flaw. Whether it caused the
historical refresh_token_reused/401 is still unproven; actual upstream build
revision/token history is not attested. A durable rotating credential source
and fresh owner login are needed for reliable recovery; merely restoring an
environment seed can become stale again. Deferred outside console/pipeline
fixes: owner credential changes/proxy restart and durable store require separate
authority/review. No wrapper repo edits or credential changes performed.
Sources: signed-in NamelessMonsterr/codex-proxy-render entrypoint at070d9d6;
https://github.com/dvcrn/codex-oauth-proxy#authentication .

## User retires proxy route; Inception API preparation

User reports no longer having the GPT proxy and directs reliance on APIs.
Proxy recovery is no longer pursued; read-only findings above remain historical,
not authorization to change that service. No proxy credentials/restarts made.
Existing Render API-variable names inspected without values:GOOGLE_API_KEY,
ITERA_API_KEY,OPENAI_API_KEY,XAI_API_KEY. Presence is not proof of validity or
free access; no generation request sent through those other variables.

User supplied Inception as the alternate API, states its key has100M free
tokens, and supplied a rate-limit screenshot:1000 requests/min,3M input
tokens/min,100k output tokens/min. Official FAQ confirms a one-time100M token
credit shared across models,not a recurring per-model allowance. No payment,
upgrade or new account required/performed. No repeated credit-dashboard checks.
Source:https://docs.inceptionlabs.ai/resources/faq .

Owner entered the key into a masked native prompt. It is saved at
C:\Users\91701\AppData\Local\FaultSeeker\inception-key.dpapi using existing
Windows DPAPI/owner+SYSTEM protection,outside Git. No plaintext key or value
printed,committed or transferred to Render. Dummy roundtrip/no-plaintext/
no-overwrite checks passed; actual key decryptability checked without output.
Local launcher now optionally loads it into process memory and clears it on
exit. Dummy launcher test verifies provider isolation,loopback-only binding
and environment cleanup; no network call in that test.

Explicit new alias inception/mercury-3 routes only to the operator-configured
Inception endpoint (default https://api.inceptionlabs.ai/v1) and its own
INCEPTION_API_KEY. No fallback to another provider/model. Upstream IDmercury-3,
documented temperature0.5..1.0 (legacy0 mapped to0.5),low reasoning for analysis,
instant reasoning for tiny preflight,max_completion_tokens capped4096 (8 for
preflight). SDK retries remain0; same run-wide retry/time budget; default
Stage2 workers1. Shared registry classifies the candidate's agents as cloud.
Sources:https://docs.inceptionlabs.ai/get-started/models and
https://docs.inceptionlabs.ai/capabilities/reasoning-efforts .

Offline Inception route tests first10 failed/4 controls passed; final14 passed.
The SDK retry assertion checks actual HTTP retry headers rather than the original
client because the session sends through a bounded clone. Three server-policy
tests reproduced failure before adding the explicit model entry. Actual
candidate six-agent transport test uses mocked HTTP and the explicit candidate
SHA; not a provider inference claim.

Four further regressions proved nonempty but explicitly unfinished completions
(length,content_filter,tool_calls,function_call) were previously accepted.
They now fail incomplete_response without retry or model_endpoint_ready,
retaining reported usage without exposing response content. No unfinished
answer can be counted as successful analysis through this shared boundary.

Final offline backend command with unchanged exact pin plus candidatee9d7166:
`python -B tests/run_offline.py --tb=line -rs`:376 passed,0 skipped in19.44s.
Frontend18 passed,0 skipped; static sync/diff checks passed. Tested local
Python3.11.9,OpenAI2.36.0,HTTPX0.28.1; no installs.

One authenticated,non-generation GET /v1/models confirmed mercury-3 available
to the saved key. Artifact:inception-model-catalog.json in local validation
history. This is catalog access,not inference/preflight/full-analysis success.
No Inception generation request has started at this checkpoint.

## D-ETH-005:274b48534546 (terminal partial / unfinished completion)

Exactly one real Mercury analysis accepted for the verified Ethereum setup
hash0xa17fdb804728f226fcd10e78eae5247abd984e0f03301312315b89cae25aa517.
Console a1126b2c7113fe7d5033647b90571ef400e6d584; pipeline
e9d7166ba9362e5fbaeeb349158d0649efc5632d. Local server PID17280/session99120,
loopback8765. No caller key/RPC override; encrypted local Inception key used.
First event2026-11-03T12:50:10.6Z. Six model requests: preflight1 success,
analysis4 successes/1 explicit unfinished response; transport21.75seconds.
Tokens1723 prompt,8278 completion,of which8230 reasoning (a subset,not extra).
All3 shared retries unused; no429,provider fallback or paid route used.

Outcome partial/INCONCLUSIVE: deterministic checks completed,address
classification failed,function analysis/scoring skipped;0 scored functions/
evidence cards. Function controller not reached. The incomplete-response guard
prevented this nonempty unfinished response from counting as successful work.
Specific finish marker was not yet persisted,so length versus filtering/tool
status cannot be asserted from this historical report. The high reasoning
usage suggests a budget issue but is not definitive proof.

Provider's six per-request log rows match this run and label HTTP200 responses
SUCCESS; its visible details do not expose finish_reason or a raw request body.
Provider HTTP success is not a full-analysis pass. No secret values read from
the dashboard. A new optional allowlisted completion_finish_reason field now
preserves the known non-final marker; its4 regression cases first failed then
passed. No automatic retry added and no output cap raised without diagnosis.

## D-ETH-006:a5c4f7294193 (instrumented reproduction; terminal partial)

Same verified setup hash,Inception mercury-3,same4096 cap; console
81ac9c2d35dcc5bf7db157ec5aef4d7d8a1a9f0a,pipelinee9d7166. The worker was
freshly spawned against this checkout; existing parent server had unchanged
server configuration. This was one targeted reproduction,not an automatic
retry/parallel copy. First event2026-11-03T13:01:14Z,end13:01:41.2Z,27.2s span.
Five HTTP requests:preflight1 success,analysis3 successes/1 failure.
Transport18.953s;1377 prompt/6256 completion tokens,6203 reasoning subset.
All3 retries unused. Captured completion_finish_reason=length confirms output
budget exhaustion for this run. Deterministic checks completed,address
classification failed,function/scoring skipped,0 scores/cards;no full pass.

The initial conservative4096 cap was inadequate for this reasoning model.
Mercury's documented example uses8192 max_completion_tokens. Console default/
maximum now8192 for Inception only;preflight remains8 with instant reasoning,
analysis remainslow,serialStage2 and shared time/retry budgets unchanged.
Two new/updated route contract failures reproduced the4096 mismatch; final
full offline suite with exact pin plus candidatee9d7166:377 passed,0 skipped
in14.56s. Unfinished-response rejection remains enabled,not weakened to pass.
The next real run must establish whether8192 actually completes the work.

Additional Base readiness: official Base RPC verified the primary PoC's
Nalakuvara attack hash0x16a99aef4fab36c84ba4616668a03a5b37caa12e2fc48923dba4e711d2094699,
chain8453,block30001613,non-creation root selector0x598e2171. Candidate-list
GET to base.blockscout.com returned403; one raw-trace attempt failedHTTPError
(status not preserved by current explorer helper). Probe-only instance
registration did not change project support. Artifact:base-nalakuvara.identity-probe.json.
No model run/full Base pass. Source:
https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/src/test/2025-05/Nalakuvara_LotteryTicket50_exp.sol .


### Mercury normal-profile correction — 2026-11-03

- Revalidated clean starting console HEAD `1dc5bc51199c2e6bdb52008813b0ef17b7405882`. Previous continuation was status-only; this cycle changes the tested request profile.
- Run `e35e90aa01fc` remained partial/INCONCLUSIVE after `completion_finish_reason=length` at8192; no completed chain pass is added.
- Official API reference https://docs.inceptionlabs.ai/api-reference/chat/create-a-chat-completion documents Mercury3 normal budget24576 including reasoning and visible output, temperature default1. Replaced arbitrary8192 normal cap with bounded24576. Legacy temperatures below0.5 map to provider default1; valid explicit0.5..1 preserved. Preflight remains instant/8tokens.
- Inception per-attempt timeout120seconds, other providers unchanged; explicit operator caps remain authoritative. Shared run budget and unfinished-response rejection unchanged. No automatic escalation or retry on truncation.
- Test-first reproduction: `python -B -m pytest tests/test_inception_route.py -q --tb=short`:2failed,14passed before implementation (temperature/default budget assertions).
- Verification: exact pin `fb57c3fad63784b7a63dc7fdf1845364c76ce0b7`, candidate `e9d7166ba9362e5fbaeeb349158d0649efc5632d`; `python -B tests/run_offline.py --tb=line -rs`:378passed,0failed,0skipped (14.72s). `node tests/run_frontend_offline.cjs`:18passed,0failed,0skipped. `python -B tools/sync_static.py --check` and `git diff --check`:passed.
- Kluster tools unavailable; no Kluster verification claimed. No live generation performed for this profile yet; running server still uses previous code. No deployment, merge or protected-branch change. Development/live complete coverage remains0/16 each.


### Development ETH008 — completed transport, correctness NOT passed

- Run `190539aa32a8`, console `62f965ee03eb2830375bbd4ce968150f62b1dea2`, candidate pipeline `e9d7166ba9362e5fbaeeb349158d0649efc5632d`, model `inception/mercury-3`. Started2026-11-03T13:24:29Z; terminal event13:28:58.9Z. Same verified Hedgey setup hash `0xa17fdb804728f226fcd10e78eae5247abd984e0f03301312315b89cae25aa517`, Ethereum.
- Real report and events persisted under local validation directory as `190539aa32a8.json` and `.events.jsonl`. Trace provenance matches requested hash/chain,34frames, Blockscout keyless raw trace with independent RPC identity check; ABI/source unverified.
-53HTTPattempts, preflight1ok, analysis52ok/0failed, transport249.311s of600shared budget; prompt177711, completion78704 (reasoning61034 is a subset), no retry consumed. Pipeline function controller started/completed1; report analysis_status completed, verdict remains INCONCLUSIVE.
-2scored functions and2evidence cards. History entry completed and report reopened through browser. Screenshot `dev-eth-008-completed-review.jpg` in session visualizations directory.
- Correctness NOT passed: output prioritizes callback/oracle-manipulation claims rather than established Hedgey allowance-revocation root cause. Trace targets include Hedgey selectors, but final scored entries are attacker callback and Balancer supply call. Requires tracing evidence selection/model reasoning; not yet a proven cache or provenance mismatch.
- Confirmed UI duplication: renderer concatenates scored_functions and evidence_cards into4findings even though both represent2targets. Also observed-call fallback presents these scored targets as unanalysed. Investigate and regression-test assembly before next model run. Calibration reports99.83% with weak source evidence; validity remains unverified, not accepted as accuracy proof.
- Full correctness coverage stays0/16development,0/16live. No merge, deployment or protected-branch push.


### ETH008 report-display follow-through

- Confirmed from pipeline `core/pipeline.py`: each scored function generates its own evidence card. Renderer previously concatenated both arrays as independent findings. Matching function/address pairs now show one entry containing both scored data and full evidence cards; different addresses remain separate, unmatched records retained. Observed-call list excludes already-scored identities. Raw report/download unchanged.
- Synthetic schema regression first failed (18passed/1failed), then19frontendtests passed. Added versioned JavaScript asset reference after real browser verification initially loaded cached renderer. Reopening actual saved run190539aa32a8 now shows2findings and0unanalysed observation headings.
- Persisted transaction_understanding itself identifies Hedgey selectors as oracle functions and asserts a flash-loan reentrancy/price-arbitrage root cause without verified ABI. This establishes the conflicting explanation exists upstream of rendering; does not yet establish whether prompting, data aggregation or another pipeline behavior caused it. Do not accept99.83% calibration as correctness evidence.
- No additional model requests, deployment or merge in this follow-through. Kluster remains unavailable.


### Confirmed pipeline target-descendant counting defect

- `_prepare_children_call_memo` counted recursively inside each depth-path step, including ancestors/siblings and multiplying descendant counts. Reproduced before fix:1failed/1passed synthetic tests, no model or network. Moved counting after traversal; preserved repeated genuine descendant occurrences and function names containing underscores.
- Actual saved34frame Hedgey setup replay: selector0xefd86b62 count101old/12correct, selector0xf412e4c7 count95old/6correct; each target occurs once. Replay transforms saved raw trace to the memo method schema, verifies topology/counting only, not full normalization or model correctness.
- New pipeline branch `fix/target-descendant-counts` based on development mainfca6b99. Commits `d6fff6b9391e5c5cb4e2be6d00b4986577ddc2d5` and `6d91501be60ef1ce715f538553f53602b24d5e07`. Verified trace fixture includes original trace provenance and source-artifactSHA256; no invented on-chain data.
- Standalone `python -B tests/run_offline_descendants.py tests`:204passed,0failed/skipped (4.30s), network blocked. Earlier combined candidate with synthetic regression:305passed. Console pin+candidate suite after first patch:378passed,0failed/skipped (13.74s). Final combined fixture suite pending at this ledger entry.
- This fixes demonstrably distorted model context. It does NOT prove this was the sole cause of the prior wrong exploit explanation. No fresh model call yet; server has not been restarted onto new candidate. No push, merge or deployment. Kluster unavailable.
