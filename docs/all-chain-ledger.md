# All-chain analysis evidence ledger

## Current scope and identity (2026-11-02)

Goal: a real, suitable transaction analysis on development and approved live for every chain advertised by the console. A pass requires completed stages, scored functions, evidence, persisted/reopened history and conclusions checked against available ground truth. No chain has passed this cycle yet. No model requests have been made.

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
| eth | Blockscout instance; RPC trace | unset | BLOCKED / BLOCKED | not run | quota and authenticated app access pending |
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
