# FaultSeeker: consolidated progress and outstanding work

Prepared 5 November 2026, Asia/Calcutta. **Progress report, not an all-clear.**

## Current position

| Question | Honest answer |
|---|---|
| Are both audits completely fixed? | **No.** Fixed, deferred, unverified and policy items are separated below. |
| Is one chain fully correct end to end? | **Not yet. Full scored correctness: 0/16 development, 0/16 live.** |
| What actually works? | Real deterministic Stage1 acquisition, report persistence and history reopening on Ethereum, Optimism and Aurora. These are not full analysis passes. |
| Did Mercury finish? | Latest run completed in161.2s, but returned no scored findings and unsupported reasoning. Workflow completion is not correctness. |
| Did Qwen finish? | Last run stopped incomplete after677.9s. It recovered from one502, then hit the function loop boundary after two cycles. |
| Is anything deployed? | No new deployment or merge. Current remediation is uncommitted local work. |
| Is there a reliable completion percentage? | No. Test counts, read files and duplicated audit rows are not percentages of readiness. |

This report reconciles the earlier47-row O/A/L/R ledger in `docs/astra-audit.md`, the supplied architecture audit's F-01–F-07, the independent findings in `docs/complete-local-audit.md`, and runtime history in `docs/all-chain-ledger.md`. Historical paragraphs retain old counts/statuses; newer evidence only supersedes them within its stated boundary. Original audit documents, frozen datasets/results, weights and papers have not been rewritten to manufacture success.

## Branches and release boundary

- Console: `fix/all-chain-validation`, base `9c8223184df5da882617191636f55542934d5adb`.
- Modified pipeline: `fix/combined-audit-remediation`, base `893fe1a8067c2b2f6fdcbc0899afa4622db76ac0`.
- Clean recovered Docker pipeline pin used in integrations: `fb57c3fad63784b7a63dc7fdf1845364c76ce0b7`.
- Current fixes are uncommitted; base SHAs alone do not identify runtime source. Per-run source hashes were captured for recent runs.
- Historical console PR#5 targets development `main`; earlier PR#4/fix-astra-audit targeted `main1`. Current remote/PR heads have not been freshly verified or updated with this work.
- Last verified live console SHA: `947db7d508f5b93eb603e075b77a77408a91779d` on `main1`. Recent public health recovered from cold-start503 to200, but current deployed console/pipeline revisions remain unverified.
- **Do not deploy the console alone and assume the local pipeline fixes accompany it.** Both diffs, the eventual dependency pin and the release must be reviewed/tested together. No direct main1 push, merge or deployment is authorized.

## Real runs: what failed and what improved

All listed runs occurred on5November. Exact UTC timestamps are in the chronological ledger; durations below are wall-clock.

| Run | Route | Result | Meaning |
|---|---|---|---|
| ef4fafd7836d | Ethereum/no model | 34frames,103.2s; Stage1 complete; history reopened | Real deterministic flow only; no function/scoring pass. |
| e5b586bfb0f3 | Optimism/no model | 37frames,37.5s; Stage1/history passed | Same limited scope. |
| 839f67a86bd3 | Aurora/no model | 24frames,37.8s; Stage1/history passed | Trace identity checked; separately discovered metadata-routing defect still matters. |
| 2db924ee8eca | Mercury3 | 33.3s; preflight passed; malformed transfer data stopped analysis | Revealed Etherscan parser generating blank addresses. Fixed afterward. |
| 526ffa17e8aa | Mercury3/parser fix | 346.6s;67analysis calls succeeded, one null-content failure; partial/INCONCLUSIVE | Parser path progressed. Null was rejected; scoring skipped. Actual partial/history UI passed. |
| e1bd42e0c8c1 | Qwen3.8/earlier revision | 677.9s;21analysis calls succeeded; one502 recovered; analysis_incomplete | First function completed2cycles,571.6s. No scoring/cards; actual partial/history UI passed. |
| 6256ef573489 | Mercury3/understanding fix | 161.2s;29analysis calls succeeded, no endpoint failure; completed with0scores/cards | **Not a correctness pass.** Claimed zero net flow proves reversion and missing calldata. Captured HTML reports Success; authoritative receipt remains unverified. Child-request defect fixed afterward. |

Mercury's latest successful transport does not prove its intermittent null response is solved. Qwen retest `960314e17403` is now active with understanding, child-request and reported execution-context corrections; no terminal outcome yet. Latest Mercury's final rendered report still needs inspection/correction; earlier Stage1 and partial reports were inspected in the actual UI.

Evidence directory: `C:/Users/91701/AppData/Local/Temp/faultseeker-corrected-dev-j5zbp1pa`. It contains per-run JSON, selected screenshots, observations and source manifests. Private credential/session/certificate-key files are not shareable report attachments. Temporary evidence is not a durable published archive.

## Tests: exact latest results and what they mean

| Type | Command | Executed / passed / failed / skipped | Scope |
|---|---|---|---|
| Pipeline regression | `python -B tests/run_offline_depth.py tests` | **503 /503 /0 /0**,14.60s | Unit and controlled cross-module paths, including child-request and reported execution-context fixes. |
| Backend/external-pipeline integration | `python -B tests/run_offline.py --tb=line -rs` | **466 /466 /0 /0**,33.17s | ASGI endpoints, mocked HTTP/SDK, actual imported pinned/candidate modules and guards at documented boundaries. |
| Frontend VM/unit | `node tests/run_frontend_offline.cjs` | **27 /27 /0 /0**,87.6892ms | Rendering, stale-run races, pagination, safe text, failure/coverage/confidence labels. |
| Offline browser | `python -B tests/browser_checks.py --offline` | **12checks passed**,latest recorded run | Real Chromium with controlled API replies; not12chain/provider integrations. |
| Actual local UI | Isolated Chromium against local HTTPS | Selected real Stage1 and partial reports reopened without browser exceptions | Actual history/rendering on those runs; not accuracy proof. |
| SDK compatibility | OpenAI2.36.0/HTTPX0.28.1 with MockTransport; foreign-URL simulation | Included above | Not OpenAI3.37/httpx2 integration; that environment was not installed. |
| Static/diff checks | `git diff --check`; static-sync checks in recorded cycles | Passed in recorded executions | Formatting/copy consistency, not forensic correctness. |

Backend environment:

```text
FAULTSEEKER_TEST_PIPELINE_REPO=C:/Users/91701/Downloads/faultseeker-demo-console-main/pipeline-pin-offline-verified
FAULTSEEKER_TEST_CANDIDATE_REPO=C:/Users/91701/Downloads/faultseeker-demo-console-main/pipeline-audit-fixes
FAULTSEEKER_TEST_CANDIDATE_SHA=893fe1a8067c2b2f6fdcbc0899afa4622db76ac0
```

Mocked HTTP cases include HTML502, JSON500, auth/rotation, quota behavior, timeout, transient recovery, shared-budget preservation/exhaustion, preflight failure, mid-run loss and success exactly at the budget limit. New tests were run failing before fixes where recorded. Earlier failing runs and historical skips remain in the ledger; they are not current passes.

**Limits:** source-pinned integration is not Docker execution. Python socket audit hooks are not an OS-wide subprocess firewall. Cleanup is substantially mocked; real completed workers do not prove every cancellation/OOM race. No full dependency resolution, current container build, production load test, independent calibrated accuracy evaluation or16-chain certification was run. **Kluster was unavailable; no Kluster review was performed or claimed.**

## Supplied architecture audit: all seven findings

| ID | Finding | Current disposition |
|---|---|---|
| F-01 | Gate cookie expiry | **Fixed/tested offline:** timestamped HMAC checked server-side. |
| F-02 | GET diagnostic keys in URLs | **Fixed/tested offline:** POST body; credential query rejected. No historical actual leak claimed. |
| F-03 | Missing finish marker accepted | **Fixed/tested offline:** supported terminal/assistant semantics required. |
| F-04 | Nested partial bypasses normalization | **Fixed/tested offline:** partial stays INCONCLUSIVE across shapes. |
| F-05 | Slow history stream total deadline | **Not reproduced:** per-operation timeout is not strict total wall time; production impact unproved. |
| F-06 | Event cap overshoot | **Fixed/tested offline:** bound complete serialized append under lock. |
| F-07 | Preflight called unlimited | **Retained bounded policy:** count differs from analysis, but shared deadline/time budget bounds it. Not proved unbounded overall. |

## Independent findings: fixed and tested locally

These are distinct implementation areas, sometimes overlapping original audit rows. Do not sum duplicated rows as unique fixes. File names below refer to the console or modified pipeline roots above.

| Area / finding | What changed / proof boundary |
|---|---|
| Worker exceptional exits, replay memory retention | Reap worker before releasing slot; shared replay/live pruning retains20terminal buffers, preserves active workers/disk reports. Fake-process and25dummy replay endpoint tests. |
| Stale frontend result/event races | Run/generation guards; VM and user-reachable controlled Chromium race regressions. |
| Confidence percentages/bool/nonfinite; repeated-pattern schema | Explicit percentage parsing, finite validation, actual pattern lists; no empty-pattern confidence boost. |
| Repeated-pattern dedup | Ordered function/address identity retains distinct patterns without input mutation. |
| Deepest-only finalization / depth confidence bonus | User-approved retain-all-and-rank; validate keys, append omitted findings; depth is context. |
| Downloader path escape/stale scratch/unrelated deletion | Owned per-address temporary directories, sanitized paths, explicit failure; no unowned cleanup. |
| Cache identity/corruption/parser versions | Version/address/chain/schema checks, atomic publication; old caches refetch, not relabelled historically verified. |
| Adjacent-address source substitution | Requested address retained across dict/list/tuple requests; no unverified proxy substitution. |
| Invalid recovered Solidity accepted | Check both lexer/parser errors before extraction/cache publication. |
| Overloads/special functions/one-line spans/multifile collision | Preserve supported overload alternatives and constructor/receive/fallback spans; path-hash names prevent collisions; label binding unverified. |
| ABI/source budget counts model idle | Shared active-I/O accounting preserves existing caps and failure policy. |
| Legacy/TraceNode field loss and missing identity accepted | Preserve caller/input/output/error; validate required identity and valid empty calldata; cycle-aware conversion. |
| Parity call subtype/creation | Preserve action.callType, creation address/initcode in modified candidate; immutable pin unchanged. |
| Deep explorer/signal/graph traversal | Iterative1024-frame checks, cycle rejection, reused siblings retained; cycle enumeration capped with honest truncation metadata. No arbitrary CPU/depth guarantee. |
| Ordinary calls promoted to bypass proof | Preserve observations without inventing exploit proof from selectors, proxies or privileged call names alone. |
| Fake numerical price/profit | Unknown remains unknown; gross movement is not net profit; no token-to-ETH invention. |
| Rule hypotheses seeded as confirmed findings | Remove confirmed-vulnerable framing; preserve uncertainty and require evidence. |
| Calibration validation/runtime feature contract | Validate shapes/finite/trained state; block incompatible feature contracts. Does not validate/retrain scientific model accuracy. |
| Node count misreported as depth / absent state as zero | Structural edge depth and consistent feature keys; unavailable state stays unknown. |
| Source-context scorer wiring | Pass target-specific source; empty/other-function source earns no availability boost. Availability is not vulnerability proof. |
| Fund-flow reuse/schema/own-token/case/numbers | Reset run state; validate roles/amounts; preserve own-token flows; normalize identities; exact bounded Decimal strings. Accuracy remains relative to input labels. |
| HTML transfer addresses / parallel overwrite | Actual captured Etherscan fragment regression; HTMLParser handles attributes/quotes; MultiDiGraph preserves parallel transfers. Captured-page replay:4edges,0blank endpoints. |
| Missing receipt defaults Success | Require explicit status0x1 in RPC fallback; null/unknown/reverted cannot become successful metadata. |
| RPC protocol and explorer errors/diagnostics | Reject malformed batches/envelopes before cache/reward; bounded configured explorer failover; hostname/static diagnostics. |
| Embedded provider credential in current source | Removed with regression. Historical copies/owner rotation remain unresolved; value never displayed or validity tested. |
| Hidden semantic JSON/finding/task failures | Latch exhausted semantic parsing, validate findings, propagate required-task failures; explicit incomplete exits and strict yes semantics. |
| Understanding ignores completed task result | Latest task/result/prior understanding now supplied. Actual-loop controlled tests for both aliases; runtime accuracy still not established. |
| Children tuple contract reversed | Prompt documents(address,function); list/tuple handler reversed it. Two failing cases/dictionary control; corrected real TraceAnalyzer-to-retrieval tests and full495suite. Latest real-model verification pending. |
| Mercury null diagnostics | Finite finish/role and boolean tool/refusal-presence metadata, private/malformed values masked. Null remains rejected; this is diagnostics, not a proven provider cure. |

## Confirmed findings still not fixed, with reasons

| Area | What is left / concrete reason |
|---|---|
| Execution status and evidence grounding | Supply/check authoritative receipt context; zero net flow does not establish reversion. Captured HTML reports Success; NodeFlare returned null receipt and Llama destination validation failed. No receipt status invented. |
| Metadata routing | Eight advertised chains default to Ethereum explorer; six lack builtin metadata fallback. Need chain-correct acquisition/identity tests, not simply a different unverified URL. |
| ContractInfoCollector chain/WAF/latest-state assumptions | Static standalone behavior confirmed; effective console path/provenance still needs full tracing. |
| Unbounded collector curl | Add bounded fetch/subprocess cleanup; whole-worker watchdog is separate. No actual historical hang cause claimed. |
| Empty target narrowing / work accounting | Semantic invalid JSON is guarded, but deliberate empty/malformed narrowing and missing required-target coverage need explicit validation. One analyzed target is not all16ranked candidates. |
| Source availability/coverage warnings | All-unverified supplementary context can disappear; main compilation unit/imports/proxy/block-end limitations remain. Source-provider limits affected Hedgey grounding. |
| Historical source/cache proof | Address/chain envelope is not cryptographic historical binding. Need historical code/ABI/source/proxy/context fidelity before stronger claims. |
| Solidity user-defined value types | Actual valid declaration rejected. Matching grammar/generator unavailable locally; no unsupported regex substitute, download/install or fake compatibility claim. |
| Text CREATE descendants and text depth truncation | Text path differs from corrected structured path; requires text parser-to-sequencer/render integration. |
| RPC logger/cache secret sinks | Console redaction is not proof every underlying library log/persistence sink is safe; full taint review remains. |
| Historical credential action | Owner rotation/history policy pending; no credential change or validity test performed. |
| Mercury intermittent null | Root cause remains unproved; latest non-null run does not establish reliability. Diagnostics now support investigation. |
| Qwen time-limit failure | Real two-cycle failure; latest understanding/child corrections not yet tested in a fresh Qwen full run. Limits not raised to force success. |
| Hybrid router/gate/cost semantics | Standalone confidence/fallback controls and unknown-price-as-zero behavior need implementation or honest capability labels. Direct console route is separately protected. |
| Human feedback | Notes/action mismatch, unapplied first-checkpoint changes, name-only confirmation collision. No abort UI exists; abort speculation dismissed. |
| Common-address registry | Canonical/lowercase mismatch and invalid-length Fantom entry; independently verify identities before replacing data. |
| Link parser/config/summary helpers | Substring-based chain choice, unused max-functions/depth settings and category keys instead of actual summary functions remain. Not all are web reachable. |
| Conditional local eval utility | CSV eval can execute operator-supplied expressions; no web caller/malicious execution established. Replace with literal parsing and strict schema. |
| ConstraintExtractor | Dict unpack returns keys; pocshift namespace unavailable. No application caller; real integration blocked, not substituted with mock proof. |
| Cross-chain CLI accounting | Dry runs/partials count as successes and input CSV labels as detected types. Needs explicit outcome/prediction separation. |
| Research helpers | Unknown-identity correlation, false remediation-keyword suggestions, constant-difference t-test, plaintext-on-hex mempool matching and unknown model prices need fixes/tests. |
| Research metrics | Vector-length/nonfinite/empty-Brier issues, hash-prefix-as-chain grouping, omitted missing predictions/empty-score denominators and name-only localization remain. No frozen rescoring. |
| CSV repair | Confirmed overflow tail duplication; fix/test code before any authorized new repair. Frozen datasets unchanged. |
| Prediction generator/cache | Analyzer never called, uniform0.95, underscore splitting and insufficient cache provenance. Existing outputs are not measured pipeline predictions. |
| Formula-only evaluations | LLM-only/full-system/routing/adversarial formulas do not run claimed variants. Need honest scope/new manifested evaluation, not paper/holdout rewriting. |
| Research exports/provenance | Hardcoded sample/retention values, copied hardening ablation and CSV/LaTeX/doc disagreements. Which historical run is authoritative remains unresolved. |
| Validity/test shim | String-based pass claims ignore process/import/skipped coverage and pytest semantics. Current counts use actual pytest; shim still needs fixing. |
| Dataset/incident import assurance | Candidate labels, whole-incident overlap, duplicate-row counting, null trace/receipt and validation-as-truth risks need adjudication. Manifests often correctly retain candidate scope; specific mislabels not independently proved. |
| Frozen ground-truth identity | One filename/hash mismatch confirmed. Source adjudication required; no expected output changed to fit code. |
| Valid calibrated model | Runtime gating fixed; no independently evaluated replacement calibration artifact/data produced. |
| Mobile preset popup | Actual360px popup overflow reproduced; baseline viewport checks did not open it. Scoped CSS plus interaction regression pending. |
| Documentation/license/build | README branch/research/license drift; Foundry immutable asset/digest and full dependency/container reproduction not finished. No fabricated hash/license interpretation. |
| Full release/16chains | Need finalized-source Mercury and Qwen results, scored findings/evidence/ground truth, every advertised chain dev and approved live, exact deployed SHA and required review/rollback/deployment approval. |

## Claims not established or narrowed

- A generic deep-trace crash is not proved by one direct-library recursion failure; specific boundaries were tested/fixed, arbitrary depth remains unproved.
- Adaptive integer depth/index-path, hash-parser partial failures and constraint cycles have remaining effective-path questions; not every static suspicion is a production bug.
- No SSRF bypass, shared Render client-IP failure, slow-stream remote denial of service, arbitrary graph CPU bound or historical OOM cause was independently established.
- Current HTML does not load retained old compiled bundles; no active legacy-bundle exploit proved. Their complete semantic review remains pending.
- Generated listener/lexer/parser AST screening and selected grammar tests are not every-line grammar correctness/generation-provenance verification.
- Uppercase0X is not an invalid-length address. Extra location markers are not automatically corrupt ground truth; incident interpretation remains necessary.
- The local retrieval prompt's braces do not cause a format crash because that prompt is concatenated. The separate tuple-order bug was real.
- Replay acquires the run lock. Current frontend overrides partial verdicts. Separate retention/API/race issues were real and fixed.
- Synthetic controls, schema scans, successful API calls and saved benchmark files are not independent forensic accuracy evidence.

## Decisions and remaining order of work

Already answered/implemented: required gate and shared admitted-user history; public-only visitor RPC with resolved-address/redirect enforcement; separate OpenAI routes; retain/rank all analyzed findings and show depth as context. Existing approved Mercury/Qwen APIs may be used without repeated dashboard gating; free-only, no quota evasion, bounded requests and secret protection still apply.

Optional policy changes have not been silently made: request quota versus accepted-run quota, retrying empty answers, deleting historical data/hostnames, raising time limits, or changing production concurrency/strict resource budgets. No new permission is needed just to fix confirmed defects.

Next work: (1) trustworthy execution/receipt and child/target context, (2) explicit work/source coverage and chain metadata, (3) separate finalized-revision Mercury/Qwen runs and factual report checks, (4) remaining credential/collector/tool/operational fixes, (5) research code/provenance without frozen-result changes, (6) remaining file/artifact audit coverage, (7) all16development and approved-live chain tests, (8) reviewed pipeline+console publication/release with explicit deployment approval and rollback verification.

**Audit inventory is not complete.** Prior inventory recorded66console and339pipeline files with pending artifact/generated/data semantic coverage; new tests/docs add files. Read/AST/schema counts are not an all-clear. No project completion percentage or production-ready label is justified.

## Earlier combined audit: original47-row reconciliation

The next table preserves every original reference, including reused/overlapping IDs. Current evidence scope is the local suites above and the original test boundaries—not deployment or Docker execution.

| Original reference / finding | Current status | Scope / remaining work |
|---|---|---|
| O1 RPC diagnostic credential leakage | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| O2 Malformed history summary wedges run lock | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| O3 Endpoint normalization breaks rotation | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| O4 / A12 Same-provider stage keys overwrite each other | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| O5 / A11 Seven integrations used different pin | Fixed and tested offline | Exact pin recovered; current pinned/candidate integrations executed with zero skips. Not Docker execution. |
| O6 Visitor RPC private destination / DNS / redirects | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| A1 All OpenAI models routed to proxy | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| A2 Unused Docker timeout variable | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| A2b 600-second budget vs 7,200-second watchdog | Not reproduced / not established | They bound different scopes: model transport vs whole analysis. Different limits alone do not prove a defect. Overall watchdog unchanged. |
| A2c Serialized model calls despite stage workers | Fixed and tested offline | Current transport permits overlap with shared reservation/accounting; current free-provider runs use one stage worker. No measured throughput guarantee. |
| A3 Successful creation transaction rejected | Fixed and tested offline | Creation identity tested through normalization, sequencing, flattening and ranking. No real creation/model correctness pass. |
| A3b Older Parity creation parser | Fixed and tested offline | Parity creation address/initcode fixed in modified candidate. Immutable original pin is not edited or deployed with these changes. |
| A4a Invalid/busy requests consume analysis quota | Design decision / retained policy | Invalid/busy requests count toward request quota. Accepted-run-only counting would change abuse policy. |
| A4b Render proxy gives everyone same IP | Not reproduced / not established | Uses `request.client.host`; deployment forwarding/trusted-proxy configuration unavailable offline. No unsafe unconditional forwarded-header trust added. |
| A4c Rate-limit IP map unbounded | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| A5a Unicode gate input crashes | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| A5b Gate brute-force attempts unbounded | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| A5c Missing gate exposes server keys | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| A6a Token redaction destroys USDC/WETH evidence | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| A6b Broad field-name redaction hides benign evidence | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| A7 Empty completion latches endpoint failure | Design decision / retained policy | Empty/null output fails closed; automatic empty-answer retry not introduced. Actual Mercury null root cause unresolved. |
| A8 Fabricated verdicts/measurements and substring hints | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| A9 Deep traces always crash near 600/1,100 frames | Not reproduced / scope narrowed | Universal deep crash not established. Specific1024-frame traversal defects separately fixed; not arbitrary-depth proof. |
| A10 Initcode/empty calldata mislabeled as function | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| A11b Local launchers follow moving branch | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| A12 Static root/404/config drift | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| A13 Missing capture gives 500 | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| A14a History mirror may be public | Fixed and tested offline | Private mirror metadata required; tests use mocks. Current remote visibility/old publication not independently verified. |
| A14b History restore blocks module import/startup | Fixed and tested offline | No network on import; background restore/merge/redaction tested. Not strict slow-stream total-deadline proof. |
| A15 Shared history access | Fixed and tested offline | Mandatory gate and shared history among admitted users were explicitly chosen; no per-user isolation promised. |
| L1 Late cancellation corrupts finished run status | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| L2 Restart leaves runs shown as active | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| L3 SSE terminal event inherits duplicate ID | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| L4 Seeded cache written under wrong cwd | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| L5 Historical Hedgey saved label is unverified | Confirmed but deferred | Historical capture kept unverified/partial; do not rewrite old results to fit newer evidence. Historical401 not claimed solved. |
| L6a Generated runs/cache/logs tracked | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| L6b Tracked Python bytecode | Not reproduced / not established | `git ls-files` shows no tracked __pycache__ or .pyc files. |
| L6c Provider/account hostname in historical samples | Design decision / retained policy | Historical provider/account hostname provenance retained; credential values redacted. Historical sanitization/deletion policy unresolved. |
| L7 Foundry stable download not checksum-pinned | Confirmed but deferred | No verified immutable Foundry asset/digest/build workflow completed; no fabricated hash. |
| L8a Container runs as root | Fixed and tested offline | Non-root user/ownership statically tested; current container runtime permissions unverified. |
| L8b Full dependency reproducibility | Confirmed but deferred | Exact source available now; full transitive lock/artifact verification and reproducible Docker execution still incomplete. |
| L9 App transport dependencies implicit | Fixed and tested offline | OpenAI2.36.0/HTTPX0.28.1 declarations and local tests; not full resolver/container proof. |
| L10 Ignored fallback_model option | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| L11 Stage worker option allows five, upstream caps four | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |
| R1 Foreign SDK URL object crashes preflight | Fixed and tested offline | Actual local SDK plus simulated foreign URL normalization. Not OpenAI3.37/httpx2 integration. |
| R2 Fork inherits stale RPC provider registry | Fixed and tested offline | Registry refresh after visitor relay tested at recovered pin/candidate boundaries; not all deployment/fork behavior. |
| R3 Cleanup exception skips relay/env/stream cleanup | Fixed and tested offline | Original correction retained; current offline regressions pass within the detailed original test boundary. Not deployment proof. |

These47rows are a reconciliation of historical findings, not47independently deployed fixes. Several overlap F-findings and the independent catalog. Detailed original reproductions remain in docs/astra-audit.md; current corrections/runtime limits are in docs/complete-local-audit.md and docs/all-chain-ledger.md.

## Post-report update: execution context and active retest

Both analysis entry paths now receive source-attributed reported status, explicitly receipt-unverified, with the distinction that zero net flow does not establish reversion. Eight new regressions; pipeline503passed/0failed/0skipped. Authoritative receipt binding and factual accuracy remain unresolved. Qwen960314e17403 is the active retest; Mercury still needs final-revision verification afterward. No completed correctness pass or deployment is claimed.
