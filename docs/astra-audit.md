# Combined audit follow-through

Branch: `fix/astra-audit`; PR #4 targets `main1`. Base remains `7259d9573f2ef91368c797387e9b025b14dd5247`.
This ledger supersedes the first-batch report. No merge, deployment, remote access, downloads, installs, live RPC or live model calls were performed in this follow-through. The current local changes have not been pushed under the local-only restriction.

## Status definitions

- **Fixed and tested**: verified within the explicitly stated local test boundary; not a claim of deployed or exact-pipeline verification.
- **Confirmed but deferred**: evidence exists, but the stated blocker prevents completion.
- **Not reproduced with evidence**: the claim was not established in the examined environment; limitations are explicit.
- **Design decision requiring your answer**: existing behavior retained pending the specified policy choice.

## Finding-by-finding ledger

| ID / finding | Status | Evidence, fix and scope |
| --- | --- | --- |
| O1 RPC diagnostic credential leakage | Fixed and tested | `app/server.py:524`: parsed hostname only; URL userinfo/query credential regressions in `tests/test_server.py`. |
| O2 Malformed history summary wedges run lock | Fixed and tested | Summary type checks and unconditional stream/lock finalization; malformed-summary regression. |
| O3 Endpoint normalization breaks rotation | Fixed and tested | `app/model_endpoint.py`: registration and client lookup normalize `str(url)` first; dummy 401-to-second-key-200 mock HTTP test. |
| O4 / A12 Same-provider stage keys overwrite each other | Fixed and tested | Model-specific key pools and explicit route/key override; shared budget remains run-wide. Mocked pipeline-hook tests; exact pipeline integration still blocked below. |
| O5 / A11 Seven integrations used different pin | Confirmed but deferred | Fixture now reads Docker SHA, but exact `fb57c3fad63784b7a63dc7fdf1845364c76ce0b7` is absent locally. Seven skips, not passes. Changing the expected SHA alone is not verification. |
| O6 Visitor RPC private destination / DNS / redirects | Fixed and tested | `app/rpc_transport.py`: check all resolved addresses, pin numeric TCP destination, retain TLS hostname verification, reject redirects, invalid JSON and oversized responses. Worker routes user URLs through loopback relay. Mocked DNS/HTTP/socket regressions; real transport and exact pinned pipeline not exercised. Older actual provider forwarding to private destinations reproduced with mocked `urlopen`. |
| A1 All OpenAI models routed to proxy | Fixed and tested | User decision implemented in `app/model_routes.py`, runtime and diagnostics: only `gpt-6.1-sol-*` uses proxy; other OpenAI models require separate endpoint/keys. Missing configuration fails before requests; implicit model calls also obey route policy. |
| A2 Unused Docker timeout variable | Fixed and tested | Explicit 300-second call timeout and 600-second shared model budget; precedence regression and Docker configuration inspected. No image build. |
| A2b 600-second budget vs 7,200-second watchdog | Not reproduced with evidence | They bound different scopes: model transport vs whole analysis. Different limits alone do not prove a defect. Overall watchdog unchanged. |
| A2c Serialized model calls despite stage workers | Design decision requiring your answer | Session serializes calls under a lock to make rotation and shared budgets deterministic. It can reduce throughput. Retain conservative serialization or authorize a separate concurrent-budget design? No silent concurrency change. |
| A3 Successful creation transaction rejected | Fixed and tested | Receipt-bound creation root, caller and initcode checks. Synthetic real older-pipeline geth normalization -> sequencer -> flattening -> ranker preserves target. Coverage ends before function/model analysis; exact pin unavailable. Failed creations without a verified deployed address remain rejected. |
| A3b Older Parity creation parser | Confirmed but deferred | Actual available `bc98bfd8cc6903363955da72792db112757172c0` normalizer loses creation address/input. Probe records both false. This external old checkout is not the Docker dependency; cannot justify patching or claiming behavior at missing `fb57...`. |
| A4a Invalid/busy requests consume analysis quota | Design decision requiring your answer | Existing semantics count requests, including invalid/busy ones; regression preserves this. Message now says analysis request limit. Retain request quota (limits abuse), or add a separate accepted-run quota? |
| A4b Render proxy gives everyone same IP | Not reproduced with evidence | Uses `request.client.host`; deployment forwarding/trusted-proxy configuration unavailable offline. No unsafe unconditional forwarded-header trust added. |
| A4c Rate-limit IP map unbounded | Fixed and tested | Expiry pruning and 4,096-IP cap; refuses new entries at capacity instead of evicting live quotas. Regression covers expiry/cap. Process-local scope remains. |
| A5a Unicode gate input crashes | Fixed and tested | UTF-8 byte comparison; Unicode password/cookie regressions. |
| A5b Gate brute-force attempts unbounded | Fixed and tested | Ten attempts per IP per 15 minutes, HTTP 429 and Retry-After; bounded state. This is not per-user or distributed throttling. |
| A5c Missing gate exposes server keys | Fixed and tested | User chose required gate: missing configuration returns 503; admitted cookie required. Health and gate form remain reachable. |
| A6a Token redaction destroys USDC/WETH evidence | Fixed and tested | Ordinary token descriptions retained while known values and URL token parameters remain masked. |
| A6b Broad field-name redaction hides benign evidence | Fixed and tested | Exact/suffix credential names after case/separator normalization; regression preserves authorization_checks, secret_extraction_evidence and password_reset_event while masking credential values, plural credential lists and common key/header forms (12 additional regressions). |
| A7 Empty completion latches endpoint failure | Design decision requiring your answer | Confirmed fail-closed behavior; no normal verdict after missing model output. Keep immediate failure or permit a bounded retry within the existing shared allowance? Frequency/provider claims were not independently measured. |
| A8 Fabricated verdicts/measurements and substring hints | Fixed and tested | Unknown measurements stay null; missing verdict stays INCONCLUSIVE; explicit classifications preserved. Backend adaptation and frontend tests. No forensic metrics invented. |
| A9 Deep traces always crash near 600/1,100 frames | Not reproduced with evidence | Console utilities are iterative and unit-tested at 1,024 frames. Actual older pipeline sets recursion limit 20,000; normalizer, deepcopy, both converters, TraceNode and JSON all returned at 1,024. Does not prove arbitrary depth or missing exact pin; earlier isolated recursion result cannot establish full-pipeline crash. |
| A10 Initcode/empty calldata mislabeled as function | Fixed and tested | CREATE/CREATE2 and selectorless frames have explicit identity kinds. A 0x sentinel is not claimed as an ABI-verified function. |
| A11b Local launchers follow moving branch | Fixed and tested | Both read Docker SHA, reject tracked dirty checkout, checkout detached and verify HEAD. Static contract tests only; download/install launchers deliberately not executed. |
| A12 Static root/404/config drift | Fixed and tested | `tools/sync_static.py` generates/checks root assets, index and config; root 404 is a small return page. Source-byte contract test, VM frontend tests and offline Chrome walkthrough pass. |
| A13 Missing capture gives 500 | Fixed and tested | Explicit 404; backend regression. |
| A14a History mirror may be public | Fixed and tested | Mirror/restore require metadata with private=true, otherwise fail closed; mocked visibility/network-failure tests. Actual remote visibility not queried. Previously published data is not erased by this change. |
| A14b History restore blocks module import/startup | Fixed and tested | No network on import; background lifespan restoration with 30-second scheduling window checked between fetches. Per-read socket timeouts are not a strict slow-stream wall deadline. Merge preserves newer local index entries; malformed IDs/data rejected and restored data redacted. |
| A15 Shared history access | Fixed and tested | User explicitly selected shared history for all admitted visitors; mandatory gate protects API access. No per-user ownership/isolation is promised. |
| L1 Late cancellation corrupts finished run status | Fixed and tested | Finishing marker synchronized with bus, reject already-dead/terminal workers before mutating cancellation state; preserve cancellation before process registration. Regressions cover both races. |
| L2 Restart leaves runs shown as active | Fixed and tested | Startup/list reconciliation marks persisted active entries without in-memory runs interrupted; regression. |
| L3 SSE terminal event inherits duplicate ID | Fixed and tested | Terminal/replay-gap listeners bypass normal event dedup; heartbeat now named event. Browser/VM regressions retain report retrieval and visible gaps. |
| L4 Seeded cache written under wrong cwd | Fixed and tested | Docker and both runners seed working-directory data/cache/forensics. Static contracts and older pipeline cwd inspection; no container execution. |
| L5 Historical Hedgey saved label is unverified | Confirmed but deferred | Historical capture retains explicit historical_unverified/partial warning. No newly verified trace/source ground truth or approved live run exists to replace it; do not rewrite historical evidence to manufacture a correct label. Historical 401 also remains unexplained. |
| L6a Generated runs/cache/logs tracked | Fixed and tested | Nine runtime artifacts removed from Git tracking while local files preserved; ignore patterns added. Tracking/diff check verifies removal. Historical Git objects are unchanged. |
| L6b Tracked Python bytecode | Not reproduced with evidence | `git ls-files` shows no tracked __pycache__ or .pyc files. |
| L6c Provider/account hostname in historical samples | Confirmed but deferred | Hostname provenance retained in historical evidence; token remains redacted. Removing account-identifying hostnames from old artifacts/history needs an explicit retention/sanitization policy. No claim that historical Git data has been purged. |
| L7 Foundry stable download not checksum-pinned | Confirmed but deferred | Docker still downloads stable. No verified Linux release asset/hash available locally; downloads prohibited. A fabricated hash or untested release pin would not fix supply-chain verification. |
| L8a Container runs as root | Fixed and tested | Docker declares uid10001 faultseeker and owns /srv. Static test only; Docker daemon unavailable, so runtime permissions remain unverified. |
| L8b Full dependency reproducibility | Confirmed but deferred | Direct OpenAI/HTTPX versions now pinned to locally tested versions. Full transitive lock/resolution needs missing exact pipeline requirements and dependency artifacts; no installs permitted. |
| L9 App transport dependencies implicit | Fixed and tested | Direct openai==2.36.0 and httpx==0.28.1 declarations; installed versions used in regressions. No install/resolver validation. |
| L10 Ignored fallback_model option | Fixed and tested | Nonempty unsupported fallback now HTTP 400; no silent alternate-provider fallback. |
| L11 Stage worker option allows five, upstream caps four | Fixed and tested | API validates 1..4, matching available upstream; backend regression. Exact dependency behavior still unverified. |
| R1 Foreign SDK URL object crashes preflight | Fixed and tested | Stringify before HTTPX construction. Simulated foreign URL contract plus actual local OpenAI2.36 mocked 401 rotation pass. OpenAI3.37/httpx2 not installed: NOT an SDK3 integration result. |
| R2 Fork inherits stale RPC provider registry | Fixed and tested | Runtime rebuilds registry after relay env installation, fail-closed if expected registry hooks absent. Real available older pipeline probe confirms registry changed. Exact pin blocked. |
| R3 Cleanup exception skips relay/env/stream cleanup | Fixed and tested | Runtime and relay cleanup isolated; injected failures in either still close both resources, restore stdout/stderr/environment and emit end. Error logged without exception text. |

## Local validation

| Exact command | Executed | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: | ---: |
| `python -B tests/run_offline.py -x --tb=short -rs` | 196 | 196 | 0 | 7 |
| `node tests/run_frontend_offline.cjs` | 13 | 13 | 0 | 0 |
| `python -B tests/browser_checks.py --offline --headed --artifacts C:\Users\91701\AppData\Local\Temp\faultseeker-astra-followthrough-browser` | 11 checks | 11 | 0 | 0 |

The backend run collected 203 cases; 196 executed, seven skipped, zero deselected, 25.68 seconds. Python runner removes inherited credentials, disables dotenv/plugins, uses temporary storage and blocks external sockets. Only thread-scoped Windows asyncio socketpair setup is permitted. Frontend VM blocks network APIs. Chrome uses fixture routes, blocked external hosts and an unusable proxy; it does not test the deployed backend or access gate end-to-end. Two earlier sandboxed attempts stalled and were interrupted; successful runs used the same offline harnesses outside that sandbox.

Additional checks passed: `python -B tools/sync_static.py --check`, `git diff --check` and `git diff --cached --check`. A local common-pattern credential scan of 37 changed/new files found no matching credential patterns; this is not proof that the entire repository/history is secret-free. `git ls-files` confirms no tracked runtime artifacts or Python bytecode.

Additional exact probe command:

```text
python -B tools/probe_local_pipeline.py --repo C:\Users\91701\AppData\Local\Temp\faultseeker-pipeline-investigation
```

Exit 0, zero network calls. Actual local pipeline HEAD `bc98bfd8cc6903363955da72792db112757172c0`, NOT Docker pin `fb57c3fad63784b7a63dc7fdf1845364c76ce0b7`. Synthetic geth creation passed sequencing/flattening/ranking; Parity creation mismatch reproduced; registry refresh true; all six 1,024-frame paths returned. Probe is additional evidence, not seven replacement integration passes or on-chain target verification.

Installed local environment: OpenAI2.36.0, HTTPX0.28.1; httpx2 absent. User-reported external 139-backend/11-frontend passes used OpenAI1.109.1 and exact pin in /tmp/fork. Their SDK3.37 failure used a different environment. Neither external run was independently rerun here, and they are not included in local counts.

## Configuration and deployment preview

- Set `DEMO_GATE_PASSWORD`; unset configuration intentionally blocks use (503). All admitted visitors share history/reports.
- Set `CODEX_PROXY_BASE_URL` for `gpt-6.1-sol-*`; legacy `OPENAI_BASE_URL` remains a fallback for this family only. Matching key variable is `OPENAI_API_KEY`.
- Other OpenAI models require `OPENAI_DIRECT_BASE_URL` and matching `OPENAI_DIRECT_API_KEY` (or explicit request model keys). There is no proxy fallback. Other configured providers retain their provider routes.
- Visitor RPCs must resolve entirely to public addresses; redirects are rejected. Operators must supply the final endpoint. No visitor private-address exception or internal-RPC allowlist is introduced.
- GitHub history is optional/best-effort and must be private. A metadata failure disables restoration/mirroring; local history remains available. Gate and quotas are process-local, shared-password controls, not a multiuser or distributed service.
- Keep the existing serialized model policy, finite shared retries/time budget, fail-closed empty completions and request-count quotas until the three policy questions above are answered.

No deployment preview service was started. Offline UI screenshots are in the artifact directory above. Docker CLI exists but its Linux daemon pipe is absent, so no build/container check was possible. Exact pinned integration, SDK3 integration, live RPC/model behavior, Render proxy-IP behavior, proxy ownership and historical 401 root cause remain unverified. Kluster tools are unavailable; no Kluster verification is claimed.

Every listed audit item is accounted for; the deferred items and open policy decisions mean the combined task is not declared fully resolved or deployment-ready.
