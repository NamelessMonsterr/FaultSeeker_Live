# Astra audit corrections

Base: `main1` at `7259d9573f2ef91368c797387e9b025b14dd5247`.
Branch: `fix/astra-audit`. Review target: `main1`.

## Problems and resulting behavior

- RPC diagnostics exposed credentials in URL userinfo or slashless query strings. The returned host now comes from URL parsing and contains no userinfo, path or query.
- Malformed history summaries could leave the global analysis lock held indefinitely. Summary inputs are type-checked and the entire finalization path unconditionally closes the stream and releases the lock.
- SDK URL normalization could prevent credential rotation. Registration and lookup now use the same HTTPX canonicalization.
- Explicit forensics keys were overwritten when stages shared a provider. Transport credential pools are now scoped to endpoint/model, using explicit stage key lists. All pools still share the run's analysis retry allowance and time budget; preflight retains its existing bounded deadline policy. SDK retries remain disabled.
- Generic token redaction removed legitimate USDC/WETH evidence. Known credentials, credential fields and token URL query parameters remain redacted, while ordinary token descriptions are preserved.
- Report adaptation synthesized verdicts and missing measurements. Missing measurements now remain null/unknown, absence of an explicit verdict stays INCONCLUSIVE, and explicit classifications survive adaptation. Partial states remain INCONCLUSIVE.
- Local trace conversion and traversal recursed through deep call stacks. Both are iterative and tested with 1,024 frames.
- CREATE/CREATE2 initcode prefixes were mislabeled as calldata selectors. Creation and selectorless frames now have explicit identity kinds.
- Root provenance checks rejected successful deployment transactions by comparing null transaction.to to a created address. Creation roots now require a matching transaction receipt and deployed address, plus the existing caller/calldata checks. Ordinary calls retain destination checks. Failed creations without a verified deployed address remain rejected.
- Docker configured an unused timeout variable. It now explicitly configures the shared transport's 300-second per-call cap and 600-second cumulative budget. The old timeout variable remains a fallback for existing installations. The enclosing 7,200-second run watchdog is unchanged.
- Integration tests used a different external revision from Docker. Their expected SHA is now read from Dockerfile, so a stale checkout fails verification.
- Non-ASCII gate input no longer raises a string-comparison TypeError. A missing saved capture returns 404 rather than failing inside FileResponse.

## Verification

All model HTTP in regression tests is mocked. The runners block external socket connections, remove inherited credential variables, disable dotenv, and direct run files and pytest scratch data to temporary directories. Windows asyncio's own socketpair setup is allowed. No agents, live model calls, dependency installs or pipeline downloads were used.

| Command | Executed | Passed | Failed | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: |
| `python -B tests/run_offline.py` | 132 | 132 | 0 | 7 | 0 |
| `node tests/run_frontend_offline.cjs` | 11 | 11 | 0 | 0 | 0 |
| `git diff --check` | 1 | 1 | 0 | 0 | 0 |

The Python suite includes the existing local thread-isolation regression; no AI workers were used. Added checks cover credential leakage, URL canonicalization/rotation, model-specific keys and shared-budget exhaustion, timeout precedence, unconditional finalization, unknown report measurements, creation identity and provenance, deep traversal, Unicode gate input and missing captures. The frontend check confirms missing scores are not rendered as zero or a successful verdict.

## Remaining limitations and review boundaries

- Seven exact-pipeline integration cases were skipped. Docker pins `fb57c3fad63784b7a63dc7fdf1845364c76ce0b7`, which is not available in the local external checkout. Passing tests against another SHA would not verify this dependency. No claim is made that these seven tests passed.
- Set `FAULTSEEKER_TEST_PIPELINE_REPO` to an already-available checkout at that exact SHA and rerun `python -B tests/run_offline.py` to exercise those integrations with mocked HTTP. Do not change the pin merely to make tests pass.
- Creation/deep-trace tests use synthetic unit inputs, not newly verified on-chain fixtures. Existing Hedgey trace provenance is unchanged. External parser, ranker, serialization and visualization behavior at extreme depth remains unverified; this PR fixes the console's two recursive utilities, not every upstream recursion path.
- No Docker build, real browser walkthrough, live RPC/model run, Render proxy-IP check, proxy ownership check or GitHub-history visibility check was performed.
- The earlier possible SSRF concern is not resolved by this PR. Custom private RPC URLs are still accepted; actual reachability through the pinned transport remains unverified. Network egress policy requires a separate transport-level design, including DNS and redirects.
- Optional shared authentication/history, login throttling, static mirror drift, moving-branch local bootstrap scripts, history startup behavior and the other unverified claims in the pasted audit are outside this confirmed-finding patch. The configured model endpoint has not been switched.
- Kluster tools were unavailable; no Kluster verification is claimed. Review was performed directly with local regression tests and diff inspection.

## Deployment preview

This is a code-review PR only. It does not deploy a preview or change `main1`. On a future approved deployment, live RPC diagnostics expose only hostnames, report consumers must handle null measurements, and model calls use the explicit transport timeout settings above. The external-pipeline integration gap should be resolved before deployment approval.
