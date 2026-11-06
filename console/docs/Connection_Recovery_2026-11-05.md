# Model connection recovery

The saved failure for run `0f6ed5dc70b8` contains one 62.313-second failed attempt followed by three failures under half a second, no HTTP status, and exhausted shared retries. Its logs do not preserve the underlying connection cause. The original outage cannot be attributed to local DNS/network, TLS, or Inception from this evidence.

A single credential-free GET to the configured default Inception `/models` endpoint returned HTTP 200 before this correction. That establishes current endpoint reachability only; it does not prove model inference/auth readiness or explain the earlier outage.

Changes in `FaultSeeker_Live/app/model_endpoint.py`:

- Analysis connection failures now use 5/10/20-second recovery waits instead of 1/2/4. The retry count is unchanged, waits use existing shared budget reservations, SDK retries remain disabled per attempt, and preflight behavior is unchanged. This may recover a brief outage but cannot guarantee recovery from provider/network failures.
- Sanitized connection subcategories inspect exception classes and OS error codes, never exception messages, URLs, headers, credentials or response bodies. These subcategories are carried in failure metadata and per-attempt events so subsequent DNS/TLS/refusal/reset/proxy/protocol failures can be distinguished where the underlying exception chain permits.

Verification:

- Three new offline mocked HTTP regressions failed before the correction and passed after it: recovery from an outage lasting 12 simulated seconds using the same two retry credits, safe nested DNS classification, and bounded terminal connection failure.
- Full console command: `python -B tests/run_offline.py --tb=short -rs`, with the previously configured local exact-pin and candidate checkout environment variables. Result: **437 passed, 64 setup errors, 0 skips**. The errors are `git rev-parse HEAD` failures, not passing integrations. Both worktree `.git` pointers still exist, but their referenced temporary Git metadata is incomplete (missing HEAD/commondir metadata). Revision verification is blocked. No metadata was reconstructed and no integration checks were bypassed.
- Candidate command: `python -B tests/run_offline_depth.py tests`: **582 passed, 0 failed, 0 skipped**.
- Frontend command: `node tests/run_frontend_offline.cjs`: **30 passed, 0 failed, 0 skipped**.
- `python -B tools/sync_static.py --check` and console `git diff --check` passed.

No new dependency, provider switch, credential change, push, merge or deployment. Kluster is unavailable. A new requested local live test uses the current local files; it must not be represented as a revision-verified release or proof that the historical network outage was fixed.
