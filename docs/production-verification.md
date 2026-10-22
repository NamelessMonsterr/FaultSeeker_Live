# Production console verification

## Scope

This change implements the two approved setup/progress designs and hardens the live FastAPI service. Saved captures require explicit selection and carry a recorded-data label. Live failures never trigger a saved-result fallback. Reports preserve forensic evidence, underlying analysis fields, scope limitations, and full JSON export. Large finding lists paginate without removing data.

## Security and reliability controls

1. History escapes all interpolated fields, including top function names; analysis models and hashes are validated before history writes. The new UI uses DOM text APIs for untrusted values.
2. Diagnostic requests pass caller keys directly to provider clients. They never mutate the parent environment, including concurrent requests and import failures. Stage-2 probes with caller keys are explicitly unsupported; live analysis isolates those keys in a child process.
3. Recursive redaction covers structured SSE payloads, persisted events, history, result responses, request keys, server keys and RPC credentials. Keys never enter browser storage.
4. Missing evidence does not imply a clean transaction. Explicit upstream scope/status is retained; incomplete, cancelled and failed reports remain inconclusive. Pipeline output is private until the final result is atomically published. Requests for in-progress reports return 409.
5. Disk, thread and child-process startup failures release the run lock. Cancellation is checked during startup and monitoring. Final status/history are established before terminal SSE delivery.
6. Diagnostic calls have per-network quotas and a maximum of three key probes. Existing live-run quotas remain enforced.
7. SSE uses bounded per-run event buffers, independent client cursors, event IDs, Last-Event-ID/after support, replay-gap notices and heartbeats. Recent terminal stream buffers are capped in memory; stored reports remain accessible.
8. Docker fetches and checks out the exact pipeline commit, independently of branch movement, and verifies the resulting SHA.

Run IDs are also validated against Windows path traversal. Authentication failures return JSON 401 to API clients rather than HTML redirects. Local/generated caches and private runtime files are excluded from Git/container inputs.

## Reproduce checks

Use an environment containing the app requirements, `pytest`, `httpx`, and Playwright for browser verification. The browser script uses an installed Chrome when available, otherwise Playwright Chromium. No frontend build or package manager is required.

```text
python -m pytest tests/test_server.py -q
node --check app/web/assets/console.js
node --test tests/frontend.test.cjs
python app/server.py
python tests/browser_checks.py --url http://127.0.0.1:8420
git diff --check
```

The backend regressions isolate provider calls with controlled stubs. Browser checks use actual Chrome and EventSource with controlled API fixtures, plus the real local server's bundled capture. They cover form validation, live progress, safe completion, reconnect/reload, cancellation, history, 360/768px layouts, long logs, rate-limit errors, XSS-safe evidence, and findings pagination. These do not constitute a paid end-to-end RPC/LLM run.

## Deploy and operate

- Run one server process per instance: the run admission lock and active SSE buffers are process-local. Horizontal scaling requires shared coordination and durable event storage.
- Set `FAULTSEEKER_REPO` to the installed pinned pipeline. Configure its RPC/LLM providers in the deployment environment. Set `DEMO_GATE_PASSWORD` for access control on a public deployment (the variable name is retained for compatibility). Never put credentials in Git.
- For persistence across replacement/redeploy, set `FAULTSEEKER_RUNS_DIR` to a mounted durable directory. An ephemeral free-tier filesystem does not provide production durability. History lists retain the latest 200 entries; apply a retention policy to stored report files appropriate to your deployment.
- Operator-supplied RPC endpoints are trusted network destinations. Restrict outbound access at the deployment/network layer, especially access to private infrastructure and metadata endpoints.
- The Dockerfile retains the existing `OPENAI_BASE_URL` proxy configuration for compatibility. Configure/verify the provider endpoint and associated credentials for your deployment before enabling live model usage.
- Publishing this branch does not prove deployment succeeded. After deployment, verify `/healthz`, authentication, provider configuration, one real known transaction, its report and a reconnect. Review provider charges and service logs.

## Verification limits in this workspace

Final local verification: 53 backend tests passed, 8 frontend regressions passed, and 9 real-Chrome checks passed. JavaScript syntax and Git whitespace checks passed. A separate real-server saved-replay integration verified early-result 409 protection, final status publication, valid report shape and identical independent SSE replay. No uncaught browser exceptions were observed in the covered flows.

Kluster tools were unavailable. The local checkout has no installed FaultSeeker pipeline; a paid external RPC/LLM run was not performed. Docker Desktop's engine was unavailable, so the full container build was not executed. The exact pinned public pipeline source was inspected to verify entry-point/output and RPC URL contracts. Automated backend and browser checks exercise the local application and controlled provider boundaries; production provider credentials, quota, latency, deployment storage and proxy operation still require deployment verification.
