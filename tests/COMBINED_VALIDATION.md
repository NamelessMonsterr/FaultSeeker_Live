# Local pipeline combination rehearsal

Base: pipeline main fca6b998fa0a01f3832be6a0f1aa1d768306da8f.
Separate queued patches combined locally:

- Calibration c58bc699429e37e3a959ddc971b5b8c1713cb530, pipeline PR3.
- Parity c076a4cec07b35d022020653dc17f6e505cdaf96, pipeline PR4.
- Depth72e6ad77d7a8d7230b461189eba9bc033d631187, pipeline PR5.

No PR/protected branch was merged. This new local validation branch preserves
the component branches. Applying depth over Parity produced a patch overlap in
rpc_provider.py; resolution keeps the iterative normalizer, calls the Parity
creation helper, retains provider metadata in tree assembly and guards result
output types. Independent read-only review confirmed neither fix was lost.

```powershell
python -B tests/run_offline_depth.py tests
git diff --check
```

Result:269 executed/passed,0failed/skipped,15.17s; diff check passed. The extra
cross-patch test retains1024 Parity CREATE frames through normalization and
TraceNode conversion with exact initcode/address assertions, then verifies
calibrated reporting retains its original heuristic and coherent label.
Synthetic inputs only; no fabricated on-chain ground truth or paper metric.
Network sockets blocked, no installed packages or live provider calls.

This does not verify complete console/model reasoning, current RPC data, Docker
or live deployment. The application-entrypoint recursion policy and direct
library boundary remain as documented in DEPTH_REGRESSION.md. A corrected live
model route is unavailable locally; no credential was sent to an assumed URL.
The console Docker pin remains unchanged. Component PR review and explicit
deployment approval are still required. This rehearsal is local, not deployed.
