# CODEX local source snapshot

Contains console source, tests, audit reports and the candidate pipeline under pipeline-audit-fixes/. The Dockerfile still uses its external pinned pipeline; this snapshot does not silently change the deployment pipeline.

Use .env.example as a local configuration template. proxy.txt is sanitized; original credentials, DPAPI files, private keys, caches, run logs and installed dependencies are excluded.

Local source validation: 437 console tests passed; 64 revision-dependent integration setups were blocked by incomplete temporary Git metadata. Candidate pipeline: 582 passed. Frontend: 30 passed. Live end-to-end correctness remains unverified. See the dated reports for exact commands and limits.

This publication is prepared on top of remote CODEX, without modifying main/main1 or the currently running local workspace. Deployment effects require verification before push.
