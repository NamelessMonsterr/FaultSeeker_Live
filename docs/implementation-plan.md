# Production console implementation

Approved scope: implement the two image-approved black/amber setup and live-progress screens, retain functional forensic results, and finish the eight audit fixes. This is a live production console; saved captures must be explicitly selected and labeled, never a fallback for failed live work.

## Files and responsibilities
- `app/web/index.html`, `app/web/assets/console.css`, `app/web/assets/console.js`: accessible, responsive setup, real SSE progress, resilient results, cancellation, recent runs, explicit saved capture. Mirror these assets and HTML to root for static hosting. No package dependencies or edits to compiled bundles.
- `app/server.py`: validate requests, isolate diagnostic keys, recursively redact outputs, release locks on all startup failures, safe history, bounded event replay with IDs and heartbeat, honest result status and metadata.
- `Dockerfile`: fetch/check out the exact declared pipeline revision.
- `tests/`: backend regression coverage for all eight findings and lifecycle boundaries. Frontend/browser checks cover setup, validation, progress, completion without blank screen, error, cancel, refresh/reconnect, history, static capture, and narrow viewports.

## Execution
1. Add failing regression tests for remaining hardening gaps; run them before fixes.
2. Implement the approved screens while retaining live API contracts and safe results rendering. Use text DOM APIs for untrusted values; never store keys in browser persistence.
3. Finish backend fixes; validate all eight audit items rather than assuming upstream fixes are complete.
4. Run backend tests, JS syntax/unit checks, and real-browser checks. Test external-provider boundaries with controlled fixtures and explicitly distinguish these from a paid live RPC/LLM run.
5. Review changes and document reproducible verification and any deployment limitations. Do not publish or push without explicit authorization.

## Review focus
Failed or malformed result must stay readable; cancellation and stream loss must not imply success; restart/reconnect must not duplicate events or hang; keys must never enter history/results/logs; long function names and logs must not widen the viewport. All incomplete analysis stays inconclusive. Runtime counts, model and elapsed times come from actual data, with no invented metrics.
