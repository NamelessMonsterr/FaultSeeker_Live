# Model endpoint and Hedgey target integrity investigation

## Review scope

Base: `main1` at `60a7c989843b775520b939a97dedbc2ab92c5c05`.
Fix branch: `fix/model-endpoint-target-integrity`. No merge, push or deployment.
External pipeline: Docker-pinned `NamelessMonsterr/FaultSeeker-` revision
`bc98bfd8cc6903363955da72792db112757172c0`, inspected and tested in an isolated checkout.
The external checkout, model selection (`gpt-6.1-sol-low`) and provider configuration are unchanged.
No live model calls, paid services or credentials were used for verification.

## 1. Endpoint failures

The pinned pipeline's `faultseeker/utils/agent.py::_llm_call_with_retry` starts a
fresh retry counter for each query: six retries plus its initial request.
Four exhausted query sequences can therefore produce 28 requests. SDK retries
were already disabled in the inspected callers; they do not explain a further
multiplier in that revision. The console Docker image sets a 300-second model
timeout, and the query-local backoff ladder adds further waiting.

`UniversalAgent._send_message` can convert an exhausted 5xx into generic error
text; `FunctionAnalyzer.run` catches individual thread failures. Consequently,
pipeline continuation does not establish that every model-dependent section ran.
The UI had stage/log activity but no distinct model-endpoint waiting state.

The supplied observations for `c8c77a00a18d` and `d93e37603527` are consistent
with this path. Their actual run logs were unavailable (public history lookup
returned 404); the source and bundled historical 502 logs were inspected instead.
Neither warming success nor these HTTP responses establish the infrastructure
root cause: proxy cold start, upstream availability and other routing failures
remain possible. No claim is made that Render itself caused the failures.

Implemented policy (`app/model_endpoint.py`, `app/pipeline_guards.py`):

| Setting | Default | Meaning |
| --- | --- | --- |
| `FAULTSEEKER_MODEL_PREFLIGHT_SECS` | 20 | Overall readiness allowance before transaction analysis |
| `FAULTSEEKER_MODEL_RETRY_LIMIT` | 3 | Retries shared across preflight and all agent queries; success never resets this allowance |
| `FAULTSEEKER_MODEL_TIME_BUDGET_SECS` | 600 | Cumulative model transport and retry-wait time across the run |
| `FAULTSEEKER_MODEL_CALL_TIMEOUT_SECS` | 60 | Per-request SDK/HTTP timeout, clamped to remaining allowance |

Preflight sends a minimal authenticated completion to the selected model at its
configured endpoint. It runs only when a user requests live model analysis;
there is no background keep-warm process. An explicit split-stage model, if
requested, shares the same preflight allowance. Automatic provider/model fallback
is disabled. SDK retries are forcibly zero, all model threads share a serialized
session, and the first exhausted/permanent failure opens a sticky run-wide circuit.
No subsequent query starts another retry ladder. Timeout accounting includes
preflight, successful requests and backoff; CPU/RPC work is outside that budget.
HTTP timeouts are transport operation limits, not an OS-level hard kill of a
malicious server that continuously trickles bytes; the existing worker watchdog
remains a separate last-resort bound.

Authentication/access, unavailable model, invalid request, rate limit, upstream
HTTP, connection, timeout and invalid completion responses have fixed safe error
messages. Provider bodies, HTML and credentials do not become report content.
Worker-boundary checks surface failures even when upstream catches them. A failed
preflight never calls transaction analysis. Mid-run failure atomically saves a
partial report with explicit failed/skipped sections and an INCONCLUSIVE verdict.
Deterministic observations are retained separately, not presented as completed
model verification. Status polling retains the latest endpoint state for reconnects.

## 2. Verified transaction and target

Fixture: `tests/fixtures/hedgey_verified_trace.json`, collected at
`2026-10-23T18:32:45.158285+00:00` from public unauthenticated `https://eth.drpc.org`
using `eth_getTransactionByHash`, `eth_getTransactionReceipt` and `trace_transaction`.
The transaction root was independently cross-checked with `ethereum.publicnode.com`.
No private API key was used. Raw responses and collection provenance are retained.

Transaction: `0x2606d459a50ca4920722a111745c2eeced1d8a01ff25ee762e22d5d4b1595739`.
Ethereum block 19,687,890; block hash
`0xadc062e388f2cb069f54f398a7b26c41c8484004deba471c78864a5c732363d3`.

| Frame | Observed execution |
| --- | --- |
| root | Attacker `0xded2b1a426e1b7d415a40bcad44e98f47181dda2` calls `0xc793113f1548b97e37c409f39244ee44241bf2b3` with selector `0xe32a9a37` |
| 0 | Attack contract STATICCALLs USDC `0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48`, selector `0x70a08231`, for ClaimCampaigns' balance |
| 0,0 | USDC DELEGATECALLs implementation `0x43506849d7c04f9138d1a2050bbf3a0c054402dd` with that calldata |
| 1 | Attack contract calls USDC `0x23b872dd`, transferring from ClaimCampaigns `0xbc452fdc8f851d7c5b72e1fe74dfb63bb793d511` to the attacker |
| 1,0 | USDC DELEGATECALLs its implementation with that transfer calldata |

The successful receipt's Transfer log matches the trace's addresses and amount.
This is an allowance-draining transaction, not the earlier allowance-creation
transaction. ClaimCampaigns `createLockedCampaign` / `cancelCampaign` are not
executed here. This transaction alone cannot localize the entire exploit sequence.
Incident context: [Hedgey post-mortem](https://medium.com/hedgey/hedgey-exploit-post-mortem-784e9860fd8d).

`keccak("updateGhoBorrowRate(uint16,uint32,uint32,uint32)")[:4]` is indeed
`0xe32a9a37`. However, that signature needs four ABI argument words. This root
calldata has two words, and its address-valued first word cannot fit uint16.
The selector lookup label is therefore not a valid ABI decoding of this call.
The true source-level function name has NOT been established.

No wrong preset hash, selected chain or cache key was established. The proven
mismatch is identity provenance: `TransactionSequencer.run` obtains canonical
RPC data but prefers cast-parsed text for its legacy trace. `TraceParser`,
`TraceAnalyzer` and `FunctionRanker` then preserve the decoded name. Successful
model calls cannot validate that name; the historical bundled result also relies
on rule-classifier assertions without establishing the target's verified source.

The runtime now checks trace metadata against the requested hash/chain and
cross-checks RPC network identity and transaction root calldata/from/to. It builds
ranking input, address memo and visualization from canonical raw selectors;
ranked selector/address pairs must actually occur in that trace. It records
trace provenance and explicitly marks ABI identity unverified. Output labels not
linked to observed targets make localization partial/INCONCLUSIVE. Historical
Hedgey replay is also labelled unverified. Existing evidence is not rewritten.

Root cross-checks do not independently replay every cached internal frame. Full
ABI/source verification, transaction-at-block code provenance and an approved live
model end-to-end run remain outside the completed verification. A pinned-pipeline
offline integration test exercises the real sequencer, trace analyzer, agents and
ranker; it does not claim an independently measured localization accuracy score.

## Verification and local deployment preview

PowerShell commands from the repository root (dependencies were already installed):

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
$env:PYTHONDONTWRITEBYTECODE='1'
$env:FAULTSEEKER_TEST_PIPELINE_REPO='C:\Users\91701\AppData\Local\Temp\faultseeker-pipeline-investigation'
python -m pytest tests -q
node --test tests/frontend.test.cjs
node --check app/web/assets/console.js
node --check assets/console.js
git diff --check
```

Results: 84 Python tests passed (including 3 exact-pinned-pipeline integrations),
10 frontend tests passed, both JavaScript syntax checks and whitespace check passed.
Without the optional pipeline checkout, those 3 integration tests skip explicitly.
Mocked HTTP covers HTML502, JSON500, 401/403, 404/400, timeout, transient recovery,
shared retry/time exhaustion, SDK retry disabling, preflight failure and mid-run
loss; worker/API/report tests check partial semantics and safe body handling.

Local preview server (no deployment):

```powershell
$env:PORT='8424'
$env:GITHUB_HISTORY_TOKEN=''
$env:FAULTSEEKER_RUNS_DIR=Join-Path $env:TEMP 'faultseeker-endpoint-preview-runs'
python app/server.py
# In another terminal, with the server running:
python tests/browser_checks.py --url http://127.0.0.1:8424 --artifacts C:/Users/91701/.codex/visualizations/2026/10/22/01a164ff-ab8b-72f1-b3a6-ba2a12b6333b/endpoint-fix-preview
```

Chrome: 11 checks passed, including SSE waiting/retry status, partial report with
failed/skipped sections, cancellation, successful report, responsive layouts and
the explicitly saved capture. Screenshots are controlled browser/API fixtures,
not evidence of a successful live Hedgey model run. The preview server is stopped
after verification. No production preview URL was created. Docker engine access
was unavailable, so no complete container build is claimed. Kluster tools were
not exposed in this session; no Kluster verification is claimed.
