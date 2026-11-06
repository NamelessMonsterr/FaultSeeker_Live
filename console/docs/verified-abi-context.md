# Historical ABI context

Set `ETH_ABI_RPC_URL` (or the equivalent advertised chain prefix) to an operator-approved public historical-state RPC. `FAULTSEEKER_ABI_RPC_URL` is a shared operator fallback; the response chain ID must still match the requested chain. Unset means disabled. Visitor inputs cannot configure this route.

The runtime supplements observed selector/address targets with Sourcify ABI entries only when the service returns an exact runtime match for that chain/address and a checked public RPC returns identical bytecode at the transaction block. Canonical target identifiers remain selectors. ABI facts do not establish source-code validation, vulnerability or exploitability. The binding is block end-state, not transaction prestate; proxies are not automatically resolved.

Lookups use a run-local cache, at most eight contracts, a shared 30-second lookup deadline, five-second HTTP timeouts, a two-MiB source-response bound and no retries. Socket timeouts and deadline checks bound network work; OS DNS resolution can exceed a socket timeout. Source/RPC throttling stops new lookups. RPC DNS addresses are checked and pinned; redirects and private destinations are rejected. There is no cross-run/disk cache. Lookup failures leave selectors unresolved and are retained as finite statuses, without raw errors or RPC credential URLs.

`verified_abi_context` appears in function-related information and persisted final/partial reports. It is supplemental provenance; global `abi_verified` remains false because not every trace target has been bound. Source/ABI response hashes and runtime hash retain verification evidence. This does not fetch Solidity sources or prove complete chain coverage.

Offline regression: `python -B tests/run_offline.py --tb=line -rs` with the exact Docker checkout and explicitly identified candidate. Source/RPC HTTP is mocked. The saved Hedgey fixture records original public endpoints, request, retrieval times and ABI response digest; it is not an invented on-chain fixture.

Verified names also enter narrowing prompts before target selection. This summary is bounded to4000characters of verified facts and explicitly records omitted/unverified counts; complete proof stays in report context. Mercury requests retain full current prompts, with a262144-byte serialized-message input bound that fails explicitly instead of deleting content. Other providers retain their existing policies.

The approved Itera Qwen route also preserves complete prompts, capped at98304serializedUTF8bytes; thinking stays disabled per provider documentation. Pinned force_json and stored-memory caps are retained. These byte limits are application safety bounds, not provider token-metering claims.
