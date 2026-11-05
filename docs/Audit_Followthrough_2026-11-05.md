# Local audit follow-through — 2026-11-05

Scope: targeted corrections following the two supplied root-cause audits. Existing uncommitted work was preserved. No live model/RPC calls, package installation, push, merge, deployment, or changes to the immutable pinned checkout were performed. This is not a claim that the complete project or any chain is production-verified.

## Changes made in this pass

| Finding | Status and evidence | Implementation scope |
| --- | --- | --- |
| Retrieval contract errors converted to depth zero | Fixed: unobserved targets and corrupt paths raise explicit retrieval errors; no fabricated depth. Existing checkpoint/failure handling retains partial evidence. | Both copies of retrieval_contract.py; real saved-trace tests remain enabled. |
| History loses user message that elicited retained assistant reply | Fixed: retain complete preceding pairs plus pending user. Reproduced before fixing. | Candidate GPT/Universal/Ollama history methods; console runtime hook also covers the exact immutable pin, with method-restoration regression. |
| Length-truncated completion immediately kills session despite spare shared retries | Fixed: length alone is retryable within existing shared retry/time accounting. Never accept truncated JSON; content-filter/tool/function completion reasons stay terminal. | Console shared transport; mocked SDK HTTP recovery and repeated-length exhaustion tests. No separate allowance or token-cap escalation. |
| Low requested temperature mapped to maximum supported temperature | Fixed: map below-minimum values to 0.5, preserving higher valid values. | Console route adapter and HTTP transport expectations. This does not prove temperature caused attempt 877. |
| Ranking rejects case-only known identities | Fixed: normalize only uniquely matching existing finding keys. | Candidate finalization. Unknown or ambiguous targets remain rejected. |
| Malformed ranking aborts without schema repair | Fixed: one additional schema request preserving the original task and allowed keys; then explicit error. | Candidate finalization. No fabricated confidence-sorted fallback; transport errors still propagate. |
| Empty/invalid shortlist silently erases candidates | Fixed: nonempty known-key list/dict required before selection is replaced. | Candidate ordinary and created-contract shortlists. Failure is explicit rather than a false successful empty analysis. Immutable upstream shortlisting is not rewritten by this pass. |
| Stage 3 malformed input causes incidental type/attribute exceptions | Fixed at public scoring boundary: explicit validation errors for malformed identities, evidence/confidence collections, participant lists and repeated-pattern containers. | Candidate scorer. Missing evidence is not coerced into neutral evidence; these errors still stop scoring explicitly. This is not proof of the audit's claimed 19 independent live crash paths. |
| Local Ollama input slicing removes schemas/evidence | Fixed: reject oversized input before changing memory or invoking the model. | Candidate local agent. No silent compaction/truncation. Local provider timeout/error handling is otherwise unchanged. |
| Reverted flat calls register ordering/state-write signals | Fixed: retain observed_flat; exclude explicitly failed frames and descendants of failed parents from flat heuristics. | Candidate SignalExtractor. Tests cover error, success=false, status=0x0 and inherited rollback. Missing success information does not establish successful execution; tree/canonical analyses retain their separate policies. |

## Other supplied claims and remaining limitations

| Audit claim / proposed change | Disposition |
| --- | --- |
| 876 consecutive successful requests | Incorrect saved accounting: 874 successful and 3 failed attempts; two recovered before terminal length response. |
| Exact exploit mechanism validated | Not established: preliminary selector/address observation, not completed independent mechanism verification, ranking or scoring. No expected result changed. |
| Temperature caused internal reasoning loop and approximately 24,000 reasoning tokens | Unproven. Raw failing completion, full wire request and per-request usage were not saved. Rate multiplied by elapsed time is not token measurement. |
| Missing calibration contract crashes whole pipeline | Not reproduced at pipeline boundary: existing code catches calibration errors and reports not_applied. Existing calibration reporting regressions remain enabled. |
| Inject contract marker and replace unavailable features with zero | Rejected: would assert unsupported training compatibility and manufacture measurements. Correctly trained, provenance-backed calibration remains unavailable. |
| Offline network hook supplies mock text | Incorrect: it denies network. Test-specific mocks are explicit; mocked integration is not live inference or deployed Docker verification. |
| Specific IndexError origin in historical run | Unresolved: missing historical traceback/request prevents uniquely identifying the indexing site. Defensive changes alone cannot establish that history. |
| Python-literal parser necessarily fixed the historical malformed response | Unverified attribution: parser compatibility does not prove what the unsaved provider output contained. |
| 133 versus 8 address counts proves dropped requests | Not established: inspected_address is a filtered role bucket, not a request-attempt counter. Model role classification remains unverified evidence. |
| UZD excluded from victim list is necessarily a bug | Not established: that list currently represents addresses with balance entries, not every economically affected asset/protocol. Asset vulnerability must not depend on victim-list membership. Broader victim semantics require a separate contract. |
| Frequency ranking delays rare targets | Confirmed policy risk, not changed to a Zunami-specific top-ten rule. Selector/name representation and cross-batch duplicate work still need independent ranking/workload validation. No frozen benchmark tuned. |
| Rename weak undecoded-call signal into closed-source exploit rule | Rejected. Existing extraction deliberately records access_control_review_required and classifier returns UNCERTAIN for it. An undecoded call plus transfer is not an authorization violation. The legacy stronger field is not populated by that observation. |
| Cyclic delegatecalls imply cyclic Python objects | Not established for serialized EVM traces. Recursive walker remains a depth/shape concern; malformed in-memory cyclic objects have not been shown reachable through the validated live path. |
| Unbounded memory / mixed-task history necessarily caused failure | History pairing fixed; candidate resets between analysis units and bounded retained turns remain. Repeated context and heterogeneous tasks still warrant workload/schema improvements, but causal attribution to attempt 877 is not proven. |
| Proxy implementation auto-resolution | Deferred: current explorer source is not proof of transaction-block implementation. Correct support needs block-bound storage/code provenance, bounded recursion and destination safety. No blind latest-state source substitution added. |
| Remaining expensive repeated work and late finalization | Checkpointing and explicit partial states preserved. No live proof of complete scoring, no execution resume, and no claim the current workload is efficient. |

## Verification

All Python tests below run with network blocked and provider credentials removed by their runners. Existing dependencies only. Mocked HTTP does not establish provider availability, model accuracy, Docker execution or production behavior.

Candidate, from pipeline-audit-fixes:

```powershell
python -B tests/run_offline_depth.py tests
```

Result: 577 passed, 0 failed, 0 skipped.

Console, from FaultSeeker_Live, with local integration checkouts explicitly enabled:

```powershell
$env:FAULTSEEKER_TEST_PIPELINE_REPO='C:\Users\91701\Downloads\faultseeker-demo-console-main\pipeline-pin-offline-verified'
$env:FAULTSEEKER_TEST_CANDIDATE_REPO='C:\Users\91701\Downloads\faultseeker-demo-console-main\pipeline-audit-fixes'
$env:FAULTSEEKER_TEST_CANDIDATE_SHA='bac131efb08752772b129c571965042e4e5b55bd'
python -B tests/run_offline.py --tb=short -rs
```

Result: 497 passed, 0 failed, 0 skipped (35.03 seconds), including the enabled exact-pin and candidate integrations. These integrations use mocked external I/O, not live RPC/models.

Frontend:

```powershell
node tests/run_frontend_offline.cjs
python -B tools/sync_static.py --check
```

Frontend result: 29 passed, 0 failed, 0 skipped. Static-copy check passed. Both repositories pass git diff --check. The immutable pipeline remains clean at fb57c3fad63784b7a63dc7fdf1845364c76ce0b7. Candidate tests include pre-existing uncommitted changes; this is not a clean committed release artifact.

Kluster tools were not available in this session; no Kluster verification is claimed.

Branches retained: console fix/all-chain-validation; candidate fix/combined-audit-remediation. Nothing was committed or published.
