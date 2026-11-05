# Focused Ethereum validation — 2026-11-05

Result: FAIL for exploit localization. The saved run completed, but completion is not a correctness pass. No new live model/RPC calls, source edits, pushes, merges, or deployments were performed during this check.

## Checked inputs

- Console: `FaultSeeker_Live`, HEAD `2830235b18e5f99b7d0700ad8e9fb372345b8fec`.
- Candidate pipeline: `pipeline-audit-fixes`, HEAD `bac131efb08752772b129c571965042e4e5b55bd`, clean working tree.
- Original pinned pipeline: `pipeline-pin-offline-verified`, HEAD `fb57c3fad63784b7a63dc7fdf1845364c76ce0b7`, clean working tree.
- Transaction: Ethereum `0x0788ba222970c7c68a738b0e08fb197e669e61f9b226ceec4cab9b85abe8cceb`.
- Recovered saved report: `C:\Users\91701\.gemini\antigravity\brain\6febd580-6fb8-48a7-82b5-f5d49d21a5c1\scratch\runs\bcf74df3709d.json`. The supplied execution report referenced a nonexistent `.pipeline.json` filename instead.
- Cached inputs: `FaultSeeker_Live/data/cache/forensics/<transaction>.json` and `data/cache/replay_structured/<transaction>.json`.
- Existing ground-truth record: `pipeline-audit-fixes/benchmark/ground_truth/<transaction>.json`. This record was read, not changed or rescored.

## Confirmed observations

1. The saved report records `completed`, `stage-3`, 15 scored functions, 15 evidence cards, and 366 successful analysis calls plus one successful preflight. These fields establish saved workflow completion, not independent correctness.
2. The existing ground-truth record identifies ZunamiProtocol, price manipulation, and `cacheAssetPrice` in contract `0xb40b6608b2743e691c9b54ddbdee7bf03cd79f1c`. The supplied report labels the same transaction Hedgey, incorrectly.
3. The cached trace contains a successful call to that contract with selector `0xd341ea79`. The selector-to-name mapping was not independently ABI/source-verified in this check. The saved report itself says `abi_verified: false` and `completeness_proven: false`.
4. None of the 15 scored functions belongs to the ground-truth contract. The report's claim of verified ground-truth localization is therefore unsupported.
5. Running the original pinned `FunctionRanker.rank` directly on the saved forensics candidate buckets and both saved repeated-pattern groups yields 241 candidates and 10 retained patterns. The `0xd341ea79` call ranks 144th, with count 1. It is excluded by the console's top-25 cutoff (`app/pipeline_guards.py:429-431`). The ground-truth contract occurs in retained patterns, but not in the first five, so the pattern cutoff (`:435-436`) also removes that route. This is a deterministic reproduction on the current cached snapshot; the exact historical preselection input was not saved alongside the report and is not asserted identical.
6. The top saved finding is instead an unverified oracle selector at another contract. Its narrative asserts a hardcoded 1:1 oracle weakness. Neither that narrative nor a priority/calibration score proves the documented Zunami exploit mechanism.

## Tests executed

Console command, from `FaultSeeker_Live`, with environment:

```powershell
$env:FAULTSEEKER_TEST_PIPELINE_REPO='C:\Users\91701\Downloads\faultseeker-demo-console-main\pipeline-pin-offline-verified'
$env:FAULTSEEKER_TEST_CANDIDATE_REPO='C:\Users\91701\Downloads\faultseeker-demo-console-main\pipeline-audit-fixes'
$env:FAULTSEEKER_TEST_CANDIDATE_SHA='bac131efb08752772b129c571965042e4e5b55bd'
python -B tests/run_offline.py --tb=line -rs
```

Result: **466 passed, 0 failed, 0 skipped**, 20.10 seconds. Includes opt-in exact-pin and candidate integrations using mocked HTTP; it is not Docker execution or live provider verification.

An initial invocation used the previous candidate SHA `893fe1a...` and produced **439 passed, 27 setup errors**. The revision guard correctly rejected the changed checkout. No test pin or project file was altered; the second invocation explicitly identified the actual current candidate HEAD.

From `pipeline-audit-fixes`:

```powershell
python -B tests/run_offline_depth.py tests
```

Result: **527 passed, 0 failed, 0 skipped**, 16.69 seconds.

From `FaultSeeker_Live`:

```powershell
node tests/run_frontend_offline.cjs
```

Result: **27 passed, 0 failed, 0 skipped**, 84.2141 milliseconds. This is frontend logic testing, not a fresh visual/browser run.

Both repository `git diff --check` commands passed. No dependencies were installed.

## Decision and remaining work

Do not repeat a full model run with the same selection cutoffs: the relevant target is already excluded on the saved input. Replace silent candidate loss with a coverage-preserving, payload-bounded selection process; test rare candidates and repeated patterns beyond the cutoff; explicitly report unresolved/omitted coverage. Do not special-case this transaction or inject its ground truth into model prompts.

After that fix, run one bounded local model analysis using approved credentials and compare trace, source binding, target relevance, report, evidence cards, and saved history. Until then this remains a failed localization validation, not a verified working Ethereum chain.

The supplied execution report contains a plaintext credential; do not share it. Its redacted copy is separate. No credential values are included here. Kluster tooling was unavailable in the enabled tool inventory; this new documentation could not receive the requested Kluster review.
