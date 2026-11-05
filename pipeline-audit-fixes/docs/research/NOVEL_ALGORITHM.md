# FAEGL: Failure-Aware Exploit Graph Localization

FaultSeeker++ now has a named algorithmic contribution: **Failure-Aware Exploit Graph Localization (FAEGL)**.

FAEGL targets a specific failure mode in blockchain exploit forensics: first-pass function selection can return an empty or weak `functions_to_inspect` set even when the transaction contains exploit evidence. This happens with proxy indirection, fallback functions, high-noise traces, obfuscated calldata, and traces where the vulnerable function is not the externally visible entry point.

## Problem definition

Given a transaction trace `T`, token-flow evidence `F`, optional graph metrics `G`, and an initial function candidate set `C0`, FAEGL computes:

```text
D = FAEGL(T, F, G, C0)
```

where `D` contains:

- a failure severity score,
- fallback-mode utilities,
- selected fallback modes,
- ranked localization candidates,
- per-candidate FAEGL scores.

The core trigger is:

```text
|C0| = 0
```

That trigger is simple and reproducible. It gives the paper a clean ablation boundary: compare the full system against `-FAEGL` on the same transactions and measure recovery rate, precision, recall, F1, runtime, and cost.

## Feature vector

FAEGL extracts a deterministic feature vector:

```text
x = [
  trace_entropy,
  call_depth,
  state_delta,
  token_flow_anomaly,
  delegatecall_density,
  graph_anomaly,
  graph_cycles
]
```

The implementation is dependency-light and reproducible:

- `trace_entropy` is normalized Shannon entropy over function/call-type tokens.
- `call_depth` is normalized maximum trace depth.
- `state_delta` is normalized storage-event density.
- `token_flow_anomaly` is normalized token-transfer fanout.
- `delegatecall_density` captures proxy or delegatecall-heavy execution.
- `graph_anomaly` and `graph_cycles` come from the transaction interaction graph.

## Failure severity

FAEGL estimates failure severity as:

```text
s = min(1, 0.58 z + 0.24 max(graph_anomaly, trace_entropy)
           + 0.18 max(state_delta, token_flow_anomaly))
```

where `z = 1` when the initial candidate set is empty, otherwise `0`.

This is not claimed as a learned model. It is a deterministic controller score that can be ablated and later replaced by a learned policy.

## Fallback utility selection

Each fallback mode receives a utility:

```text
u_m = s * base_m(x)
```

FAEGL selects mode `m` when:

```text
u_m >= 0.35
```

Current modes:

- entropy trace analysis,
- state-delta reasoning,
- graph expansion,
- aggressive call-depth inspection,
- proxy unwrapping.

## Candidate ranking

For each trace-derived candidate `c`, FAEGL computes:

```text
score(c) =
  0.24 graph_anomaly
+ 0.18 trace_entropy
+ 0.16 state_delta
+ 0.14 depth(c)
+ 0.12 token_flow_anomaly
+ 0.10 proxy(c)
+ 0.04 value(c)
+ 0.02 address_prior(c)
```

The output score is clipped to `[0, 1]` and emitted as `_faegl_score`.

## Why this is the paper contribution

FAEGL is stronger than a normal engineering fallback because it provides:

- a formal failure trigger,
- reproducible feature extraction,
- explicit fallback-mode utility scoring,
- ranked localization candidates,
- clean ablation boundaries.

In the paper, this should be positioned as the main algorithmic contribution:

> a failure-aware adaptive localization algorithm for dependable exploit forensics under trace sparsity, proxy indirection, and noisy execution paths.

## Evaluation plan

Report at least these tables:

| Configuration | Precision | Recall | F1 | Empty-set recovery | Runtime |
|---|---:|---:|---:|---:|---:|
| Full system + FAEGL | TBD | TBD | TBD | TBD | TBD |
| Without FAEGL | TBD | TBD | TBD | TBD | TBD |
| FAEGL without graph anomaly | TBD | TBD | TBD | TBD | TBD |
| FAEGL without state delta | TBD | TBD | TBD | TBD | TBD |
| FAEGL without entropy | TBD | TBD | TBD | TBD | TBD |

Also report adversarial degradation under:

- proxy obfuscation,
- misleading function names,
- recursive trace noise,
- fake event emissions,
- calldata prompt-injection strings.
