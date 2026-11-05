# Error Taxonomy

Use this taxonomy for every false positive and false negative in final evaluation.

## False Positives

| Code | Category | Description | Example benign flow |
|---|---|---|---|
| FP-FLASH | Benign flash liquidity | Flash loan or flash swap used for normal arbitrage/liquidation | Aave liquidation |
| FP-MEV | MEV/arbitrage pattern | High-frequency swaps look exploit-like but are price correcting | sandwich/arbitrage bundle |
| FP-PROXY | Proxy ambiguity | Delegatecall/proxy pattern raises risk without exploit evidence | upgradeable DeFi protocol |
| FP-ADMIN | Legitimate privileged action | Owner/admin action resembles access-control exploit | governance execution |
| FP-NOISE | Trace noise | Router fanout or recursive callbacks inflate anomaly score | aggregator swap |

## False Negatives

| Code | Category | Description | Required follow-up |
|---|---|---|---|
| FN-MULTITX | Multi-transaction campaign | Single transaction does not contain full attack context | temporal correlation |
| FN-ORACLE | External oracle dependence | Manipulation occurs before inspected transaction | block-window oracle analysis |
| FN-STATE | Hidden state dependency | Critical state delta is not visible in shallow trace | storage-delta expansion |
| FN-PROXY | Proxy unwrap failure | Vulnerable implementation not resolved | proxy-unwrapping fallback |
| FN-LABEL | Ground truth ambiguity | Public source label is incomplete or too broad | manual adjudication |

Each error row should include:

- transaction hash
- chain
- predicted class
- ground truth class
- confidence
- active signals
- taxonomy code
- analyst note
