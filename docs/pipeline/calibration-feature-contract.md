# Runtime calibration feature contract

The production report accepts only a trained model declaring `input_contract: faultseeker.runtime-components.v1` with the exact ordered `FEATURE_NAMES` list in `faultseeker/research/calibration.py`. The generic research calibrator can still load older models for reproduction; the runtime report refuses unknown or incompatible input semantics.

This marker establishes a declared input contract, not scientific validity. Do not add it to existing proxy-trained weights to bypass rejection. A replacement requires fitting on the actual runtime feature definitions with independently established labels and an untouched validation split. No such model was trained or validated in this remediation. The shipped model/data artifacts remain unchanged.

| Feature | Runtime definition |
|---|---|
| pattern_match | Current ConfidenceScorer pattern component for this function |
| code_evidence | Current ConfidenceScorer source/evidence component for this function; availability is not proof of vulnerability |
| txn_consistency | Current ConfidenceScorer transaction-consistency component |
| llm_confidence | Current ConfidenceScorer model-confidence component |
| trace_entropy | Normalized entropy of observed flattened call labels |
| call_depth | Maximum structural call-tree edges below a root; a root-only trace is0, absent trace is unavailable; never address-graph node count |
| state_delta | Count of observed canonical storage-write events when storage trace availability is established, otherwise unavailable; not monetary state change |
| token_flow_anomaly | Existing interaction-graph anomaly heuristic; not a measured token loss or native profit |

All eight inputs must be finite numeric measurements/components, with the matching producer contract on the signals. Missing values are not filled with zero. Explicit measured zeros remain valid. Stage1 lacks per-function scorer components and therefore does not publish a probability from invented zero components.

Reports retain heuristic scores when calibration is not applied and expose a finite reason: no_model, no_findings, model_untrained, feature_contract_unverified, features_unavailable or calibration_failed. The console renders the confidence basis. A later failed function does not leave earlier functions partially calibrated. Compatible-model tests use controlled predictions and do not establish model accuracy.
