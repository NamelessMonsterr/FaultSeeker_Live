"""Malformed calibration models must not produce plausible probabilities."""
import pytest
from faultseeker.research.calibration import LogisticConfidenceCalibrator as Calibrator

@pytest.mark.parametrize("override", [
    {"weights": [1]}, {"means": [0]}, {"scales": [1]},
    {"weights": [float("nan"), 0]}, {"bias": float("inf")},
    {"scales": [0, 1]}, {"scales": [-1, 1]},
    {"trained": "false"}, {"feature_names": ["x", "x"]},
])
def test_invalid_model_rejected(override):
    data = {"feature_names": ["x", "y"], "weights": [1, 2], "means": [0, 0], "scales": [1, 1], "bias": 0, "trained": True}
    data.update(override)
    with pytest.raises(ValueError):
        Calibrator.from_dict(data)

def test_valid_model_round_trip_and_all_features_contribute():
    model = Calibrator.from_dict({"feature_names": ["x", "y"], "weights": [1, 2], "means": [0, 0], "scales": [1, 1], "bias": 0, "trained": True})
    assert model.predict_proba({"x": 0, "y": 1}) > model.predict_proba({"x": 0, "y": 0})
    assert Calibrator.from_dict(model.to_dict()).to_dict() == model.to_dict()

@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_nonfinite_prediction_features_rejected(value):
    with pytest.raises(ValueError):
        Calibrator(["x"]).predict_proba({"x": value})



def test_runtime_contract_round_trip_does_not_relabel_legacy_models():
    from faultseeker.research.calibration import RUNTIME_FEATURE_CONTRACT, require_runtime_calibrator, CalibrationInputError
    legacy = Calibrator().to_dict()
    legacy["trained"] = True
    legacy.pop("input_contract")
    loaded = Calibrator.from_dict(legacy)
    assert loaded.input_contract is None
    with pytest.raises(CalibrationInputError, match="feature_contract_unverified"):
        require_runtime_calibrator(loaded)
    # Explicit compatible metadata survives serialization, without a training run.
    declared = Calibrator(input_contract=RUNTIME_FEATURE_CONTRACT)
    declared.trained = True
    restored = Calibrator.from_dict(declared.to_dict())
    require_runtime_calibrator(restored)
    assert restored.input_contract == RUNTIME_FEATURE_CONTRACT


@pytest.mark.parametrize("missing", ["pattern_match", "call_depth", "state_delta"])
def test_runtime_feature_contract_requires_measurements(missing):
    from faultseeker.research.calibration import RUNTIME_FEATURE_CONTRACT, runtime_feature_row, CalibrationInputError, FEATURE_NAMES
    values = {name: 0 for name in FEATURE_NAMES}
    values["feature_contract"] = RUNTIME_FEATURE_CONTRACT
    # Explicit measured zeros remain valid, missing observations do not.
    assert runtime_feature_row(values, values) == {name: 0 for name in FEATURE_NAMES}
    values.pop(missing)
    with pytest.raises(CalibrationInputError, match="features_unavailable"):
        runtime_feature_row(values, values)
