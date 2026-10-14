from datetime import datetime, timezone
import pytest
from apt_detection.common.schemas import Prediction


def test_valid_prediction():
    prediction = Prediction(
        sample_id="synthetic_001",
        module="network_flow",
        timestamp=datetime.now(timezone.utc),
        attack_probability=0.8,
        predicted_label=1,
        model_version="baseline_v1",
    )
    assert prediction.schema_version == "1.0"


def test_probability_rejects_out_of_range():
    with pytest.raises(ValueError):
        Prediction(
            sample_id="synthetic_002", module="network_flow",
            timestamp=datetime.now(timezone.utc),
            attack_probability=1.5, predicted_label=1,
            model_version="baseline_v1",
        )