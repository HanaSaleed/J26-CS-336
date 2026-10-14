"""Shared prediction interface for all three research modules.

Scores must be calibrated to an agreed positive-class definition before
being treated as comparable probabilities in the fusion module.
"""
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

ModuleName = Literal["network_flow", "device_telemetry", "physical_sensor"]


@dataclass(frozen=True)
class Prediction:
    sample_id: str
    module: ModuleName
    timestamp: datetime
    attack_probability: float
    predicted_label: int
    model_version: str
    schema_version: str = "1.0"

    def __post_init__(self) -> None:
        if not self.sample_id or not self.model_version:
            raise ValueError("sample_id and model_version must not be empty")
        if self.module not in ("network_flow", "device_telemetry", "physical_sensor"):
            raise ValueError("Unknown module")
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        if not 0.0 <= self.attack_probability <= 1.0:
            raise ValueError("attack_probability must be in [0, 1]")
        if self.predicted_label not in (0, 1):
            raise ValueError("predicted_label must be 0 or 1")