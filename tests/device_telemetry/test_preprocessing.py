from pathlib import Path
import pytest
from apt_detection.device_telemetry.preprocessing import clean_phase

RAW = Path(__file__).resolve().parents[2] / "data" / "raw" / "cicapt_provenance"
P2 = RAW / "Phase2_Provenance.csv"

@pytest.mark.skipif(not P2.exists(), reason="CICAPT data not downloaded")
def test_phase2_cleaning_counts():
    table, events, report = clean_phase(P2)
    assert report["processes"] == 12443
    assert report["attack_processes"] == 7161
    assert report["attack_steps"] == 47
    assert report["events_without_process"] == 0
    assert table.index.is_unique