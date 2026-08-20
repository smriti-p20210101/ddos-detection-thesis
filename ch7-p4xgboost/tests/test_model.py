import pytest
import sys
import os
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from controller.ml.xgboost_model import XGBoostEnsemble
from controller.app import SDNController

FEATURE_COLUMNS = ["pkt_rate", "byte_rate", "duration", "proto_var", "port_div",
                    "size_var", "tcp_flags", "inter_arrival", "syn_noack_ratio", "ack_ratio"]


def _real_feature_row(label: int) -> list[float]:
    """Pulls a real row from the real extracted dataset, rather than a
    hand-picked synthetic vector. The old version of this test used
    pkt_rate=1200 as a "malicious" stand-in, tuned to trigger the previous
    fake model's `if pkt_rate > 500` rule -- that assumption doesn't hold
    for the real trained model (this real attacker sends a sustained
    moderate rate, not an extreme burst; see controller/ml/train_model.py's
    docstring), so it's replaced with real, verified data instead."""
    import pandas as pd
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    csv_path = os.path.join(base_dir, "evaluation_output", "extracted_features.csv")
    df = pd.read_csv(csv_path)
    row = df[df["label"] == label].iloc[0]
    return row[FEATURE_COLUMNS].tolist()


def test_xgboost_malicious():
    model = XGBoostEnsemble()
    malicious_features = _real_feature_row(label=1)
    prediction = model.predict_proba(malicious_features)
    assert prediction[0][1] > 0.5, "Should classify a real attack-labeled row as malicious"

def test_xgboost_benign():
    model = XGBoostEnsemble()
    benign_features = _real_feature_row(label=0)
    prediction = model.predict_proba(benign_features)
    assert prediction[0][1] < 0.5, "Should classify a real benign-labeled row as benign"

def test_model_reload_params():
    model = XGBoostEnsemble()
    assert "n_estimators" in model.params
    assert model.params["n_estimators"] == 100
    assert model.params["max_depth"] == 9

def test_controller_custom_threshold():
    controller = SDNController(threshold=0.85, ip_blacklist={"10.10.10.10"})
    assert controller.threshold == 0.85
    assert "10.10.10.10" in controller.ip_blacklist

