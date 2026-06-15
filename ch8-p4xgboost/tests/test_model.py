import pytest
import sys
import os
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from controller.ml.xgboost_model import XGBoostEnsemble
from controller.app import SDNController

def test_xgboost_malicious():
    model = XGBoostEnsemble()
    malicious_features = [1200, 1500000, 0.5, 0.1, 1, 0.05, 0.8, 0.0001]
    prediction = model.predict_proba(malicious_features)
    assert prediction[0][1] > 0.5, "Should classify high pkt_rate as malicious"

def test_xgboost_benign():
    model = XGBoostEnsemble()
    benign_features = [80, 15000, 2.5, 0.4, 2, 0.15, 0.2, 0.05]
    prediction = model.predict_proba(benign_features)
    assert prediction[0][1] < 0.5, "Should classify low pkt_rate as benign"

def test_model_reload_params():
    model = XGBoostEnsemble()
    assert "n_estimators" in model.params
    assert model.params["n_estimators"] == 100
    assert model.params["max_depth"] == 6

def test_controller_custom_threshold():
    controller = SDNController(threshold=0.85, ip_blacklist={"10.10.10.10"})
    assert controller.threshold == 0.85
    assert "10.10.10.10" in controller.ip_blacklist

