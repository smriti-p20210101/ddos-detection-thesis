from __future__ import annotations

import os

import xgboost as xgb

class XGBoostEnsemble:
    """
    Real XGBoost model, retrained after a real hyperparameter/feature search
    (see controller/ml/train_model.py's module docstring):
    - 100 estimators
    - max tree depth 9 (tuned via leakage-safe CV search; the thesis's
      original depth 6 measurably underperformed on the real combined
      UDP+SYN dataset)
    - learning rate 0.2 (tuned)
    - binary:logistic

    Loads the artifact trained by controller/ml/train_model.py on real
    CIC-DDoS2019 packet data (see that module's docstring for dataset scope
    and label ground truth) -- does not retrain on every controller start.
    """

    FEATURE_COLUMNS = ["pkt_rate", "byte_rate", "duration", "proto_var", "port_div",
                       "size_var", "tcp_flags", "inter_arrival", "syn_noack_ratio", "ack_ratio"]

    def __init__(self):
        self.params = {}
        self.reload_params()
        self.booster = self._load_model()

    def _load_model(self) -> xgb.XGBClassifier:
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        model_path = os.path.join(base_dir, "controller", "ml", "model.json")
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"No trained model at {model_path}. Run "
                "`python -m controller.ml.train_model` first to extract features "
                "and train a real model -- there is no fallback simulation."
            )
        model = xgb.XGBClassifier()
        model.load_model(model_path)
        return model
        
    def reload_params(self) -> None:
        """Dynamically reloads XGBoost model parameters from config/settings.yaml."""
        default_params = {
            'n_estimators': 100,
            'max_depth': 9,
            'learning_rate': 0.2,
            'objective': 'binary:logistic'
        }
        
        # Determine path to settings.yaml relative to this file
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        config_path = os.path.join(base_dir, "config", "settings.yaml")
        
        self.params = default_params.copy()
        if os.path.exists(config_path):
            try:
                import yaml
                with open(config_path, 'r') as f:
                    data = yaml.safe_load(f)
                    ml_data = data.get('settings', {}).get('ml', {})
                    for k, v in ml_data.items():
                        if k in self.params:
                            self.params[k] = v
            except Exception:
                # Fallback line-by-line parser if PyYAML is not installed
                try:
                    with open(config_path, 'r') as f:
                        in_ml = False
                        for line in f:
                            stripped = line.strip()
                            if stripped.startswith("ml:"):
                                in_ml = True
                                continue
                            if in_ml:
                                if ":" in stripped:
                                    k, v = stripped.split(":", 1)
                                    k = k.strip()
                                    v = v.strip().strip('"').strip("'")
                                    if k in self.params:
                                        if k in ['n_estimators', 'max_depth']:
                                            self.params[k] = int(v)
                                        elif k == 'learning_rate':
                                            self.params[k] = float(v)
                                        else:
                                            self.params[k] = v
                                elif line.startswith("  ") and not line.startswith("    ") and stripped:
                                    in_ml = False
                except Exception:
                    pass
                    
        print(f"[INFO] Initializing XGBoost Ensemble...")
        print(f"[PARAMS] n_estimators={self.params['n_estimators']}, max_depth={self.params['max_depth']}, "
              f"eta={self.params['learning_rate']}, objective='{self.params['objective']}'")
        
    def predict_proba(self, features: list[float]) -> list[list[float]]:
        """
        Predicts malicious probability based on the 10D vector, via the real
        trained XGBoost booster loaded in __init__.
        Features mapping: [pkt_rate, byte_rate, duration, proto_var, port_div, size_var, tcp_flags,
        inter_arrival, syn_noack_ratio, ack_ratio]
        """
        return self.booster.predict_proba([features]).tolist()

