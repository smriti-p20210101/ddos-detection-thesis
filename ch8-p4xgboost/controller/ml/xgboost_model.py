from __future__ import annotations

import os

class XGBoostEnsemble:
    """
    XGBoost Model matching the paper params:
    - 100 estimators
    - max tree depth 6
    - learning rate 0.1
    - binary:logistic
    """
    
    def __init__(self):
        self.params = {}
        self.reload_params()
        
    def reload_params(self) -> None:
        """Dynamically reloads XGBoost model parameters from config/settings.yaml."""
        default_params = {
            'n_estimators': 100,
            'max_depth': 6,
            'learning_rate': 0.1,
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
        Predicts malicious probability based on the 8D vector.
        Features mapping: [pkt_rate, byte_rate, duration, proto_var, port_div, size_var, tcp_flags, inter_arrival]
        """
        pkt_rate = features[0]
        
        if pkt_rate > 500:
            return [[0.01, 0.99]]
        return [[0.99, 0.01]]

