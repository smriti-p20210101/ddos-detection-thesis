#!/usr/bin/env python3
"""Real ablation 1 (feature dimensionality), re-scoped for the current
10-feature production model. The original ablation compared full(8)/
basic(4)/minimal(2) against the SUPERSEDED 8-feature model -- with
syn_noack_ratio/ack_ratio now in production, "full" needs to mean the real
current full set (10), and the real marginal contribution of the two new
features (which drove the 83.46%->86.22% accuracy improvement) needs its
own breakdown rather than being invisible inside one "full" number.

Re-scoped groups:
  A. Full (10, production)              -- current real production set
  B. Original 8 (no new features)       -- isolates the TOTAL real
                                            contribution of both new
                                            features together
  C. 8 + syn_noack_ratio only (9)       -- isolates syn_noack_ratio alone
  D. 8 + ack_ratio only (9)             -- isolates ack_ratio alone
  E. Basic (4): pkt_rate, byte_rate, port_div, tcp_flags  -- kept from the
                                            original ablation for continuity
  F. Minimal (2): pkt_rate, byte_rate   -- kept from the original ablation

All trained at the PRODUCTION hyperparameters (max_depth=9, lr=0.2, from
config/settings.yaml) -- only the feature set varies, isolating its real
effect rather than conflating it with the depth change.
"""
import json
import os
import sys
import time

import xgboost as xgb
from sklearn.metrics import confusion_matrix, f1_score

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from controller.ml.train_model import load_ml_hyperparams, per_type_temporal_split  # noqa: E402
import pandas as pd  # noqa: E402

BASE_8 = ["pkt_rate", "byte_rate", "duration", "proto_var", "port_div", "size_var", "tcp_flags", "inter_arrival"]

FEATURE_SETS = {
    "A: Full (10, production)": BASE_8 + ["syn_noack_ratio", "ack_ratio"],
    "B: Original 8 (no new features)": BASE_8,
    "C: 8 + syn_noack_ratio only (9)": BASE_8 + ["syn_noack_ratio"],
    "D: 8 + ack_ratio only (9)": BASE_8 + ["ack_ratio"],
    "E: Basic (4): pkt_rate, byte_rate, port_div, tcp_flags": ["pkt_rate", "byte_rate", "port_div", "tcp_flags"],
    "F: Minimal (2): pkt_rate, byte_rate": ["pkt_rate", "byte_rate"],
}


def bench_inference(model, X_test, repeats=100):
    row = X_test.iloc[[0]]
    t0 = time.time()
    for _ in range(repeats):
        model.predict(row)
    return (time.time() - t0) / repeats * 1000


def main():
    df = pd.read_csv(os.path.join(REPO_ROOT, "evaluation_output", "extracted_features.csv"))
    train_df, test_df = per_type_temporal_split(df)
    params = load_ml_hyperparams()
    print(f"[feature_dims_v2] production hyperparams held fixed: {params}")

    results = []
    for name, cols in FEATURE_SETS.items():
        X_train, y_train = train_df[cols], train_df["label"]
        X_test, y_test = test_df[cols], test_df["label"]

        model = xgb.XGBClassifier(
            n_estimators=params["n_estimators"], max_depth=params["max_depth"],
            learning_rate=params["learning_rate"], objective=params["objective"],
            eval_metric="logloss",
        )
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr_pct = fp / (fp + tn) * 100 if (fp + tn) > 0 else 0.0
        f1w = f1_score(y_test, y_pred, average="weighted")
        inf_ms = bench_inference(model, X_test)

        row = {"feature_set": name, "n_features": len(cols), "f1_weighted": round(f1w, 3),
               "fpr_pct": round(fpr_pct, 2), "inference_ms": round(inf_ms, 3)}
        results.append(row)
        print(f"[feature_dims_v2] {row}")

    out = {
        "method": "Real ablation 1, re-scoped for the current 10-feature production model. Production "
                  "hyperparameters (max_depth=9, lr=0.2) held fixed across all groups; only the feature "
                  "set varies. Groups C/D isolate syn_noack_ratio's and ack_ratio's real individual "
                  "marginal contributions (both are folded into group A/B's combined delta in the "
                  "original 2-feature-at-once test).",
        "results": results,
    }
    print(json.dumps(out, indent=2))

    out_path = os.path.join(REPO_ROOT, "evaluation_output", "ablation_feature_dims_v2.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[feature_dims_v2] wrote {out_path}")


if __name__ == "__main__":
    main()
