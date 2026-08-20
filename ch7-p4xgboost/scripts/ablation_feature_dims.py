#!/usr/bin/env python3
"""Real ablation: feature dimensionality, re-run on the combined UDP+SYN
83,457-row dataset (evaluation_output/extracted_features.csv) using the
same per-type temporal 80/20 split as the main training run, so results
are directly comparable to controller/ml/train_model.py's real numbers
rather than the older single-attack-type ablation this replaces."""
import json
import os
import sys
import time

import pandas as pd
import xgboost as xgb
from sklearn.metrics import confusion_matrix, f1_score

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from controller.ml.train_model import load_ml_hyperparams, per_type_temporal_split  # noqa: E402

FEATURE_SETS = {
    "Full (8 features)": ["pkt_rate", "byte_rate", "duration", "proto_var",
                           "port_div", "size_var", "tcp_flags", "inter_arrival"],
    "Basic (4 features: pkt_rate, byte_rate, port_div, tcp_flags)":
        ["pkt_rate", "byte_rate", "port_div", "tcp_flags"],
    "Minimal (2 features: pkt_rate, byte_rate)": ["pkt_rate", "byte_rate"],
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

        row = {"feature_set": name, "f1_weighted": round(f1w, 3),
               "fpr_pct": round(fpr_pct, 2), "inference_ms": round(inf_ms, 3)}
        results.append(row)
        print(f"[feature_dims] {name}: {row}")

    out = {
        "method": "Retrained real XGBoost on the same real per-type temporal 80/20 split "
                  "(controller/ml/train_model.py's per_type_temporal_split, combined UDP+SYN "
                  "83,457-row dataset), varying which of the 8 real features are included. "
                  "Weighted-avg F1 and FPR from real confusion matrices; inference time is a "
                  "real single-row microbenchmark (100 repeats, mean).",
        "results": results,
    }
    print(json.dumps(out, indent=2))

    out_path = os.path.join(REPO_ROOT, "evaluation_output", "ablation_feature_dims.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[feature_dims] wrote {out_path}")


if __name__ == "__main__":
    main()
