#!/usr/bin/env python3
"""Real ablation: XGBoost max_depth, re-run on the combined UDP+SYN
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
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from controller.ml.train_model import (  # noqa: E402
    FEATURE_COLUMNS, load_ml_hyperparams, per_type_temporal_split,
)

DEPTHS = [3, 6, 9, 12]


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

    X_train, y_train = train_df[FEATURE_COLUMNS], train_df["label"]
    X_test, y_test = test_df[FEATURE_COLUMNS], test_df["label"]

    results = []
    for depth in DEPTHS:
        model = xgb.XGBClassifier(
            n_estimators=params["n_estimators"], max_depth=depth,
            learning_rate=params["learning_rate"], objective=params["objective"],
            eval_metric="logloss",
        )
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)

        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1w = f1_score(y_test, y_pred, average="weighted")
        inf_ms = bench_inference(model, X_test)

        row = {"depth": depth, "precision": round(precision, 3), "recall": round(recall, 3),
               "f1_weighted": round(f1w, 3), "inference_ms": round(inf_ms, 3)}
        results.append(row)
        print(f"[tree_depth] {row}")

    out = {
        "method": "Retrained real XGBoost at max_depth in {3,6,9,12} on the same real per-type "
                  "temporal 80/20 split (combined UDP+SYN 83,457-row dataset). Same single-row "
                  "microbenchmark methodology (100 repeats, mean) for inference time.",
        "results": results,
    }
    print(json.dumps(out, indent=2))

    out_path = os.path.join(REPO_ROOT, "evaluation_output", "ablation_tree_depth.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[tree_depth] wrote {out_path}")


if __name__ == "__main__":
    main()
