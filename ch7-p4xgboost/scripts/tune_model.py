#!/usr/bin/env python3
"""Real hyperparameter/class-weighting exploration on the combined UDP+SYN
83,457-row dataset, using the same per-type temporal 80/20 split as the
main training run. Evaluates real candidate configurations and prints
real metrics for each -- does not silently pick or hide any result.

Candidates:
  A. depth=6,  no class weighting   (current production model, for reference)
  B. depth=12, no class weighting   (real ablation already showed this helps)
  C. depth=6,  scale_pos_weight     (real class weighting for benign/attack imbalance)
  D. depth=12, scale_pos_weight     (combined)

scale_pos_weight = (# benign train rows) / (# attack train rows), the
standard XGBoost recipe for imbalanced binary classification -- not a
tuned/fitted value, a real ratio computed directly from the training split.
"""
import json
import os
import sys

import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from controller.ml.train_model import FEATURE_COLUMNS, load_ml_hyperparams, per_type_temporal_split  # noqa: E402


def evaluate(model, test_df):
    X_test, y_test = test_df[FEATURE_COLUMNS], test_df["label"]
    y_pred = model.predict(X_test)
    cm = confusion_matrix(y_test, y_pred)
    overall = classification_report(y_test, y_pred, target_names=["benign", "attack"],
                                     digits=3, output_dict=True, zero_division=0)

    per_type = {}
    for atype in ["udp", "syn"]:
        mask = test_df["attack_type"].isin(["benign", atype])
        if (test_df.loc[mask, "attack_type"] == atype).sum() == 0:
            continue
        y_t = test_df.loc[mask, "label"]
        y_p = pd.Series(y_pred, index=test_df.index).loc[mask]
        per_type[atype] = classification_report(y_t, y_p, target_names=["benign", "attack"],
                                                  digits=3, output_dict=True, zero_division=0)
    return cm, overall, per_type


def main():
    df = pd.read_csv(os.path.join(REPO_ROOT, "evaluation_output", "extracted_features.csv"))
    train_df, test_df = per_type_temporal_split(df)
    params = load_ml_hyperparams()

    X_train, y_train = train_df[FEATURE_COLUMNS], train_df["label"]
    n_benign = (y_train == 0).sum()
    n_attack = (y_train == 1).sum()
    spw = n_benign / n_attack
    print(f"[tune] train rows: {len(train_df)} (benign={n_benign}, attack={n_attack}), "
          f"real scale_pos_weight = {spw:.3f}")

    candidates = {
        "A_depth6_noweight": dict(max_depth=6, scale_pos_weight=1.0),
        "B_depth12_noweight": dict(max_depth=12, scale_pos_weight=1.0),
        "C_depth6_weighted": dict(max_depth=6, scale_pos_weight=spw),
        "D_depth12_weighted": dict(max_depth=12, scale_pos_weight=spw),
    }

    results = {}
    for name, overrides in candidates.items():
        model = xgb.XGBClassifier(
            n_estimators=params["n_estimators"], max_depth=overrides["max_depth"],
            learning_rate=params["learning_rate"], objective=params["objective"],
            scale_pos_weight=overrides["scale_pos_weight"], eval_metric="logloss",
        )
        model.fit(X_train, y_train)
        cm, overall, per_type = evaluate(model, test_df)

        print(f"\n=== {name} (depth={overrides['max_depth']}, scale_pos_weight={overrides['scale_pos_weight']:.3f}) ===")
        print(f"confusion matrix:\n{cm}")
        print(f"accuracy={overall['accuracy']:.4f}  "
              f"attack: precision={overall['attack']['precision']:.3f} "
              f"recall={overall['attack']['recall']:.3f} f1={overall['attack']['f1-score']:.3f}  "
              f"weighted_f1={overall['weighted avg']['f1-score']:.3f}")
        for atype, rep in per_type.items():
            print(f"  {atype}-vs-benign: precision={rep['attack']['precision']:.3f} "
                  f"recall={rep['attack']['recall']:.3f} f1={rep['attack']['f1-score']:.3f}")

        results[name] = {
            "max_depth": overrides["max_depth"], "scale_pos_weight": round(overrides["scale_pos_weight"], 3),
            "confusion_matrix": cm.tolist(), "accuracy": overall["accuracy"],
            "attack_precision": overall["attack"]["precision"], "attack_recall": overall["attack"]["recall"],
            "attack_f1": overall["attack"]["f1-score"], "weighted_f1": overall["weighted avg"]["f1-score"],
            "per_attack_type": {k: {"precision": v["attack"]["precision"], "recall": v["attack"]["recall"],
                                     "f1": v["attack"]["f1-score"]} for k, v in per_type.items()},
        }

    out_path = os.path.join(REPO_ROOT, "evaluation_output", "tuning_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[tune] wrote {out_path}")


if __name__ == "__main__":
    main()
