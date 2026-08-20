#!/usr/bin/env python3
"""Real randomized hyperparameter search (+ optional SMOTE) on the combined
UDP+SYN 83,457-row dataset, using the same per-type temporal 80/20 split as
the main training run for the FINAL held-out evaluation.

Methodology note (a real improvement over the earlier ad hoc ablations,
which evaluated each candidate directly against the real test set): search
itself uses 3-fold StratifiedKFold cross-validation *within the training
split only* -- the real test set is touched exactly once per model, for
the single final reported number, not probed repeatedly while tuning. CV
folds are not temporally ordered (a real, disclosed departure from the
thesis's temporal-split framing, used here only for hyperparameter
selection, not for the final reported metric).

Two searches are run:
  1. Plain XGBoost hyperparameter search (no resampling).
  2. Same search, with SMOTE oversampling of the minority (attack) class
     wrapped inside an imblearn Pipeline -- SMOTE is fit only on each CV
     fold's training partition, never on its validation fold or on the
     real test set, so there is no synthetic-data leakage into anything
     that gets reported as a real metric.

Both best configs are refit on the full real training set and scored once
on the real, untouched test set. Both real outcomes are reported --
neither is picked or hidden based on which one looks better.
"""
import json
import os
import sys

import pandas as pd
import xgboost as xgb
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from controller.ml.train_model import FEATURE_COLUMNS, load_ml_hyperparams, per_type_temporal_split  # noqa: E402

N_ITER = 25
CV_FOLDS = 3
RANDOM_STATE = 42

PARAM_DIST = {
    "clf__max_depth": [3, 6, 9, 12, 15],
    "clf__n_estimators": [100, 150, 200, 300],
    "clf__learning_rate": [0.02, 0.05, 0.1, 0.2],
    "clf__min_child_weight": [1, 3, 5, 7],
    "clf__subsample": [0.7, 0.8, 0.9, 1.0],
    "clf__colsample_bytree": [0.7, 0.8, 0.9, 1.0],
    "clf__gamma": [0, 0.1, 0.5, 1.0],
}
SMOTE_PARAM_DIST = dict(PARAM_DIST, **{"smote__sampling_strategy": [0.5, 0.75, 1.0]})


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


def run_search(name, pipeline, param_dist, X_train, y_train, test_df):
    print(f"\n{'=' * 70}\n{name}: RandomizedSearchCV, {N_ITER} candidates x {CV_FOLDS}-fold CV (train only)\n{'=' * 70}")
    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)
    search = RandomizedSearchCV(
        pipeline, param_distributions=param_dist, n_iter=N_ITER, cv=cv,
        scoring="f1", random_state=RANDOM_STATE, n_jobs=-1, refit=True,
    )
    search.fit(X_train, y_train)
    print(f"[{name}] best CV f1 (train-only, real): {search.best_score_:.4f}")
    print(f"[{name}] best params: {json.dumps(search.best_params_, indent=2)}")

    cm, overall, per_type = evaluate(search.best_estimator_, test_df)
    print(f"[{name}] REAL held-out test set (touched once):")
    print(f"  confusion matrix:\n{cm}")
    print(f"  accuracy={overall['accuracy']:.4f}  attack: precision={overall['attack']['precision']:.3f} "
          f"recall={overall['attack']['recall']:.3f} f1={overall['attack']['f1-score']:.3f}  "
          f"weighted_f1={overall['weighted avg']['f1-score']:.3f}")
    for atype, rep in per_type.items():
        print(f"    {atype}-vs-benign: precision={rep['attack']['precision']:.3f} "
              f"recall={rep['attack']['recall']:.3f} f1={rep['attack']['f1-score']:.3f}")

    return {
        "best_cv_f1_train_only": search.best_score_,
        "best_params": search.best_params_,
        "test_confusion_matrix": cm.tolist(),
        "test_accuracy": overall["accuracy"],
        "test_attack_precision": overall["attack"]["precision"],
        "test_attack_recall": overall["attack"]["recall"],
        "test_attack_f1": overall["attack"]["f1-score"],
        "test_weighted_f1": overall["weighted avg"]["f1-score"],
        "test_per_attack_type": {k: {"precision": v["attack"]["precision"], "recall": v["attack"]["recall"],
                                      "f1": v["attack"]["f1-score"]} for k, v in per_type.items()},
    }


def main():
    df = pd.read_csv(os.path.join(REPO_ROOT, "evaluation_output", "extracted_features.csv"))
    train_df, test_df = per_type_temporal_split(df)
    params = load_ml_hyperparams()
    X_train, y_train = train_df[FEATURE_COLUMNS], train_df["label"]

    base_clf = xgb.XGBClassifier(objective=params["objective"], eval_metric="logloss", random_state=RANDOM_STATE)

    plain_pipeline = ImbPipeline([("clf", base_clf)])
    results = {"plain_search": run_search("A: plain hyperparameter search (no SMOTE)",
                                           plain_pipeline, PARAM_DIST, X_train, y_train, test_df)}

    smote_pipeline = ImbPipeline([
        ("smote", SMOTE(random_state=RANDOM_STATE)),
        ("clf", xgb.XGBClassifier(objective=params["objective"], eval_metric="logloss", random_state=RANDOM_STATE)),
    ])
    results["smote_search"] = run_search("B: hyperparameter search + SMOTE (leakage-safe CV pipeline)",
                                          smote_pipeline, SMOTE_PARAM_DIST, X_train, y_train, test_df)

    out_path = os.path.join(REPO_ROOT, "evaluation_output", "tuning_search_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[tune_search] wrote {out_path}")


if __name__ == "__main__":
    main()
