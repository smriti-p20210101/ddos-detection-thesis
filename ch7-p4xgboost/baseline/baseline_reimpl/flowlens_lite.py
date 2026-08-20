"""
flowlens_lite.py -- offline equivalent of p4/flowlens_lite.p4 + a
RandomForestClassifier standing in for FlowLens's own use-case classifier
(the paper uses Random Forest for its closest-to-DDoS use case, P2P botnet
chatter detection -- see docs/flowlens_lite.md for the mapping rationale).

Unlike jaqen_lite.py and poseidon_lite.py (both threshold-based, no
training), FlowLens's classifier must be trained. `fit_predict()` performs
the same temporal 80/20 split used everywhere else in this comparison and
returns predictions on the held-out test set only.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from common import REG_SIZE, MemoryFootprint, ensure_bin_histogram, temporal_split

NUM_BINS = 10
QUANT_SHIFT = 4  # QL=4, per p4/flowlens_lite.p4 and the paper's best-reported
                   # covert-channel configuration (Table III)


def fit_predict(df: pd.DataFrame, ts_col: str = "timestamp", random_state: int = 0):
    """Returns (y_test, y_pred) using the standard 80/20 temporal split."""
    df = ensure_bin_histogram(df, num_bins=NUM_BINS, quant_shift=QUANT_SHIFT)
    bin_cols = [f"bin_{i}" for i in range(NUM_BINS)]

    train_df, test_df = temporal_split(df, ts_col=ts_col)

    X_train = train_df[bin_cols].to_numpy()
    y_train = train_df["label"].to_numpy()
    X_test = test_df[bin_cols].to_numpy()
    y_test = test_df["label"].to_numpy()

    clf = RandomForestClassifier(
        n_estimators=100, max_depth=None, random_state=random_state, n_jobs=-1
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    return y_test, y_pred, clf


def memory_footprint(num_flows: int = REG_SIZE, num_bins: int = NUM_BINS) -> MemoryFootprint:
    """num_flows x num_bins x 16-bit counters -- matches p4/flowlens_lite.p4's
    register grid, and is deliberately reported in the same units as
    P4-XGBoost's CMS and Jaqen-lite/POSEIDON-lite's registers for a direct
    memory-footprint comparison in Table 7.6."""
    bytes_total = num_flows * num_bins * 2
    return MemoryFootprint(
        name="FlowLens-lite",
        bytes_total=bytes_total,
        breakdown=f"{num_flows}x{num_bins}x16b flow-marker register grid",
    )
