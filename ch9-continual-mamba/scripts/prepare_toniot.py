from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd


DROP_COLUMNS = {
    "src_ip",
    "dst_ip",
    "dns_query",
    "ssl_subject",
    "ssl_issuer",
    "http_uri",
    "http_user_agent",
    "label",
}


def encode_categoricals(df: pd.DataFrame, target_col: str) -> pd.DataFrame:
    out = df.copy()
    for col in out.columns:
        if col == target_col:
            continue
        if out[col].dtype == "object":
            values = out[col].fillna("-").astype(str)
            out[col] = pd.Categorical(values).codes.astype(np.int32)
    return out


def write_stratified_shards(
    df: pd.DataFrame,
    out_dir: Path,
    target_col: str,
    n_shards: int,
    seed: int,
) -> None:
    rng = np.random.default_rng(seed)
    shard_parts = [[] for _ in range(n_shards)]

    for _, group in df.groupby(target_col, sort=True):
        idx = group.index.to_numpy()
        rng.shuffle(idx)
        for shard_id, part in enumerate(np.array_split(idx, n_shards)):
            if len(part) > 0:
                shard_parts[shard_id].append(df.loc[part])

    out_dir.mkdir(parents=True, exist_ok=True)
    for shard_id, parts in enumerate(shard_parts, start=1):
        shard = pd.concat(parts, axis=0)
        shard = shard.sample(frac=1.0, random_state=seed + shard_id).reset_index(drop=True)
        shard.to_csv(out_dir / f"Merged{shard_id:02d}.csv", index=False)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare ToN-IoT Network CSV for continual_mamba.")
    parser.add_argument("--input", required=True, help="Path to train_test_network.csv")
    parser.add_argument("--output-dir", required=True, help="Directory for Merged*.csv shards")
    parser.add_argument("--shards", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    in_path = Path(args.input)
    out_dir = Path(args.output_dir)
    target_col = "type"

    df = pd.read_csv(in_path)
    missing = {"type", "label"} - set(df.columns)
    if missing:
        raise ValueError(f"Missing expected ToN-IoT columns: {sorted(missing)}")

    keep_drop = [c for c in DROP_COLUMNS if c in df.columns]
    df = df.drop(columns=keep_drop)
    df = encode_categoricals(df, target_col=target_col)
    df = df.rename(columns={target_col: "Label"})

    feature_cols = [c for c in df.columns if c != "Label"]
    df[feature_cols] = (
        df[feature_cols]
        .apply(pd.to_numeric, errors="coerce")
        .replace([np.inf, -np.inf], np.nan)
        .fillna(0.0)
        .clip(-1e9, 1e9)
    )

    write_stratified_shards(
        df=df,
        out_dir=out_dir,
        target_col="Label",
        n_shards=args.shards,
        seed=args.seed,
    )

    print(f"Wrote {args.shards} stratified shards to {out_dir}")
    print(df["Label"].value_counts().sort_index().to_string())
    print(f"Features: {len(feature_cols)}")


if __name__ == "__main__":
    main()
