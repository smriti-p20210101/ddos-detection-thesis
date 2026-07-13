# Ch.10 — Correlation-Aware Random Forest for DDoS Detection (Packet Byte Ratio)

Random Forest DDoS classification evaluated on CICIDS2017 and CICDDoS2019,
including a cross-dataset generalisation test (train on one, test on the
other). Corresponds to the Computer Networks (Elsevier) paper (in preparation).

## Suggested new layout for this chapter

This chapter currently has no real structure — two notebooks sitting inside
a folder literally named `untitled folder/`, with inconsistent naming
(`2017 copy.ipynb`, `2019  & crosscopy.ipynb` — stray double-space and `&`),
plus a `README.md.txt` that GitHub won't render. Proposed reorganisation:

```
ch10-random-forest/
├── notebooks/
│   ├── cicids2017_analysis.ipynb         # was: untitled folder/2017 copy.ipynb
│   └── cicddos2019_cross_dataset.ipynb    # was: untitled folder/2019  & crosscopy.ipynb
├── data/                                    # (create this — see Dataset preparation)
│   ├── CICIDS2017.csv
│   └── cicddos2019_dataset.csv
├── README.md                                  # this file (replaces README.md.txt)
└── requirements.txt
```

**To apply this layout**: rename/move the two notebooks as shown above (see
the top-level `CLEANUP_GUIDE.md` for how to do this via the GitHub web UI —
GitHub's file editor supports rename-as-move). Then delete `README.md.txt`
after uploading this file, and delete the now-empty `untitled folder/`.

**Important — both notebooks currently read their CSVs from the working
directory the notebook is launched from**, via hardcoded relative paths:
```python
df2 = pd.read_csv("CICIDS2017.csv")            # cicids2017_analysis.ipynb
df  = pd.read_csv("cicddos2019_dataset.csv")    # cicddos2019_cross_dataset.ipynb
```
If you move the notebooks into `notebooks/` but keep the CSVs in `data/`,
**these two lines need to change** to `"../data/CICIDS2017.csv"` and
`"../data/cicddos2019_dataset.csv"` respectively (or launch Jupyter from the
chapter root and adjust accordingly) — this is a one-line edit per notebook,
not a structural blocker, but don't skip it or the notebooks will fail on
the first cell with a `FileNotFoundError`.

## What this experiment shows

Random Forest trained and evaluated independently on CICIDS2017 and
CICDDoS2019 both do well in-distribution — but training on one and testing
on the other collapses accuracy, demonstrating a real generalisation gap
rather than a reporting artefact.

## Notebook contents (verified by inspection)

- **`cicids2017_analysis.ipynb`**: loads `CICIDS2017.csv`, drops NaNs, label-encodes
  the target, cleans inf/NaN numeric values, trains/evaluates a
  `RandomForestClassifier` on CICIDS2017 (Case IV in the thesis).
- **`cicddos2019_cross_dataset.ipynb`**: loads `cicddos2019_dataset.csv`,
  trains a `RandomForestClassifier` (`n_estimators=50`, `random_state=42`,
  `test_size=0.3`), evaluates in-distribution (Case V), **then also runs the
  cross-dataset test** — training on one dataset's features and predicting
  on the other, with confusion matrix, macro/micro F1, and ROC/AUC (Case VI).
  This notebook has several iterative/exploratory cells (visible re-runs of
  the same confusion-matrix/label-mapping logic) — harmless to leave as-is,
  but worth trimming to the final working version if you want a cleaner
  notebook for publication alongside the thesis.

## Requirements

Pure Python/scikit-learn — no P4/Mininet/GPU dependency, the lightest
chapter to reproduce in this repo.

## Setup

```bash
pip install -r requirements.txt
jupyter notebook notebooks/
```

## Dataset preparation

1. **CICIDS2017**: download from https://www.unb.ca/cic/datasets/ids-2017.html,
   combine/save as `data/CICIDS2017.csv` (a single merged CSV with a `Label`
   column — check `cicids2017_analysis.ipynb`'s first few cells for the
   exact expected column set before assuming your download matches directly).
2. **CICDDoS2019**: download from https://www.unb.ca/cic/datasets/ddos-2019.html,
   save as `data/cicddos2019_dataset.csv`.
3. Update the two `pd.read_csv(...)` paths as described above if you keep the
   suggested `notebooks/` + `data/` split.

## Running

```bash
jupyter nbconvert --to notebook --execute notebooks/cicids2017_analysis.ipynb
jupyter nbconvert --to notebook --execute notebooks/cicddos2019_cross_dataset.ipynb
```
Or open both in Jupyter interactively if you want to inspect intermediate
cells (recommended for `cicddos2019_cross_dataset.ipynb` given its
exploratory cells, noted above).

## Expected output

- CICIDS2017 (in-distribution): high accuracy, matching the thesis's
  reported 99.44% / macro-F1 0.9696 for this dataset.
- CICDDoS2019 (in-distribution): matching the thesis's reported 93.22%
  accuracy / macro-F1 0.5332.
- Cross-dataset (train CICIDS2017 → test CICDDoS2019, or vice versa per
  which cells you run): a sharp accuracy drop — matching the thesis's
  headline 25.32% cross-dataset accuracy, ROC-AUC ≈ 0.52. This is the
  expected, documented result, not a bug in your reproduction.

## Extending this chapter

- **PBR feature engineering**: the thesis's Packet Byte Ratio feature
  (`PBR = pktcount / bytecount`) is described in the paper text but isn't
  yet a separate, clearly-marked cell in either notebook — add it as an
  explicit feature-engineering step before the `train_test_split` call if
  you want the notebook to visibly match the thesis's Case I/II/III
  correlation-pruning narrative, rather than only covering Cases IV-VI.
- **New dataset**: both notebooks follow the same
  load-CSV → clean → encode → train → evaluate pattern; a third notebook
  following that structure will drop into the cross-dataset comparison with
  minimal changes to the existing cells.

## Citation

"Mitigation of DDoS Attacks in SDN Networks Using Random Forest Classifier,"
thesis Ch.10; Computer Networks, Elsevier (in preparation).
