# Dataset Notes

Large datasets are not included in this repository.

The experiment configs were written for the following local dataset layout:

```text
D:/4-2/CIC_IOT_Dataset2023/MERGED_CSV/Merged*.csv
D:/4-2/TON_IoT_Network/train_test_network.csv
D:/4-2/TON_IoT_Network/MERGED_CSV/Merged*.csv
D:/4-2/CIC-IDS- 2017/*.csv
```

## CIC-IoT2023

The main continual benchmark uses merged CIC-IoT2023 CSV shards with `Label` as the target column.

## ToN-IoT

The raw ToN-IoT network CSV is converted into stratified merged shards:

```powershell
python .\scripts\prepare_toniot.py --input D:\4-2\TON_IoT_Network\train_test_network.csv --output-dir D:\4-2\TON_IoT_Network\MERGED_CSV
```

## CIC-IDS2017

The static check uses local day-wise CIC-IDS2017 CSV files. This is included to provide a same-dataset comparison against the MAMBA-KAN reference, but it is not an exact reproduction of that paper's preprocessing.

