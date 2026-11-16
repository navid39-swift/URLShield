from pathlib import Path

import pandas as pd

from host_features import FEATURE_COLUMNS, extract_host_features

BASE_DIR = Path(__file__).resolve().parent

hosts = pd.read_csv(BASE_DIR / "hosts_clean.csv").reset_index(drop=True)

features = pd.DataFrame(
    hosts["host"].map(extract_host_features).tolist(),
    columns=FEATURE_COLUMNS,
)
data = pd.concat([hosts[["host", "label"]], features], axis=1)
data.to_csv(BASE_DIR / "host_features.csv", index=False)

print("Shape:", data.shape)
print("Missing values:", data.isna().sum().sum())
print("\nMedian of each feature per label (1 = legitimate, 0 = phishing):")
print(data.groupby("label")[FEATURE_COLUMNS].median().T.round(3))
print("\nMean of each feature per label:")
print(data.groupby("label")[FEATURE_COLUMNS].mean().T.round(3))