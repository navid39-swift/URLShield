import json
import os
import sys
from pathlib import Path

import coremltools as ct
import joblib
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier

from host_features import (
    FEATURE_COLUMNS, extract_host, extract_host_features, tld_of,
)

if sklearn.__version__ != "1.5.1":
    sys.exit(f"Wrong environment: scikit-learn {sklearn.__version__}")

BASE_DIR = Path(__file__).resolve().parent
SMOOTHING = 20
MODEL_COLUMNS = FEATURE_COLUMNS + ["tld_phish_rate"]

# ---------- 1. TLD rates from ALL data ----------
data = pd.read_csv(BASE_DIR / "host_features.csv")
data["tld"] = data["host"].map(tld_of)

prior = round(float((data["label"] == 0).mean()), 6)
stats = data.groupby("tld")["label"].agg(count="size", legit="sum")
phish = stats["count"] - stats["legit"]
rates = ((phish + SMOOTHING * prior) / (stats["count"] + SMOOTHING)).round(6)

data["tld_phish_rate"] = data["tld"].map(rates)

with open(BASE_DIR / "tld_rates.json", "w") as f:
    json.dump(
        {
            "smoothing": SMOOTHING,
            "prior": prior,
            "rates": {tld: float(r) for tld, r in rates.sort_index().items()},
        },
        f,
        indent=1,
    )
print("TLDs saved:", len(rates), "| prior:", prior)

# ---------- 2. Train the final model on ALL hosts ----------
model = RandomForestClassifier(
    n_estimators=100, min_samples_leaf=5, n_jobs=-1, random_state=42,
)
model.fit(data[MODEL_COLUMNS], data["label"])
joblib.dump(model, BASE_DIR / "urlshield_host_rf.joblib")

nodes = sum(tree.tree_.node_count for tree in model.estimators_)
print("Trained on", len(data), "hosts | total tree nodes:", nodes)

# ---------- 3. Convert to Core ML ----------
coreml_model = ct.converters.sklearn.convert(
    model,
    input_features=MODEL_COLUMNS,
    output_feature_names=["prediction", "probabilities"],
)

coreml_model.author = "Navid Zare"
coreml_model.short_description = (
    "Estimates whether a hostname looks like phishing. "
    "Label 0 = phishing, 1 = legitimate."
)
coreml_model.version = "2.0"
coreml_model.user_defined_metadata["feature_order"] = ",".join(MODEL_COLUMNS)
coreml_model.user_defined_metadata["tld_smoothing"] = str(SMOOTHING)
coreml_model.user_defined_metadata["training_data"] = (
    "PhiUSIIL Phishing URL Dataset (UCI), hostnames only, deduplicated, "
    "shorteners, open platforms and IPFS gateways removed"
)

model_path = BASE_DIR / "URLShieldHost.mlmodel"
coreml_model.save(str(model_path))
print(f"Saved {model_path.name}: {os.path.getsize(model_path) / 1_000_000:.1f} MB")

# ---------- 4. Check: Core ML gives the same answers as scikit-learn ----------
SANITY = [
    "https://www.google.com",
    "https://support.apple.com/en-us/102568",
    "https://www.poste.it",
    "http://paypal.com.secure-login.xyz/verify",
    "http://poste-it-verifica.info/track",
    "https://xk7q9z2p.top",
    "http://192.168.10.5/login",
]
phish_col = list(model.classes_).index(0)

print("\nP(phishing): scikit-learn vs Core ML")
max_diff = 0.0
for url in SANITY:
    host = extract_host(url)
    row = extract_host_features(host) + [float(rates.get(tld_of(host), prior))]

    p_sklearn = model.predict_proba(
        pd.DataFrame([row], columns=MODEL_COLUMNS)
    )[0][phish_col]
    result = coreml_model.predict({name: float(v) for name, v in zip(MODEL_COLUMNS, row)})
    p_coreml = result["probabilities"][0]

    max_diff = max(max_diff, abs(p_sklearn - p_coreml))
    print(f"{p_sklearn:.4f}  {p_coreml:.4f}  {host}")

print(f"\nLargest difference: {max_diff:.6f} (should be below 0.001)")