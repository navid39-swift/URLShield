"""Step B3: train model v2 = PhiUSIIL + fresh phishing + more legitimate sites.

Same 10 inputs in the same order ("host-v1"), so the app needs no code change.
1. Backs up the v1 files into model_v1/ (only the first time).
2. Builds the bigger dataset -> host_features_v2.csv
3. Fair test: v1 vs v2 on domains v2 did NOT train on.
4. Trains the final v2 on everything, writes URLShieldHost.mlmodel + tld_rates.json
   (the Xcode project keeps its own v1 copies - v2 reaches the app as an update).
"""
import json
import os
import random
import shutil
import sys

import coremltools as ct
import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

from fresh_data import (
    BASE_DIR, V1_DIR, is_ipfs_gateway, load_fresh_phishing, load_special_hosts,
    load_tranco, registrable_domain,
)
from host_features import FEATURE_COLUMNS, extract_host, extract_host_features, tld_of

if sklearn.__version__ != "1.5.1":
    sys.exit(f"Wrong environment: scikit-learn {sklearn.__version__}. Use coreml_env.")

SMOOTHING = 20
PER_DOMAIN_CAP = 2          # max phishing hosts per registrable domain (stops weebly etc. dominating)
MIN_SAMPLES_LEAF = 20       # bigger leaves = smaller model (v1 used 5 on 4x less data)
MAX_MB = 25                 # GitHub's web upload limit
MODEL_COLUMNS = FEATURE_COLUMNS + ["tld_phish_rate"]
random.seed(42)

# ---------- 1. Back up v1 (once) ----------
V1_DIR.mkdir(exist_ok=True)
for name in ["URLShieldHost.mlmodel", "tld_rates.json", "allowlist.json", "urlshield_host_rf.joblib"]:
    if not (V1_DIR / name).exists():
        shutil.copy2(BASE_DIR / name, V1_DIR / name)
        print("Backed up v1:", name, "-> model_v1/")

# ---------- 2. Build the v2 dataset ----------
base = pd.read_csv(BASE_DIR / "host_features.csv")
base["source"] = "PhiUSIIL"
known = set(base["host"])

fresh = load_fresh_phishing()
phish = (fresh.groupby("group")["host"]
         .apply(lambda s: random.sample(sorted(s), min(PER_DOMAIN_CAP, len(s))))
         .explode().tolist())

special = load_special_hosts()
phish_groups = set(fresh["group"])
legit_pool = [d for d in load_tranco()
              if d not in known and d not in phish_groups
              and d not in special and not is_ipfs_gateway(d)]
legit = random.sample(legit_pool, min(len(phish), len(legit_pool)))   # balance the new data


def feature_frame(hosts, label, source):
    df = pd.DataFrame([extract_host_features(h) for h in hosts], columns=FEATURE_COLUMNS)
    df.insert(0, "host", hosts)
    df["label"] = label
    df["source"] = source
    return df


data = pd.concat([base,
                  feature_frame(phish, 0, "fresh phishing"),
                  feature_frame(legit, 1, "Tranco legit")], ignore_index=True)
data.to_csv(BASE_DIR / "host_features_v2.csv", index=False)
data["tld"] = data["host"].map(tld_of)
data["group"] = data["host"].map(registrable_domain)

print("\nv2 dataset (label 0 = phishing, 1 = legit):")
print(data.groupby(["source", "label"]).size().to_string())
print("Total hosts:", len(data))


def tld_rates(df):
    prior = round(float((df["label"] == 0).mean()), 6)
    stats = df.groupby("tld")["label"].agg(count="size", legit="sum")
    rates = ((stats["count"] - stats["legit"] + SMOOTHING * prior)
             / (stats["count"] + SMOOTHING)).round(6)
    return rates, prior


def new_forest():
    return RandomForestClassifier(n_estimators=100, min_samples_leaf=MIN_SAMPLES_LEAF,
                                  n_jobs=-1, random_state=42)


# ---------- 3. Fair test: split by domain ----------
train_idx, test_idx = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
                           .split(data, groups=data["group"]))
train, test = data.iloc[train_idx].copy(), data.iloc[test_idx].copy()
print("\nDomain overlap train/test:", len(set(train["group"]) & set(test["group"])))

rates, prior = tld_rates(train)
for df in (train, test):
    df["tld_phish_rate"] = df["tld"].map(rates).fillna(prior)
v2_test = new_forest().fit(train[MODEL_COLUMNS], train["label"])

# Compare only on the NEW data: v1 trained on all of PhiUSIIL, so that part would be unfair
new = test[test["source"] != "PhiUSIIL"].copy()
v1 = joblib.load(V1_DIR / "urlshield_host_rf.joblib")
v1_tld = json.loads((V1_DIR / "tld_rates.json").read_text())
X_v1 = new[FEATURE_COLUMNS].copy()
X_v1["tld_phish_rate"] = new["tld"].map(lambda t: v1_tld["rates"].get(t, v1_tld["prior"]))

is_phish = (new["label"] == 0).values
print(f"\nFair test on {len(new):,} new hosts from domains neither model trained on:")
print("model | ROC AUC | P>=0.5 caught / false alarms | P>=0.9 caught / false alarms")
for name, model, X in [("v1", v1, X_v1), ("v2", v2_test, new[MODEL_COLUMNS])]:
    p = model.predict_proba(X)[:, list(model.classes_).index(0)]
    print(f" {name}  | {roc_auc_score(is_phish, p):.4f}  |"
          f"   {(p[is_phish] >= .5).mean():6.1%} / {(p[~is_phish] >= .5).mean():6.2%}       |"
          f"   {(p[is_phish] >= .9).mean():6.1%} / {(p[~is_phish] >= .9).mean():6.2%}")

# ---------- 4. Final v2 on ALL data ----------
rates, prior = tld_rates(data)
data["tld_phish_rate"] = data["tld"].map(rates)
model = new_forest().fit(data[MODEL_COLUMNS], data["label"])
joblib.dump(model, BASE_DIR / "urlshield_host_rf_v2.joblib")
nodes = sum(tree.tree_.node_count for tree in model.estimators_)
print(f"\nFinal v2 trained on {len(data):,} hosts | tree nodes: {nodes:,} (v1: 832,574)")

with open(BASE_DIR / "tld_rates.json", "w") as f:
    json.dump({"smoothing": SMOOTHING, "prior": prior,
               "rates": {t: float(r) for t, r in rates.sort_index().items()}}, f, indent=1)
print("TLDs saved:", len(rates), "| prior:", prior)

coreml_model = ct.converters.sklearn.convert(
    model, input_features=MODEL_COLUMNS, output_feature_names=["prediction", "probabilities"])
coreml_model.author = "Navid Zare"
coreml_model.short_description = ("Estimates whether a hostname looks like phishing. "
                                   "Label 0 = phishing, 1 = legitimate.")
coreml_model.version = "v2"
coreml_model.user_defined_metadata["feature_order"] = ",".join(MODEL_COLUMNS)
coreml_model.user_defined_metadata["tld_smoothing"] = str(SMOOTHING)
coreml_model.user_defined_metadata["training_data"] = (
    "PhiUSIIL (UCI) + Phishing.Database ACTIVE domains (MIT) + Tranco legit domains, "
    "hostnames only")
model_path = BASE_DIR / "URLShieldHost.mlmodel"
coreml_model.save(str(model_path))
size_mb = os.path.getsize(model_path) / 1_000_000
print(f"Saved {model_path.name}: {size_mb:.1f} MB" + ("  <-- TOO BIG for GitHub web upload!" if size_mb > MAX_MB else ""))

# ---------- 5. Check Core ML = scikit-learn, and compare with v1 ----------
SANITY = ["google.com", "poste.it", "support.apple.com", "mail.unina.it", "comune.napoli.it",
          "paypa1.com", "paypal.com.secure-login.xyz", "poste-it-verifica.info",
          "xk7q9z2p.top", "secure-update-account4421.com", "192.168.10.5"]
phish_col = list(model.classes_).index(0)
print("\nP(phishing):   v1      v2 (sklearn)  v2 (Core ML)  host")
max_diff = 0.0
for host in map(extract_host, SANITY):
    feats = extract_host_features(host)
    row_v1 = feats + [v1_tld["rates"].get(tld_of(host), v1_tld["prior"])]
    row_v2 = feats + [float(rates.get(tld_of(host), prior))]
    p1 = v1.predict_proba(pd.DataFrame([row_v1], columns=MODEL_COLUMNS))[0][phish_col]
    p2 = model.predict_proba(pd.DataFrame([row_v2], columns=MODEL_COLUMNS))[0][phish_col]
    p2_ml = coreml_model.predict({n: float(v) for n, v in zip(MODEL_COLUMNS, row_v2)})["probabilities"][0]
    max_diff = max(max_diff, abs(p2 - p2_ml))
    print(f"             {p1:.4f}   {p2:.4f}        {p2_ml:.4f}       {host}")
print(f"\nLargest sklearn/Core ML difference: {max_diff:.6f} (should be below 0.001)")
