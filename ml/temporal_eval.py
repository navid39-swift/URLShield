"""Step B2: how good is model v1 on data it has NEVER seen?

- Fresh phishing (from fetch_fresh_phishing.py), one host per domain
  so big hosting platforms don't dominate.
- "Fresh" legitimate sites: Tranco ranks below 100,000 that were not
  in the training data. These are smaller, less famous sites -
  harder than the big sites the model was trained on.
"""
import json
import random
import sys

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import roc_auc_score

from fresh_data import (
    BASE_DIR, V1_DIR, load_fresh_phishing, load_tranco, make_allowlist_check,
    registrable_domain,
)
from host_features import FEATURE_COLUMNS, extract_host_features, tld_of

if sklearn.__version__ != "1.5.1":
    sys.exit(f"Wrong environment: scikit-learn {sklearn.__version__}. Use coreml_env.")

random.seed(42)
LEGIT_SAMPLE = 30_000

# v1 files: from the backup if train_v2.py already ran, otherwise the current ones
src = V1_DIR if (V1_DIR / "urlshield_host_rf.joblib").exists() else BASE_DIR
model = joblib.load(src / "urlshield_host_rf.joblib")
tld = json.loads((src / "tld_rates.json").read_text())
allowlisted = make_allowlist_check(set(json.loads((src / "allowlist.json").read_text())))
print("Evaluating model v1 from:", "model_v1/ backup" if src == V1_DIR else "current v1 files")


def p_phishing(hosts):
    rows = [extract_host_features(h) + [tld["rates"].get(tld_of(h), tld["prior"])] for h in hosts]
    X = pd.DataFrame(rows, columns=FEATURE_COLUMNS + ["tld_phish_rate"])
    return model.predict_proba(X)[:, list(model.classes_).index(0)]


# ---------- 1. Fresh phishing ----------
fresh = load_fresh_phishing()
on_list = fresh[fresh["host"].map(allowlisted)]
print(f"\nFresh phishing hosts the app would call 'Known site': {len(on_list):,}")
print("  most common:", on_list["group"].value_counts().head(8).to_dict())

reach_model = fresh[~fresh["host"].map(allowlisted)]
phish = reach_model.groupby("group")["host"].apply(lambda s: random.choice(list(s))).tolist()

# ---------- 2. Fresh legitimate sites ----------
train_groups = set(pd.read_csv(BASE_DIR / "hosts_clean.csv")["host"].map(registrable_domain))
phish_groups = set(fresh["group"])
tail = [d for d in load_tranco()[100_000:] if d not in train_groups and d not in phish_groups]
legit = random.sample(tail, min(LEGIT_SAMPLE, len(tail)))

# ---------- 3. Score ----------
p = p_phishing(phish)
q = p_phishing(legit)
y = np.r_[np.ones(len(p)), np.zeros(len(q))]
print(f"\nFresh phishing tested: {len(p):,} (one per domain) | fresh legit tested: {len(q):,}")
print(f"ROC AUC on fresh data: {roc_auc_score(y, np.r_[p, q]):.4f}   (v1 test set was 0.8884)")
print("\nThreshold | phishing caught | false alarms on legit")
for t in (0.5, 0.9):
    print(f"   {t:.1f}    |     {(p >= t).mean():6.1%}      |     {(q >= t).mean():6.2%}")
print("\n(v1 test set at 0.9: 57.4% caught, 0.3% false alarms)")
