import sys
from pathlib import Path

import pandas as pd
import sklearn
import tldextract
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix, roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

from host_features import FEATURE_COLUMNS, extract_host, extract_host_features

# ---------- Safety check: right Python environment ----------
if sklearn.__version__ != "1.5.1":
    sys.exit(
        f"Wrong environment: scikit-learn {sklearn.__version__} "
        f"({sys.executable}). Use coreml_env (needs 1.5.1)."
    )

BASE_DIR = Path(__file__).resolve().parent
data = pd.read_csv(BASE_DIR / "host_features.csv")

# ---------- Group by registrable domain ----------
# include_psl_private_domains=True: "abc.web.app" counts as its own domain,
# because the attacker chose "abc".
extractor = tldextract.TLDExtract(include_psl_private_domains=True)


def registrable_domain(host):
    return extractor(host).registered_domain or host


data["group"] = data["host"].map(registrable_domain)

X = data[FEATURE_COLUMNS]
y = data["label"]

splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(splitter.split(X, y, groups=data["group"]))

X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

overlap = set(data["group"].iloc[train_idx]) & set(data["group"].iloc[test_idx])
print("Train hosts:", len(train_idx), "| Test hosts:", len(test_idx))
print("Domain overlap between train and test:", len(overlap))

# ---------- Train ----------
model = RandomForestClassifier(
    n_estimators=100,
    min_samples_leaf=5,
    n_jobs=-1,
    random_state=42,
)
model.fit(X_train, y_train)

phish_col = list(model.classes_).index(0)
p_phish = model.predict_proba(X_test)[:, phish_col]
pred = model.predict(X_test)

# ---------- Results ----------
print("\nAccuracy:", round(accuracy_score(y_test, pred), 4))
print("ROC AUC:", round(roc_auc_score(y_test == 0, p_phish), 4))

print("\nConfusion matrix (rows = actual, columns = predicted):")
print(pd.DataFrame(
    confusion_matrix(y_test, pred, labels=[0, 1]),
    index=["actual phishing", "actual legit"],
    columns=["pred phishing", "pred legit"],
))

print("\n" + classification_report(
    y_test, pred, labels=[0, 1],
    target_names=["phishing", "legitimate"],
))

# ---------- Is ML better than a simple rule? ----------
simple_rule = (
    (X_test["dot_count"] == 1)
    & (X_test["digit_count"] == 0)
    & (X_test["hyphen_count"] == 0)
).astype(int)   # 1 = "looks legit"
print("Simple rule accuracy (1 dot, no digits, no hyphens):",
      round(accuracy_score(y_test, simple_rule), 4))

# ---------- What different thresholds mean ----------
actual_phish = (y_test == 0).values
print("\nThreshold  | phishing caught | legit wrongly flagged")
for t in [0.5, 0.7, 0.9]:
    flagged = p_phish >= t
    caught = (flagged & actual_phish).sum() / actual_phish.sum()
    false_alarm = (flagged & ~actual_phish).sum() / (~actual_phish).sum()
    print(f"P >= {t:<5} | {caught:>14.1%} | {false_alarm:>20.1%}")

# ---------- Feature importance ----------
print("\nFeature importance:")
print(pd.Series(model.feature_importances_, index=FEATURE_COLUMNS)
      .sort_values(ascending=False).round(4).to_string())

# ---------- Real-world sanity check ----------
SANITY = [
    ("real", "https://www.google.com"),
    ("real", "https://support.apple.com/en-us/102568"),
    ("real", "https://en.wikipedia.org/wiki/Phishing"),
    ("real", "https://github.com/apple/swift"),
    ("real", "https://mail.google.com"),
    ("real", "https://www.poste.it"),
    ("real", "https://www.unina.it"),
    ("real", "https://www.amazon.it/gp/css/order-history"),
    ("real", "https://www.intesasanpaolo.com"),
    ("fake", "http://paypal.com.secure-login.xyz/verify"),
    ("fake", "https://secure-update-account4421.com"),
    ("fake", "https://appleid-verify-login.net"),
    ("fake", "http://poste-it-verifica.info/track"),
    ("fake", "http://192.168.10.5/login"),
    ("fake", "https://xk7q9z2p.top"),
]
hosts = [extract_host(url) for _, url in SANITY]
X_sanity = pd.DataFrame([extract_host_features(h) for h in hosts],
                        columns=FEATURE_COLUMNS)
p_sanity = model.predict_proba(X_sanity)[:, phish_col]

print("\nSanity check (P = probability of phishing):")
for (kind, url), host, p in zip(SANITY, hosts, p_sanity):
    print(f"{kind}  P={p:.2f}  {host}")