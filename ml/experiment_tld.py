import sys
from pathlib import Path

import pandas as pd
import sklearn
import tldextract
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

from host_features import (
    FEATURE_COLUMNS, extract_host, extract_host_features, is_ipv4,
)

if sklearn.__version__ != "1.5.1":
    sys.exit(f"Wrong environment: scikit-learn {sklearn.__version__}")

BASE_DIR = Path(__file__).resolve().parent
data = pd.read_csv(BASE_DIR / "host_features.csv")

extractor = tldextract.TLDExtract(include_psl_private_domains=True)


def registrable_domain(host):
    return extractor(host).top_domain_under_public_suffix or host


def tld_of(host):
    """Last part of the host. Swift will copy this exactly."""
    if is_ipv4(host) or host.startswith("["):
        return "<ip>"
    return host.rsplit(".", 1)[-1]


data["group"] = data["host"].map(registrable_domain)
data["tld"] = data["host"].map(tld_of)

# Same split as train_evaluate.py (same random_state)
splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(splitter.split(data, groups=data["group"]))
train = data.iloc[train_idx].copy()
test = data.iloc[test_idx].copy()

# ---------- TLD phishing rate, learned from TRAIN only ----------
SMOOTHING = 20


def fit_tld_rates(df):
    prior = (df["label"] == 0).mean()
    stats = df.groupby("tld")["label"].agg(count="size", legit="sum")
    phish = stats["count"] - stats["legit"]
    rates = (phish + SMOOTHING * prior) / (stats["count"] + SMOOTHING)
    return rates, prior


rates, prior = fit_tld_rates(train)
for df in (train, test):
    df["tld_phish_rate"] = df["tld"].map(rates).fillna(prior)


def evaluate(name, columns):
    model = RandomForestClassifier(
        n_estimators=100, min_samples_leaf=5, n_jobs=-1, random_state=42,
    )
    model.fit(train[columns], train["label"])
    phish_col = list(model.classes_).index(0)
    p = model.predict_proba(test[columns])[:, phish_col]
    actual = (test["label"] == 0).values

    print(f"\n=== {name} ===")
    print("Accuracy:", round(accuracy_score(test["label"], model.predict(test[columns])), 4))
    print("ROC AUC: ", round(roc_auc_score(actual, p), 4))
    for t in (0.5, 0.7, 0.9):
        flagged = p >= t
        caught = (flagged & actual).sum() / actual.sum()
        false_alarm = (flagged & ~actual).sum() / (~actual).sum()
        print(f"P >= {t}: caught {caught:.1%}, false alarms {false_alarm:.1%}")
    return model, phish_col


base_model, base_col = evaluate("Without TLD", FEATURE_COLUMNS)
tld_columns = FEATURE_COLUMNS + ["tld_phish_rate"]
tld_model, tld_col = evaluate("With TLD", tld_columns)

# ---------- Do the TLD rates look like the real world? ----------
counts = train["tld"].value_counts()
common = rates[counts[counts >= 500].index].sort_values(ascending=False)
print("\nTLD phishing rates (TLDs with >= 500 training hosts):")
print(pd.DataFrame({"hosts": counts[common.index], "phish_rate": common.round(3)}).to_string())

# ---------- Sanity check, both models ----------
SANITY = [
    ("real", "https://www.google.com"),
    ("real", "https://support.apple.com/en-us/102568"),
    ("real", "https://en.wikipedia.org/wiki/Phishing"),
    ("real", "https://github.com/apple/swift"),
    ("real", "https://www.poste.it"),
    ("real", "https://www.unina.it"),
    ("real", "https://www.amazon.it/gp/css/order-history"),
    ("real", "https://www.intesasanpaolo.com"),
    ("fake", "http://paypal.com.secure-login.xyz/verify"),
    ("fake", "https://secure-update-account4421.com"),
    ("fake", "https://appleid-verify-login.net"),
    ("fake", "http://poste-it-verifica.info/track"),
    ("fake", "https://xk7q9z2p.top"),
]
hosts = [extract_host(url) for _, url in SANITY]
X_base = pd.DataFrame([extract_host_features(h) for h in hosts], columns=FEATURE_COLUMNS)
X_tld = X_base.copy()
X_tld["tld_phish_rate"] = [rates.get(tld_of(h), prior) for h in hosts]

p_base = base_model.predict_proba(X_base)[:, base_col]
p_tld = tld_model.predict_proba(X_tld)[:, tld_col]

print("\nSanity check, P(phishing): without TLD -> with TLD")
for (kind, _), host, a, b in zip(SANITY, hosts, p_base, p_tld):
    print(f"{kind}  {a:.2f} -> {b:.2f}  {host}")