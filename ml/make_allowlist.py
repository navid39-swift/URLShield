import csv
import json
from collections import Counter
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
TOP_N = 5000
PLATFORM_LIMIT = 3   # phishing subdomains under one domain = probably a hosting platform

# Always included (Italian services + big brands we test with)
MANUAL = [
    "google.com", "apple.com", "icloud.com", "wikipedia.org", "microsoft.com",
    "amazon.com", "amazon.it", "paypal.com", "github.com", "netflix.com",
    "poste.it", "posteitaliane.it", "intesasanpaolo.com", "unicredit.it",
    "bper.it", "bancobpm.it", "mps.it", "finecobank.com",
    "inps.it", "agenziaentrate.gov.it", "unina.it", "dhl.com", "dhl.it",
]

# 1. Top domains from Tranco
top = []
tranco_path = BASE_DIR / "tranco.csv"
if tranco_path.exists():
    with open(tranco_path, newline="") as f:
        for row in csv.reader(f):
            if len(row) >= 2:
                top.append(row[1].strip().lower())
            if len(top) >= TOP_N:
                break
else:
    print("WARNING: tranco.csv not found, using only the manual list")

# 2. Find domains where attackers host phishing on many subdomains
hosts = pd.read_csv(BASE_DIR / "hosts_clean.csv")
phish_hosts = set(hosts.loc[hosts["label"] == 0, "host"])
fresh_path = BASE_DIR / "fresh_phishing.csv"
if fresh_path.exists():   # v2: also learn platforms from the fresh phishing list
    phish_hosts |= set(pd.read_csv(fresh_path)["host"])
    print("Using fresh_phishing.csv too")

subdomain_counts = Counter()
for host in phish_hosts:
    labels = host.split(".")
    for i in range(1, len(labels) - 1):
        subdomain_counts[".".join(labels[i:])] += 1

excluded = sorted(
    d for d in top
    if d in phish_hosts or subdomain_counts[d] >= PLATFORM_LIMIT
)
allowlist = sorted((set(top) - set(excluded)) | set(MANUAL))

with open(BASE_DIR / "allowlist.json", "w") as f:
    json.dump(allowlist, f, indent=0)

print("Top domains read:", len(top))
print("Excluded (phishing found on them):", len(excluded))
print(excluded[:60])
print("Allowlist size:", len(allowlist))