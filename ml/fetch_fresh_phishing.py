"""Step B1: download fresh phishing domains and clean them.

Source: Phishing.Database by Mitchell Krog (MIT License)
https://github.com/mitchellkrogza/Phishing.Database

Output: fresh_phishing.csv  (host, group) - only hosts the model has NEVER seen.
"""
import subprocess
import sys
from collections import Counter
from datetime import date

import pandas as pd

from fresh_data import (
    BASE_DIR, FRESH_DIR, is_ipfs_gateway, load_special_hosts, load_tranco,
    registrable_domain,
)
from host_features import extract_host

URL = ("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/"
       "master/phishing-domains-ACTIVE.txt")
TRANCO_TOP = 100_000   # a phishing "host" that IS a top-100k site is probably a mistake or a hacked site

# ---------- 1. Download (once per day) ----------
FRESH_DIR.mkdir(exist_ok=True)
raw_path = FRESH_DIR / f"phishing-domains-ACTIVE-{date.today()}.txt"
if not raw_path.exists():
    print("Downloading", URL)
    result = subprocess.run(["curl", "-sSfL", "--max-time", "120", "-o", str(raw_path), URL])
    if result.returncode != 0:
        raw_path.unlink(missing_ok=True)
        sys.exit("Download failed. Check your internet connection and try again.")
else:
    print("Using today's file:", raw_path.name)

lines = [l.strip() for l in raw_path.read_text().splitlines()]
lines = [l for l in lines if l and not l.startswith("#")]
print("Lines in the list:", len(lines))

# ---------- 2. Normalize exactly like the app ----------
hosts = {extract_host(l) for l in lines}
hosts.discard("")
print("Unique hosts after normalizing:", len(hosts))

# ---------- 3. Remove what the model should not learn from ----------
known = set(pd.read_csv(BASE_DIR / "hosts_clean.csv")["host"])
special = load_special_hosts()
top_sites = set(load_tranco()[:TRANCO_TOP])

removed = Counter()
fresh = []
for host in sorted(hosts):
    if host in known:
        removed["already in PhiUSIIL"] += 1
    elif host in special or is_ipfs_gateway(host):
        removed["shortener / platform / IPFS (handled by rules)"] += 1
    elif host in top_sites:
        removed[f"is itself a Tranco top-{TRANCO_TOP:,} site"] += 1
    else:
        fresh.append(host)

for reason, n in removed.items():
    print(f"  removed {n:>7,}  {reason}")

df = pd.DataFrame({"host": fresh})
df["group"] = df["host"].map(registrable_domain)
df.to_csv(BASE_DIR / "fresh_phishing.csv", index=False)

print(f"\nFresh phishing hosts kept: {len(df):,}")
print(f"Different registrable domains: {df['group'].nunique():,}")
print("\nDomains with the most phishing subdomains (= hosting platforms):")
for group, n in df["group"].value_counts().head(15).items():
    print(f"  {n:>6,}  {group}")
print("\nSaved fresh_phishing.csv")
