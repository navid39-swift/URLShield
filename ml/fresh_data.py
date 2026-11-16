"""Shared helpers for the v2 scripts (fresh phishing data)."""
import csv
import json
from pathlib import Path

import pandas as pd
import tldextract

BASE_DIR = Path(__file__).resolve().parent
FRESH_DIR = BASE_DIR / "fresh_data"
V1_DIR = BASE_DIR / "model_v1"

# suffix_list_urls=() -> use the suffix list shipped with tldextract (no network)
_extractor = tldextract.TLDExtract(include_psl_private_domains=True, suffix_list_urls=())


def registrable_domain(host):
    """'abc.weebly.com' -> 'abc.weebly.com' (private suffix), 'mail.unina.it' -> 'unina.it'."""
    r = _extractor(host)
    domain = getattr(r, "top_domain_under_public_suffix", None)
    if domain is None:                      # older tldextract versions
        domain = r.registered_domain
    return domain or host


def is_ipfs_gateway(host):
    return any("ipfs" in part for part in host.split("."))


def load_special_hosts():
    special = json.loads((BASE_DIR / "special_hosts.json").read_text())
    return set(special["shorteners"]) | set(special["platforms"])


def load_tranco():
    """List of domains in rank order (rank 1 first)."""
    with open(BASE_DIR / "tranco.csv", newline="") as f:
        return [row[1].strip().lower() for row in csv.reader(f) if len(row) >= 2]


def make_allowlist_check(allowlist):
    """Same rule as the app: the host or any parent domain is on the list."""
    def check(host):
        labels = host.split(".")
        return any(".".join(labels[i:]) in allowlist for i in range(len(labels) - 1))
    return check


def load_fresh_phishing():
    path = BASE_DIR / "fresh_phishing.csv"
    if not path.exists():
        raise SystemExit("fresh_phishing.csv not found. Run fetch_fresh_phishing.py first.")
    return pd.read_csv(path)
