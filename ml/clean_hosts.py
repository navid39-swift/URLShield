import json
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent

# Links whose real destination is hidden
URL_SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "is.gd", "v.gd", "s.id",
    "t.co", "goo.gl", "ow.ly", "cutt.ly", "rb.gy", "shorturl.at",
    "tiny.cc", "rebrand.ly", "buff.ly", "t.ly", "1drv.ms",
    "v.ht", "urlz.fr", "s.free.fr",
}

# Legitimate platforms where anyone can publish content
OPEN_PLATFORMS = {
    "docs.google.com", "sites.google.com", "drive.google.com",
    "forms.gle", "storage.googleapis.com",
    "firebasestorage.googleapis.com", "s3.amazonaws.com",
    "ipfs.io", "gateway.ipfs.io", "fleek.ipfs.io", "dweb.link",
    "cloudflare-ipfs.com", "cf-ipfs.com", "gateway.pinata.cloud",
    "storageapi.fleek.co", "onedrive.live.com", "dropbox.com",
    "storage.cloud.google.com", "storage.yandexcloud.net",
    "infura-ipfs.io", "ipfs.fleek.co", "storageapi-stg.fleek.co",
    "tribelio.page",
}


def is_ipfs_gateway(host):
    """IPFS gateways: any dot-separated part of the host contains 'ipfs'."""
    return any("ipfs" in part for part in host.split("."))


hosts = pd.read_csv(BASE_DIR / "hosts.csv")

is_shortener = hosts["host"].isin(URL_SHORTENERS)
is_platform = hosts["host"].isin(OPEN_PLATFORMS)
is_ipfs = hosts["host"].map(is_ipfs_gateway)

print("Shortener hosts found:", is_shortener.sum())
print(hosts[is_shortener].to_string(index=False))

print("\nPlatform hosts found:", is_platform.sum())
print(hosts[is_platform].to_string(index=False))

print("\nIPFS hosts per label (should be almost all 0 = phishing):")
print(hosts[is_ipfs]["label"].value_counts())

print("\nIPFS hosts labeled legitimate (check these by eye):")
print(hosts[is_ipfs & (hosts["label"] == 1)].to_string(index=False))

clean = hosts[~(is_shortener | is_platform | is_ipfs)]
clean.to_csv(BASE_DIR / "hosts_clean.csv", index=False)

with open(BASE_DIR / "special_hosts.json", "w") as f:
    json.dump(
        {
            "shorteners": sorted(URL_SHORTENERS),
            "platforms": sorted(OPEN_PLATFORMS),
            "ipfs_rule": "any dot-separated part of the host contains 'ipfs'",
        },
        f,
        indent=2,
    )

print("\nRemoved in total:", len(hosts) - len(clean))
print("\nClean hosts per label (1 = legitimate, 0 = phishing):")
print(clean["label"].value_counts())

print("\nTop 30 remaining phishing hosts (look for platforms we missed):")
print(clean[clean.label == 0].nlargest(30, "url_count").to_string(index=False))