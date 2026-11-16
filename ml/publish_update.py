"""Prepare a signed model update in the folder update_site/.

Usage:  python publish_update.py --version 3 --notes "Retrained with fresh data"
Then upload everything inside update_site/ to your GitHub Pages repository.
"""
import argparse
import base64
import hashlib
import json
import shutil
import sys
from pathlib import Path

import coremltools as ct
from cryptography.hazmat.primitives import serialization

from host_features import FEATURE_COLUMNS, extract_host_features, tld_of

BASE_DIR = Path(__file__).resolve().parent
MODEL_COLUMNS = FEATURE_COLUMNS + ["tld_phish_rate"]
FILES = ["URLShieldHost.mlmodel", "tld_rates.json", "allowlist.json", "special_hosts.json"]
SELF_TEST_HOSTS = ["google.com", "poste.it", "paypa1.com", "xk7q9z2p.top", "secure-update-account4421.com"]

parser = argparse.ArgumentParser()
parser.add_argument("--version", type=int, required=True)
parser.add_argument("--notes", default="")
args = parser.parse_args()
BUNDLED_VERSION = 2   # must match ModelStore.bundledVersion in the app
if args.version <= BUNDLED_VERSION:
    sys.exit(f"Version must be {BUNDLED_VERSION + 1} or higher: version {BUNDLED_VERSION} is built into the app.")

out = BASE_DIR / "update_site"
out.mkdir(exist_ok=True)

# 1. Copy files and hash them
entries = []
for name in FILES:
    dst = out / name
    shutil.copyfile(BASE_DIR / name, dst)
    entries.append({"name": name, "sha256": hashlib.sha256(dst.read_bytes()).hexdigest()})

# 2. Expected scores, so the app can self-test the downloaded model
tld = json.loads((BASE_DIR / "tld_rates.json").read_text())
model = ct.models.MLModel(str(BASE_DIR / "URLShieldHost.mlmodel"))
self_tests = []
for host in SELF_TEST_HOSTS:
    row = extract_host_features(host) + [float(tld["rates"].get(tld_of(host), tld["prior"]))]
    result = model.predict({name: float(v) for name, v in zip(MODEL_COLUMNS, row)})
    self_tests.append({"host": host, "pPhishing": round(float(result["probabilities"][0]), 6)})

# 3. Manifest + signature
manifest = {
    "version": args.version,
    "featureSchema": "host-v1",
    "files": entries,
    "selfTests": self_tests,
    "notes": args.notes,
}
data = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
(out / "manifest.json").write_bytes(data)

key = serialization.load_pem_private_key((BASE_DIR / "signing_key_PRIVATE.pem").read_bytes(), password=None)
(out / "manifest.sig").write_text(base64.b64encode(key.sign(data)).decode())

print(f"Update v{args.version} ready in {out.name}/:")
for p in sorted(out.iterdir()):
    print(f"  {p.name:28} {p.stat().st_size / 1_000_000:6.2f} MB")
print("\nSelf-tests:", self_tests)
print("\nUpload ALL files in update_site/ to your GitHub Pages repo. Never upload signing_key_PRIVATE.pem.")
