"""Create the key pair that signs URLShield model updates.

Run ONCE. Keep signing_key_PRIVATE.pem secret: never upload it, never commit it.
Anyone with this file could publish a fake model to every user.
"""
import base64
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE_DIR = Path(__file__).resolve().parent
key_path = BASE_DIR / "signing_key_PRIVATE.pem"

if key_path.exists():
    sys.exit(f"{key_path.name} already exists. Not overwriting it: the app trusts that key.")

key = Ed25519PrivateKey.generate()
key_path.write_bytes(key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
))
key_path.chmod(0o600)

public_raw = key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
print("Private key saved to", key_path.name, "(keep it secret, back it up offline)")
print("\nPaste this public key into ModelUpdater.swift (publicKeyBase64):\n")
print(base64.b64encode(public_raw).decode())
