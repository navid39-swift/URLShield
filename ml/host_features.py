import math
import re
from collections import Counter

# ---------- Hostname extraction ----------

SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://")


def extract_host(url):
    s = str(url).strip().lower()
    s = SCHEME_RE.sub("", s, count=1)
    s = s.replace("\\", "/")
    for separator in "/?#":
        s = s.split(separator, 1)[0]
    if "@" in s:
        s = s.rsplit("@", 1)[1]
    if s.startswith("["):
        s = s.split("]", 1)[0] + "]"
    else:
        s = s.split(":", 1)[0]
    s = s.rstrip(".")
    if s.startswith("www."):
        s = s[4:]
    return s


# ---------- Features ----------

FEATURE_COLUMNS = [
    "host_length",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "digit_ratio",
    "longest_label_length",
    "char_entropy",
    "has_ip_address",
    "suspicious_keyword_count",
]

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "account",
    "password", "secure", "update", "confirm", "bank",
    "support", "wallet",
]

DIGITS = set("0123456789")   # ASCII only, so Swift can match exactly


def is_ipv4(host):
    parts = host.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part or len(part) > 3 or any(c not in DIGITS for c in part):
            return False
        if len(part) > 1 and part[0] == "0":
            return False
        if int(part) > 255:
            return False
    return True


def tld_of(host):
    """Last dot-separated part of the host. '<ip>' for IP addresses."""
    if is_ipv4(host) or host.startswith("["):
        return "<ip>"
    return host.rsplit(".", 1)[-1]


def char_entropy(host):
    """Shannon entropy in bits: higher = more random-looking."""
    if not host:
        return 0.0
    n = len(host)
    return -sum((c / n) * math.log2(c / n) for c in Counter(host).values())


def extract_host_features(host):
    n = len(host)
    digit_count = sum(c in DIGITS for c in host)
    labels = host.split(".")

    return [
        n,
        host.count("."),
        host.count("-"),
        digit_count,
        digit_count / n if n else 0.0,
        max(len(label) for label in labels),
        char_entropy(host),
        1 if (is_ipv4(host) or host.startswith("[")) else 0,
        sum(keyword in host for keyword in SUSPICIOUS_KEYWORDS),
    ]


# ---------- Self-test: run `python host_features.py` ----------
if __name__ == "__main__":
    f = extract_host_features("google.com")
    assert f[:6] == [10, 1, 0, 0, 0.0, 6], f
    assert round(f[6], 4) == 2.6464, f
    assert f[7:] == [0, 0], f

    f = extract_host_features("paypal.com.secure-login.xyz")
    assert f[:4] == [27, 3, 1, 0] and f[5] == 12 and f[8] == 2, f

    f = extract_host_features("192.168.0.1")
    assert f[0] == 11 and f[3] == 8 and f[7] == 1, f

    assert tld_of("google.com") == "com"
    assert tld_of("poste-it-verifica.info") == "info"
    assert tld_of("bbc.co.uk") == "uk"
    assert tld_of("192.168.0.1") == "<ip>"
    assert tld_of("[::1]") == "<ip>"
    assert tld_of("localhost") == "localhost"

    print("All feature tests passed")