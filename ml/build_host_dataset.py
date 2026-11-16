import re
import pandas as pd

SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://")


def extract_host(url):
    """Turn any URL-like string into a normalized hostname.

    Every rule here must be copied exactly in Swift later.
    """
    s = str(url).strip().lower()

    # 1. Remove the scheme (https://, http://, ...) if present
    s = SCHEME_RE.sub("", s, count=1)

    # 2. Browsers treat "\" like "/", so we do too
    s = s.replace("\\", "/")

    # 3. Keep only the part before the first / ? #
    for separator in "/?#":
        s = s.split(separator, 1)[0]

    # 4. Remove "user:password@" (the real host is after the LAST @)
    if "@" in s:
        s = s.rsplit("@", 1)[1]

    # 5. Remove the port (":8080"), but keep IPv6 literals like [::1]
    if s.startswith("["):
        s = s.split("]", 1)[0] + "]"
    else:
        s = s.split(":", 1)[0]

    # 6. Remove trailing dot and a leading "www."
    s = s.rstrip(".")
    if s.startswith("www."):
        s = s[4:]

    return s


# ---------- Unit tests for extract_host ----------
TESTS = {
    "https://www.Google.com/search?q=1": "google.com",
    "http://user:pw@evil.com:8080/x": "evil.com",
    "paypal.com.secure-login.xyz/verify": "paypal.com.secure-login.xyz",
    "HTTP://WWW.Example.COM./": "example.com",
    "http://[::1]:80/": "[::1]",
    "https://evil.com\\@google.com": "evil.com",
    "192.168.0.1/login": "192.168.0.1",
    "bit.ly/3xYz": "bit.ly",
}
for raw, expected in TESTS.items():
    got = extract_host(raw)
    status = "OK  " if got == expected else "FAIL"
    print(f"{status} {raw!r} -> {got!r} (expected {expected!r})")


# ---------- Build the dataset ----------
df = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv", usecols=["URL", "label"])
df["host"] = df["URL"].map(extract_host)
df = df[df["host"] != ""]

per_host = df.groupby("host")["label"].agg(["nunique", "first", "size"])
conflicts = per_host[per_host["nunique"] > 1]

hosts = (
    per_host[per_host["nunique"] == 1]
    .reset_index()
    .rename(columns={"first": "label", "size": "url_count"})
    [["host", "label", "url_count"]]
)
hosts.to_csv("hosts.csv", index=False)

print("\nURLs in dataset:      ", len(df))
print("Unique hosts:         ", len(per_host))
print("Conflicting hosts:    ", len(conflicts), "(removed)")
print(conflicts.head(10))

print("\nHosts per label (1 = legitimate, 0 = phishing):")
print(hosts["label"].value_counts())

print("\nTop 20 phishing hosts by number of URLs:")
print(hosts[hosts.label == 0].nlargest(20, "url_count").to_string(index=False))

print("\nNumber of dots in host, share per label:")
dots = hosts["host"].str.count(r"\.").clip(upper=4)
print(pd.crosstab(dots, hosts["label"], normalize="columns").round(3))
