import socket
import whois
from datetime import datetime
from tranco import Tranco
import tldextract
from datetime import timezone


# Load Tranco list once (cached) — reused across all predictions
_tranco_client = Tranco(cache=True, cache_dir='.tranco')
_tranco_list = _tranco_client.list()


def extract_domain_features(url):
    features = {}

    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"

    # ── DNS record check ─────────────────────────────────────
    try:
        socket.gethostbyname(domain)
        features['dns_record'] = 1
    except Exception:
        features['dns_record'] = 0

    # ── Web traffic (Tranco rank) ────────────────────────────
    try:
        features['web_traffic'] = _tranco_list.rank(domain)
    except Exception:
        features['web_traffic'] = -1

    # ── WHOIS lookup (registration info + domain age) ───────
    try:
        w = whois.whois(domain)
        # print(f"DEBUG - domain_name: {w.domain_name}")
        # print(f"DEBUG - creation_date: {w.creation_date}")
        # print(f"DEBUG - creation_date: {w.creation_date}")
        
        # whois_registered_domain: 1 if WHOIS data exists
        features['whois_registered_domain'] = 1 if w.domain_name else 0
        # print(f"DEBUG - whois_registered_domain set to: {features['whois_registered_domain']}")

        # Handle creation_date (can be a list or single value depending on registrar)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        # print(f"DEBUG - creation_date after list-check: {creation_date}")

        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        # print(f"DEBUG - expiration_date after list-check: {expiration_date}")


        # Fix timezone issue — make datetime.now() timezone-aware
        now = datetime.now(tz=timezone.utc)

        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            features['domain_age'] = (now - creation_date).days
            # print(f"DEBUG - domain_age calculated: {domain_age_days}")
        else:
            features['domain_age'] = -1


        if creation_date and expiration_date:
            # make expiration_date timezone-aware if it isn't already
            if expiration_date.tzinfo is None:
                expiration_date = expiration_date.replace(tzinfo=timezone.utc)
            features['domain_registration_length'] = (expiration_date - creation_date).days
        else:
            features['domain_registration_length'] = -1

    except Exception as e:
        # print(f"DEBUG - WHOIS error: {e}")
        features['whois_registered_domain'] = 0
        features['domain_age'] = -1
        features['domain_registration_length'] = -1

    return features


# ---- TEST ----
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "https://www.github.com",
        "http://totally-fake-nonexistent-site12345.com"
    ]

    for url in test_urls:
        print(f"\nURL: {url}")
        features = extract_domain_features(url)
        for key, value in features.items():
            print(f"   {key}: {value}")
        print(f"   TOTAL FEATURES: {len(features)}")