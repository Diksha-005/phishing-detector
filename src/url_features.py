import re
import tldextract
from urllib.parse import urlparse

# Common brand names phishing sites often impersonate
BRANDS = ['paypal', 'amazon', 'google', 'facebook', 'apple', 'microsoft',
          'bank', 'netflix', 'instagram', 'whatsapp', 'ebay', 'linkedin']

# Suspicious/free TLDs commonly abused by phishing sites
SUSPICIOUS_TLDS = ['zip', 'cricket', 'link', 'work', 'party', 'gq', 'kim',
                    'country', 'science', 'tk', 'xyz', 'top', 'club']

# Common URL shortening services
SHORTENING_SERVICES = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'ow.ly',
                        'is.gd', 'buff.ly', 'adf.ly']


def extract_url_features(url):
    features = {}

    parsed = urlparse(url)
    extracted = tldextract.extract(url)
    hostname = parsed.netloc
    domain = extracted.domain
    subdomain = extracted.subdomain
    path = parsed.path

    # ── Basic length features ──────────────────────────────
    features['length_url'] = len(url)
    features['length_hostname'] = len(hostname)

    # ── IP address check ───────────────────────────────────
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    features['ip'] = 1 if re.match(ip_pattern, hostname.split(':')[0]) else 0

    # ── Character counts ───────────────────────────────────
    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_at'] = url.count('@')
    features['nb_qm'] = url.count('?')
    features['nb_and'] = url.count('&')
    features['nb_or'] = url.count('|')
    features['nb_eq'] = url.count('=')
    features['nb_underscore'] = url.count('_')
    features['nb_tilde'] = url.count('~')
    features['nb_percent'] = url.count('%')
    features['nb_slash'] = url.count('/')
    features['nb_star'] = url.count('*')
    features['nb_colon'] = url.count(':')
    features['nb_comma'] = url.count(',')
    features['nb_semicolumn'] = url.count(';')
    features['nb_dollar'] = url.count('$')
    features['nb_space'] = url.count(' ') + url.count('%20')
    features['nb_www'] = url.lower().count('www')
    features['nb_com'] = url.lower().count('.com')
    features['nb_dslash'] = url.count('//')

    # ── HTTP/HTTPS related ─────────────────────────────────
    features['http_in_path'] = 1 if 'http' in path.lower() else 0
    features['https_token'] = 1 if parsed.scheme == 'https' else 0

    # ── Digit ratios ────────────────────────────────────────
    digits_in_url = sum(c.isdigit() for c in url)
    features['ratio_digits_url'] = round(digits_in_url / len(url), 3) if len(url) > 0 else 0

    digits_in_host = sum(c.isdigit() for c in hostname)
    features['ratio_digits_host'] = round(digits_in_host / len(hostname), 3) if len(hostname) > 0 else 0

    # ── Punycode (used to fake unicode domains) ────────────
    features['punycode'] = 1 if 'xn--' in url.lower() else 0

    # ── Port number present? ────────────────────────────────
    features['port'] = 1 if ':' in hostname and hostname.split(':')[-1].isdigit() else 0

    # ── TLD location checks ──────────────────────────────────
    tld = extracted.suffix
    features['tld_in_path'] = 1 if tld and tld in path else 0
    features['tld_in_subdomain'] = 1 if tld and tld in subdomain else 0

    # ── Subdomain checks ────────────────────────────────────
    features['abnormal_subdomain'] = 1 if subdomain.count('-') > 0 or subdomain.count('.') > 2 else 0
    subdomain_parts = subdomain.split('.') if subdomain else []
    features['nb_subdomains'] = len(subdomain_parts) + 1  # +1 to count base domain level

    # ── Prefix-suffix (hyphen in domain, e.g. paypal-secure) ─
    features['prefix_suffix'] = 1 if '-' in domain else 0

    # ── Random-looking domain (high consonant ratio, crude heuristic) ─
    vowels = sum(1 for c in domain.lower() if c in 'aeiou')
    features['random_domain'] = 1 if len(domain) > 0 and vowels / len(domain) < 0.2 else 0

    # ── Shortening service check ────────────────────────────
    features['shortening_service'] = 1 if any(s in url.lower() for s in SHORTENING_SERVICES) else 0

    # ── File extension in path ──────────────────────────────
    features['path_extension'] = 1 if re.search(r'\.\w{2,4}$', path) else 0

    # ── Word-based statistics ───────────────────────────────
    # Split URL into "words" by removing special characters
    raw_words = re.split(r'[\/\-\_\.\?\=\&\%]', url)
    raw_words = [w for w in raw_words if w]  # remove empty strings

    host_words = re.split(r'[\-\_\.]', hostname)
    host_words = [w for w in host_words if w]

    path_words = re.split(r'[\/\-\_\.\?\=\&]', path)
    path_words = [w for w in path_words if w]

    word_lengths_raw = [len(w) for w in raw_words] if raw_words else [0]
    word_lengths_host = [len(w) for w in host_words] if host_words else [0]
    word_lengths_path = [len(w) for w in path_words] if path_words else [0]

    features['length_words_raw'] = len(raw_words)
    features['shortest_words_raw'] = min(word_lengths_raw)
    features['shortest_word_host'] = min(word_lengths_host)
    features['shortest_word_path'] = min(word_lengths_path)
    features['longest_words_raw'] = max(word_lengths_raw)
    features['longest_word_host'] = max(word_lengths_host)
    features['longest_word_path'] = max(word_lengths_path)
    features['avg_words_raw'] = round(sum(word_lengths_raw) / len(word_lengths_raw), 2)
    features['avg_word_host'] = round(sum(word_lengths_host) / len(word_lengths_host), 2)
    features['avg_word_path'] = round(sum(word_lengths_path) / len(word_lengths_path), 2) if path_words else 0

    # ── Character repeat (longest run of same character) ───
    max_repeat = 1
    current_repeat = 1
    for i in range(1, len(url)):
        if url[i] == url[i-1]:
            current_repeat += 1
            max_repeat = max(max_repeat, current_repeat)
        else:
            current_repeat = 1
    features['char_repeat'] = max_repeat

    # ── Phishing keyword hints ──────────────────────────────
    phish_keywords = ['login', 'verify', 'secure', 'account', 'update',
                       'confirm', 'banking', 'signin', 'password']
    features['phish_hints'] = sum(1 for kw in phish_keywords if kw in url.lower())

    # ── Brand name checks ───────────────────────────────────
    url_lower = url.lower()
    features['domain_in_brand'] = 1 if any(b in domain.lower() for b in BRANDS) else 0
    features['brand_in_subdomain'] = 1 if any(b in subdomain.lower() for b in BRANDS) else 0
    features['brand_in_path'] = 1 if any(b in path.lower() for b in BRANDS) else 0

    # ── Suspicious TLD ──────────────────────────────────────
    features['suspecious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0

    return features


# ---- TEST ----
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://paypal-secure-login.xyz/verify?user=abc@gmail.com",
        "http://192.168.1.1/bank/login"
    ]

    for url in test_urls:
        print(f"\nURL: {url}")
        features = extract_url_features(url)
        for key, value in features.items():
            print(f"   {key}: {value}")
        print(f"   TOTAL FEATURES: {len(features)}")