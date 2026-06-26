import re
import tldextract

def extract_url_features(url):
    """
    This function takes a URL and pulls out important features
    that help us detect if it is phishing or not.
    """

    features = {}

    # 1. Length of the URL (phishing URLs are usually very long)
    features['url_length'] = len(url)

    # 2. Count how many dots are in the URL
    features['num_dots'] = url.count('.')

    # 3. Count how many hyphens (phishing sites use many hyphens)
    features['num_hyphens'] = url.count('-')

    # 4. Check if there is an @ symbol (used to trick browsers)
    features['has_at_symbol'] = 1 if '@' in url else 0

    # 5. Check if URL uses HTTPS (secure) or HTTP (not secure)
    features['has_https'] = 1 if url.startswith('https') else 0

    # 6. Check if an IP address is used instead of a domain name
    # Example: http://192.168.1.1/login  <-- suspicious!
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    features['has_ip_address'] = 1 if re.search(ip_pattern, url) else 0

    # 7. Count how many subdomains the URL has
    # Example: login.secure.paypal.attackersite.com has many subdomains
    extracted = tldextract.extract(url)
    subdomains = extracted.subdomain.split('.') if extracted.subdomain else []
    features['num_subdomains'] = len(subdomains)

    # 8. Length of just the domain name
    features['domain_length'] = len(extracted.domain)

    # 9. Check if URL has double slash // somewhere unusual
    features['has_double_slash'] = 1 if '//' in url[7:] else 0

    # 10. Count total number of special characters
    special_chars = ['@', '?', '=', '&', '!', '#', '%']
    features['num_special_chars'] = sum(url.count(c) for c in special_chars)

    # 11. Count number of digits in the URL
    features['num_digits'] = sum(c.isdigit() for c in url)

    # 12. Check if common brand names are misused in URL
    # Phishing sites often use "paypal-secure.xyz" or "amazon-login.com"
    brand_keywords = ['paypal', 'amazon', 'google', 'facebook', 'bank', 'secure', 'login', 'verify']
    features['has_brand_keyword'] = 1 if any(word in url.lower() for word in brand_keywords) else 0

    return features


# ---- TEST: Run this file directly to see if it works ----
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://paypal-secure-login.xyz/verify?user=abc@gmail.com",
        "http://192.168.1.1/bank/login"
    ]

    for url in test_urls:
        print(f"\nURL: {url}")
        print("Features extracted:")
        features = extract_url_features(url)
        for key, value in features.items():
            print(f"   {key}: {value}")