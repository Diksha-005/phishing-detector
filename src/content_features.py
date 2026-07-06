import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


def extract_content_features(url):
    features = {}

    feature_names = [
        'nb_redirection', 'nb_external_redirection', 'statistical_report',
        'nb_hyperlinks', 'ratio_intHyperlinks', 'ratio_extHyperlinks',
        'ratio_nullHyperlinks', 'nb_extCSS', 'ratio_intRedirection',
        'ratio_extRedirection', 'ratio_intErrors', 'ratio_extErrors',
        'login_form', 'external_favicon', 'links_in_tags', 'submit_email',
        'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe', 'popup_window',
        'safe_anchor', 'onmouseover', 'right_clic', 'empty_title',
        'domain_in_title', 'domain_with_copyright'
    ]

    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')

        base_domain = urlparse(url).netloc.replace('www.', '')
        domain_name = base_domain.split('.')[0] if base_domain else ''

        # ── Redirection features ────────────────────────────
        # number of redirects that happened to reach final page
        features['nb_redirection'] = len(response.history)
        # how many of those redirects went to a DIFFERENT domain
        ext_redirects = sum(1 for r in response.history
                             if urlparse(r.url).netloc.replace('www.', '') != base_domain)
        features['nb_external_redirection'] = ext_redirects

        # ── Statistical report (basic heuristic: suspicious keywords in page) ─
        suspicious_terms = ['phish', 'malware', 'scam', 'fraud']
        features['statistical_report'] = 1 if any(t in html.lower() for t in suspicious_terms) else 0

        # ── Hyperlink analysis ───────────────────────────────
        all_links = soup.find_all('a', href=True)
        total_links = len(all_links)
        features['nb_hyperlinks'] = total_links

        internal_links, external_links, null_links = 0, 0, 0
        for link in all_links:
            href = link['href'].strip()
            if href in ['#', '', 'javascript:void(0)'] or href.startswith('#'):
                null_links += 1
            elif href.startswith('http'):
                link_domain = urlparse(href).netloc.replace('www.', '')
                if link_domain == base_domain:
                    internal_links += 1
                else:
                    external_links += 1
            else:
                internal_links += 1  # relative links are internal

        if total_links > 0:
            features['ratio_intHyperlinks'] = round(internal_links / total_links, 3)
            features['ratio_extHyperlinks'] = round(external_links / total_links, 3)
            features['ratio_nullHyperlinks'] = round(null_links / total_links, 3)
        else:
            features['ratio_intHyperlinks'] = 0
            features['ratio_extHyperlinks'] = 0
            features['ratio_nullHyperlinks'] = 0

        # ── External CSS files ───────────────────────────────
        css_links = soup.find_all('link', rel='stylesheet', href=True)
        ext_css = sum(1 for c in css_links if c['href'].startswith('http')
                       and base_domain not in c['href'])
        features['nb_extCSS'] = ext_css

        # ── Internal/external redirection & error ratios (within links) ─
        # approximated using internal/external link ratios as proxy
        features['ratio_intRedirection'] = features['ratio_intHyperlinks']
        features['ratio_extRedirection'] = features['ratio_extHyperlinks']
        features['ratio_intErrors'] = 0  # would need to actually visit each link; default safe value
        features['ratio_extErrors'] = 0

        # ── Login form detection ─────────────────────────────
        password_inputs = soup.find_all('input', {'type': 'password'})
        features['login_form'] = 1 if len(password_inputs) > 0 else 0

        # ── External favicon ─────────────────────────────────
        favicon = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
        if favicon and favicon.get('href'):
            favicon_url = favicon['href']
            if favicon_url.startswith('http') and base_domain not in favicon_url:
                features['external_favicon'] = 1
            else:
                features['external_favicon'] = 0
        else:
            features['external_favicon'] = 0

        # ── Links inside <script>, <link>, <meta> tags pointing externally ─
        tag_links = soup.find_all(['script', 'link', 'meta'])
        ext_tag_links = 0
        total_tag_links = 0
        for tag in tag_links:
            src = tag.get('src') or tag.get('href') or tag.get('content')
            if src and src.startswith('http'):
                total_tag_links += 1
                if base_domain not in src:
                    ext_tag_links += 1
        features['links_in_tags'] = round(ext_tag_links / total_tag_links, 3) if total_tag_links > 0 else 0

        # ── Forms that submit via email (mailto:) ────────────
        forms = soup.find_all('form')
        submit_email = any('mailto:' in (f.get('action') or '') for f in forms)
        features['submit_email'] = 1 if submit_email else 0

        # ── Media ratio (images/video/audio internal vs external) ─
        media_tags = soup.find_all(['img', 'video', 'audio'])
        total_media = len(media_tags)
        int_media, ext_media = 0, 0
        for m in media_tags:
            src = m.get('src', '')
            if src.startswith('http'):
                if base_domain in src:
                    int_media += 1
                else:
                    ext_media += 1
            else:
                int_media += 1
        features['ratio_intMedia'] = round(int_media / total_media, 3) if total_media > 0 else 0
        features['ratio_extMedia'] = round(ext_media / total_media, 3) if total_media > 0 else 0

        # ── SFH (Server Form Handler) — form action pointing elsewhere/blank ─
        sfh_suspicious = 0
        for f in forms:
            action = f.get('action', '')
            if action == '' or action == 'about:blank':
                sfh_suspicious = 1
            elif action.startswith('http') and base_domain not in action:
                sfh_suspicious = 1
        features['sfh'] = sfh_suspicious

        # ── Iframe usage ──────────────────────────────────────
        features['iframe'] = len(soup.find_all('iframe'))

        # ── Popup window detection (window.open in scripts) ──
        scripts_text = ' '.join([s.get_text() for s in soup.find_all('script')])
        features['popup_window'] = 1 if 'window.open' in scripts_text else 0

        # ── Safe anchor ratio (links with valid, non-empty href) ─
        safe_anchors = sum(1 for link in all_links if link['href'].strip() not in ['#', '', 'javascript:void(0)'])
        features['safe_anchor'] = round(safe_anchors / total_links, 3) if total_links > 0 else 0

        # ── onmouseover event (used to fake status bar URLs) ─
        features['onmouseover'] = 1 if 'onmouseover' in html.lower() else 0

        # ── Right-click disabled (common phishing trick) ────
        features['right_clic'] = 1 if 'event.button==2' in html.lower() or 'contextmenu' in html.lower() else 0

        # ── Empty title ───────────────────────────────────────
        title_tag = soup.find('title')
        title_text = title_tag.text.strip() if title_tag else ''
        features['empty_title'] = 1 if len(title_text) == 0 else 0

        # ── Domain name appears in title ─────────────────────
        features['domain_in_title'] = 1 if domain_name.lower() in title_text.lower() else 0

        # ── Copyright mention with domain name ───────────────
        copyright_terms = ['©', 'copyright', 'all rights reserved']
        has_copyright = any(term in html.lower() for term in copyright_terms)
        features['domain_with_copyright'] = 1 if has_copyright and domain_name.lower() in html.lower() else 0

    except Exception as e:
        print(f"  Could not fetch page: {e}")
        for name in feature_names:
            features[name] = -1

    return features


# ---- TEST ----
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "https://www.github.com"
    ]

    for url in test_urls:
        print(f"\nURL: {url}")
        features = extract_content_features(url)
        for key, value in features.items():
            print(f"   {key}: {value}")
        print(f"   TOTAL FEATURES: {len(features)}")