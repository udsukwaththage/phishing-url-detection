import re
import math
import json
import joblib
import numpy as np
import pandas as pd
from datetime import datetime
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from urllib.parse import urlparse, parse_qs
from collections import Counter
from typing import Dict, List, Any

app = FastAPI(title="Phishing URL Detection API")
scan_history: List[Dict] = []

# ── Load config — single source of truth for all feature orders ─────────────
with open('config.json') as f:
    config = json.load(f)

FEATURE_NAMES       = config['feature_names']        # exact model input order
BINARY_FEATURES     = config['binary_features']
CONTINUOUS_FEATURES = config['continuous_features']  # exact scaler order
THRESHOLD           = config['threshold']            # 0.5491 from training

# ── Load model and scaler ────────────────────────────────────────────────────
model = None
scaler = None

try:
    import xgboost as xgb
    import os
    print(f"Current directory: {os.getcwd()}")
    print(f"Files: {os.listdir('.')}")
    
    # Use XGBoost.json for better compatibility
    print("Loading XGBoost.json...")
    model = xgb.XGBClassifier()
    model.load_model('XGBoost.json')
    print(f"Model loaded: {type(model)}")
    
    print("Loading robust_scaler.pkl...")
    scaler = joblib.load('robust_scaler.pkl')
    print(f"Scaler loaded: {type(scaler)}, has feature_names: {hasattr(scaler, 'feature_names_in_')}")
    
    if scaler is not None and hasattr(scaler, 'feature_names_in_'):
        print(f"Scaler features: {list(scaler.feature_names_in_)}")
    
    print("✓ Model and scaler loaded")
except Exception as e:
    import traceback
    print(f"✗ Error loading models: {e}")
    traceback.print_exc()

# ── Constants ────────────────────────────────────────────────────────────────
KNOWN_LEGIT_DOMAINS = {
    'google.com', 'google.co.uk', 'google.com.au', 'google.ca',
    'bing.com', 'yahoo.com', 'duckduckgo.com', 'baidu.com',
    'github.com', 'gitlab.com', 'stackoverflow.com', 'stackexchange.com',
    'reddit.com', 'medium.com', 'dev.to', 'npmjs.com', 'pypi.org',
    'readthedocs.io', 'docs.python.org', 'mozilla.org',
    'bbc.co.uk', 'bbc.com', 'cnn.com', 'nytimes.com', 'theguardian.com',
    'reuters.com', 'apnews.com', 'washingtonpost.com', 'forbes.com',
    'amazon.com', 'amazon.co.uk', 'ebay.com', 'etsy.com', 'shopify.com',
    'paypal.com', 'stripe.com', 'apple.com', 'microsoft.com',
    'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'linkedin.com', 'youtube.com', 'tiktok.com', 'pinterest.com',
    'aws.amazon.com', 'azure.microsoft.com', 'cloud.google.com',
    'cloudflare.com', 'digitalocean.com', 'heroku.com',
    'wikipedia.org', 'wikimedia.org', 'archive.org',
    'gov.uk', 'usa.gov', 'whitehouse.gov', 'europa.eu',
    'example.com', 'w3schools.com', 'coursera.org', 'udemy.com',
    'netflix.com', 'spotify.com', 'dropbox.com', 'box.com',
}
LEGIT_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'co', 'io', 'uk', 'de',
    'fr', 'jp', 'au', 'ca', 'mil', 'int', 'eu', 'us', 'info'
}
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'online', 'site', 'website', 'space',
    'fun', 'live', 'click', 'link', 'download', 'win', 'bid',
    'trade', 'gq', 'ml', 'cf', 'tk', 'ga', 'men', 'loan'
}
PHISHING_KEYWORDS = [
    'verify', 'signin', 'banking', 'payment', 'wallet',
    'password', 'recovery', 'helpdesk', 'refund',
    'prize', 'winner', 'claim', 'crypto', 'bitcoin',
    'webscr', 'ebayisapi', 'cmd=_login', 'dispatch',
]
BRAND_NAMES = [
    'paypal', 'ebay', 'amazon', 'google', 'microsoft',
    'apple', 'facebook', 'instagram', 'netflix', 'bankofamerica',
    'wellsfargo', 'chase', 'citibank',
]
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'buff.ly', 'adf.ly', 'short.link', 'tiny.cc', 'is.gd'
}


# ── Feature extraction (identical to training) ───────────────────────────────
def shannon_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())

def is_ip_address(host):
    ipv4 = re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host)
    ipv6 = re.match(r'^\[?[0-9a-fA-F:]+\]?$', host)
    return int(bool(ipv4 or ipv6))

def count_subdomains(host):
    parts = host.split('.')
    return max(0, len(parts) - 2)

def brand_used_suspiciously(url_lower, domain):
    for brand in BRAND_NAMES:
        if brand not in url_lower:
            continue
        if domain.startswith(brand + '.'):
            return 0
        return 1
    return 0

def add_www(url: str) -> str:
    """Add www. if missing — model was trained mostly on www. URLs."""
    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
        host = parsed.hostname or ''
        # Only add www if truly no subdomain at all
        if host and '.' in host and not host.startswith('www.'):
            parts = host.split('.')
            # Don't add www to IPs or already-subdomained hosts
            if len(parts) == 2 and not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', host):
                scheme = parsed.scheme or 'http'
                new_host = f'www.{host}'
                reconstructed = f"{scheme}://{new_host}"
                if parsed.port:
                    reconstructed += f":{parsed.port}"
                if parsed.path:
                    reconstructed += parsed.path
                if parsed.query:
                    reconstructed += f"?{parsed.query}"
                return reconstructed
    except Exception:
        pass
    return url

def extract_features(url: str) -> Dict[str, Any]:
    url = str(url).strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url):
        url_to_parse = 'http://' + url
    else:
        url_to_parse = url

    try:
        parsed   = urlparse(url_to_parse)
        scheme   = parsed.scheme.lower()
        host     = parsed.hostname or ''
        port     = parsed.port
        path     = parsed.path or ''
        query    = parsed.query or ''
    except Exception:
        scheme = host = path = query = ''
        port = None

    eps        = 1e-9
    url_lower  = url.lower()
    url_length = len(url)

    n_digits      = sum(c.isdigit() for c in url)
    n_letters     = sum(c.isalpha() for c in url)
    n_dots        = url.count('.')
    n_hyphens     = url.count('-')
    n_underscores = url.count('_')
    n_slashes     = path.count('/')
    n_equals      = url.count('=')
    n_qmarks      = url.count('?')
    n_amps        = url.count('&')
    n_at          = url.count('@')
    n_percent     = url.count('%')

    host_parts = host.split('.')
    tld    = host_parts[-1].lower() if host_parts else ''
    domain = '.'.join(host_parts[-2:]) if len(host_parts) >= 2 else host

    try:
        params       = parse_qs(query)
        n_params     = len(params)
        param_values = [str(v[0]) for v in params.values()]
    except Exception:
        n_params     = 0
        param_values = []

    is_https         = int(scheme == 'https')
    is_http          = int(scheme == 'http')
    has_non_std_port = int(port is not None and port not in (80, 443, 8080, 8443))

    domain_length       = len(domain)
    host_length         = len(host)
    n_subdomains        = count_subdomains(host)
    is_ip               = is_ip_address(host)
    domain_entropy      = shannon_entropy(domain)
    host_entropy        = shannon_entropy(host)
    n_dots_in_host      = host.count('.')
    n_hyphens_in_domain = domain.count('-')
    domain_digit_ratio  = sum(c.isdigit() for c in domain) / (domain_length + eps)
    is_shortener        = int(any(s in host for s in URL_SHORTENERS))
    has_dash_in_domain  = int('-' in (domain.split('.')[0] if '.' in domain else domain))
    multiple_subdomains = int(n_subdomains >= 3)

    tld_length        = len(tld)
    is_legit_tld      = int(tld in LEGIT_TLDS)
    is_suspicious_tld = int(tld in SUSPICIOUS_TLDS)

    path_length   = len(path)
    n_path_dirs   = max(0, path.count('/') - 1)
    path_entropy  = shannon_entropy(path)
    n_path_digits = sum(c.isdigit() for c in path)
    path_has_exe  = int(bool(re.search(r'\.(exe|bat|sh|cmd|msi|vbs|ps1)$', path.lower())))
    path_has_form = int(any(kw in path.lower() for kw in ('signin', 'verify')))

    query_length      = len(query)
    n_query_params    = n_params
    query_entropy     = shannon_entropy(query)
    avg_param_val_len = float(np.mean([len(v) for v in param_values])) if param_values else 0.0

    has_at_symbol    = int(n_at > 0)
    has_double_slash = int(path.count('//') > 0)
    has_hex_chars    = int(bool(re.search(r'%[0-9a-fA-F]{2}', url)))
    hex_char_count   = len(re.findall(r'%[0-9a-fA-F]{2}', url))
    has_punycode     = int('xn--' in host.lower())

    n_phishing_keywords  = sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)
    has_phishing_keyword = int(n_phishing_keywords > 0)
    has_brand_name       = brand_used_suspiciously(url_lower, domain)

    digit_ratio        = n_digits  / (url_length + eps)
    letter_ratio       = n_letters / (url_length + eps)
    special_char_ratio = (n_dots + n_hyphens + n_underscores +
                          n_equals + n_qmarks + n_amps + n_at + n_percent) / (url_length + eps)
    url_entropy        = shannon_entropy(url)
    domain_url_ratio   = domain_length / (url_length + eps)
    path_url_ratio     = path_length   / (url_length + eps)
    slash_path_ratio   = n_slashes / (url_length + eps)

    is_known_legit_domain = int(
        domain in KNOWN_LEGIT_DOMAINS or
        host in KNOWN_LEGIT_DOMAINS or
        any(host.endswith('.' + d) for d in KNOWN_LEGIT_DOMAINS)
    )

    return {
        'url_length': url_length, 'url_entropy': round(url_entropy, 4),
        'digit_ratio': round(digit_ratio, 4), 'letter_ratio': round(letter_ratio, 4),
        'special_char_ratio': round(special_char_ratio, 4), 'n_dots': n_dots,
        'n_hyphens': n_hyphens, 'n_underscores': n_underscores,
        'slash_path_ratio': round(slash_path_ratio, 6), 'n_equals': n_equals,
        'n_qmarks': n_qmarks, 'n_amps': n_amps, 'n_at': n_at, 'n_percent': n_percent,
        'n_digits': n_digits, 'n_letters': n_letters, 'is_https': is_https,
        'is_http': is_http, 'has_non_std_port': has_non_std_port,
        'domain_length': domain_length, 'host_length': host_length,
        'n_subdomains': n_subdomains, 'is_ip': is_ip,
        'domain_entropy': round(domain_entropy, 4), 'host_entropy': round(host_entropy, 4),
        'n_dots_in_host': n_dots_in_host, 'n_hyphens_in_domain': n_hyphens_in_domain,
        'domain_digit_ratio': round(domain_digit_ratio, 4), 'is_shortener': is_shortener,
        'has_dash_in_domain': has_dash_in_domain, 'multiple_subdomains': multiple_subdomains,
        'tld_length': tld_length, 'is_legit_tld': is_legit_tld,
        'is_suspicious_tld': is_suspicious_tld, 'path_length': path_length,
        'n_path_dirs': n_path_dirs, 'path_entropy': round(path_entropy, 4),
        'n_path_digits': n_path_digits, 'path_has_exe': path_has_exe,
        'path_has_form': path_has_form, 'path_url_ratio': round(path_url_ratio, 4),
        'query_length': query_length, 'n_query_params': n_query_params,
        'query_entropy': round(query_entropy, 4),
        'avg_param_val_len': round(avg_param_val_len, 4),
        'has_at_symbol': has_at_symbol, 'has_double_slash': has_double_slash,
        'has_hex_chars': has_hex_chars, 'hex_char_count': hex_char_count,
        'has_punycode': has_punycode, 'n_phishing_keywords': n_phishing_keywords,
        'has_phishing_keyword': has_phishing_keyword, 'has_brand_name': has_brand_name,
        'domain_url_ratio': round(domain_url_ratio, 4),
        'is_known_legit_domain': is_known_legit_domain,
    }


# ── Feature preparation — guaranteed correct order ───────────────────────────
def prepare_features(features: Dict[str, Any]) -> pd.DataFrame:
    df = pd.DataFrame([features])

    # Verify nothing is missing
    missing = [f for f in FEATURE_NAMES if f not in df.columns]
    if missing:
        raise ValueError(f"Missing features from extractor: {missing}")

    # Scale continuous features in exact scaler order
    df[CONTINUOUS_FEATURES] = scaler.transform(df[CONTINUOUS_FEATURES])

    # Return in exact FEATURE_NAMES order — this is what the model sees
    return df[FEATURE_NAMES]


# ── Startup verification ─────────────────────────────────────────────────────
@app.on_event("startup")
def verify_setup():
    if scaler is None:
        print("⚠ Warning: Scaler not loaded, skipping verification")
        return
    scaler_feats = list(scaler.feature_names_in_)
    if scaler_feats != CONTINUOUS_FEATURES:
        print(f"⚠ Warning: Scaler feature order mismatch!")
        print(f"  config.json: {CONTINUOUS_FEATURES}")
        print(f"  scaler:      {scaler_feats}")
    else:
        print(f"✓ Feature order verified ({len(FEATURE_NAMES)} features)")
    print(f"✓ Threshold: {THRESHOLD}")


# ── Request/Response models ──────────────────────────────────────────────────
class URLRequest(BaseModel):
    url: str


# ── Endpoints ────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "message": "Phishing URL Detection API",
        "status": "running",
        "model": config['best_model'],
        "threshold": THRESHOLD,
        "metrics": config['test_metrics']
    }


@app.post("/predict")
def predict_phishing(request: URLRequest):
    if model is None:
        raise HTTPException(status_code=500, detail="Model not loaded")
    if scaler is None:
        raise HTTPException(status_code=500, detail="Scaler not loaded")

    start_time   = datetime.now()
    original_url = request.url
    processed_url = add_www(original_url)

    features    = extract_features(processed_url)
    features_df = prepare_features(features)

    phishing_prob = float(model.predict_proba(features_df)[0][1])
    phishing_rate = round(phishing_prob * 100, 2)
    is_phishing   = phishing_prob >= THRESHOLD

    scan_time = (datetime.now() - start_time).total_seconds()

    result = {
        "original_url":  original_url,
        "scanned_url":   processed_url,
        "is_phishing":   is_phishing,
        "phishing_rate": phishing_rate,
        "threshold":     round(THRESHOLD * 100, 2),
        "scan_time":     round(scan_time, 4),
        "timestamp":     datetime.now().isoformat(),
    }
    scan_history.append(result)
    return result


@app.post("/features")
def get_features(request: URLRequest):
    original_url  = request.url
    processed_url = add_www(original_url)
    features      = extract_features(processed_url)
    return {
        "original_url":  original_url,
        "processed_url": processed_url,
        "features":      features,
    }


@app.get("/history")
def get_history(limit: int = 10):
    return {
        "total_scans": len(scan_history),
        "scans": scan_history[-limit:]
    }


@app.delete("/history")
def clear_history():
    scan_history.clear()
    return {"message": "History cleared"}


@app.delete("/history/delete")
def delete_url(url: str = Query(...)):
    global scan_history
    original_count = len(scan_history)
    scan_history = [s for s in scan_history if s.get("original_url") != url]
    deleted_count = original_count - len(scan_history)
    if deleted_count == 0:
        raise HTTPException(status_code=404, detail="URL not found in history")
    return {"message": f"Deleted {deleted_count} record(s)", "url": url}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)