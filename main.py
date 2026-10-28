from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
import joblib
import pandas as pd
import urllib.parse
import re
from tranco import Tranco

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000", 
        "http://127.0.0.1:3000",
        "https://realornot-project.netlify.app" 
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

print("Loading AI Brain...")
model = joblib.load('phishing_model.joblib')
expected_features = list(model.feature_names_in_)

# Tier 1: Verified Authority Suffixes & Tranco Dynamic Database
TRUSTED_TLDS = ('.gov', '.gov.in', '.edu', '.ac.in', '.edu.in', '.nic.in')
TRUSTED_DOMAINS = set()

print("Fetching Tranco Top 100,000 global domains...")
try:
    # cache=True creates a hidden folder so it only downloads the list once per day, 
    # making your server startup fast after the first download.
    t = Tranco(cache=True, cache_dir='.tranco_cache')
    latest_list = t.list()
    
    # Load top 100,000 domains into a set for O(1) lookups
    TRUSTED_DOMAINS = set(latest_list.top(100000))
    print(f"Success: Loaded {len(TRUSTED_DOMAINS)} top domains into memory.")
except Exception as e:
    print(f"Warning: Could not load Tranco list. Error: {e}")

class ScanRequest(BaseModel):
    url: str

def is_whitelisted(domain: str) -> bool:
    """Checks if a domain belongs to verified authority registries or the Global Top 100k."""
    domain = domain.lower()
    
    # 1. Check official academic/government TLDs
    if any(domain.endswith(tld) for tld in TRUSTED_TLDS):
        return True
        
    # 2. Extract the root domain (turns "www.instagram.com" into "instagram.com")
    parts = domain.split('.')
    root_domain = domain
    if len(parts) >= 2:
        # Ignore regional subdomains like .co.uk or .ac.in for the extraction
        if parts[-2] in ['co', 'ac', 'com', 'org'] and len(parts) >= 3:
            root_domain = f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
        else:
            root_domain = f"{parts[-2]}.{parts[-1]}"
            
    # 3. Check if the exact domain or the root domain is in the top 100,000
    if domain in TRUSTED_DOMAINS or root_domain in TRUSTED_DOMAINS:
        return True
        
    return False

def extract_features(url_string: str) -> pd.DataFrame:
    """Translates a text URL into numerical features matching the trained model."""
    if not url_string.startswith('http'):
        url_string = 'http://' + url_string
        
    parsed = urllib.parse.urlparse(url_string)
    domain = parsed.hostname or parsed.netloc or ""
    path = parsed.path or ""
    query = parsed.query or ""
    
    features = {feature: 0 for feature in expected_features}
    
    # Structural lengths & counts
    if 'is_syntax_valid' in features: features['is_syntax_valid'] = 1
    if 'url_length' in features: features['url_length'] = len(url_string)
    if 'url_len' in features: features['url_len'] = len(url_string)
    if 'domain_len' in features: features['domain_len'] = len(domain)
    if 'path_len' in features: features['path_len'] = len(path)
    if 'query_len' in features: features['query_len'] = len(query)
    if 'path_depth' in features: features['path_depth'] = path.count('/')
    
    # Character counts
    if 'digit_count_v2' in features: features['digit_count_v2'] = sum(c.isdigit() for c in url_string)
    if 'letter_count_v2' in features: features['letter_count_v2'] = sum(c.isalpha() for c in url_string)
    if 'count_dots' in features: features['count_dots'] = url_string.count('.')
    if 'count_hyphens' in features: features['count_hyphens'] = url_string.count('-')
    if 'count_at' in features: features['count_at'] = url_string.count('@')
    
    # Binary flags
    if 'is_https' in features: features['is_https'] = 1 if parsed.scheme == 'https' else 0
    if 'has_punycode' in features: features['has_punycode'] = 1 if 'xn--' in domain else 0
    if 'is_ip_host' in features: features['is_ip_host'] = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain) else 0
    
    if 'subdomain_count' in features:
        parts = domain.split('.')
        features['subdomain_count'] = len(parts) - 2 if len(parts) > 2 else 0
        
    return pd.DataFrame([features], columns=expected_features)

@app.post("/api/scan")
async def scan_url(req: ScanRequest):
    raw_url = req.url.strip()
    url = raw_url.lower()
    
    if not url.startswith('http'):
        url = 'http://' + url
        
    parsed = urllib.parse.urlparse(url)
    domain = parsed.hostname or parsed.netloc or ""

    # -------------------------------------------------------------
    # TIER 1: Domain Reputation & Authority Check
    # -------------------------------------------------------------
    if is_whitelisted(domain):
        return {
            "score": 0,
            "label": "LOOKS REAL",
            "title": "Verified Authority Domain",
            "desc": "This domain belongs to an official academic, governmental, or verified trusted infrastructure.",
            "flags": [],
            "goods": [
                "Matches verified academic/government domain registry.",
                "Uses trusted root authority infrastructure."
            ],
            "color": "safe"
        }

    # -------------------------------------------------------------
    # TIER 2: Machine Learning Heuristic Inspection (Random Forest)
    # -------------------------------------------------------------
    features_df = extract_features(url)
    probabilities = model.predict_proba(features_df)[0]
    malicious_prob = probabilities[1] * 100
    
    flags = []
    goods = []
    
    if features_df.get('is_https', pd.Series([1])).iloc[0] == 0:
        flags.append("No HTTPS encryption detected.")
    else:
        goods.append("Uses secure HTTPS encryption.")
        
    if features_df.get('has_punycode', pd.Series([0])).iloc[0] == 1:
        flags.append("Uses Punycode (xn--) to hide lookalike characters.")
        
    if features_df.get('is_ip_host', pd.Series([0])).iloc[0] == 1:
        flags.append("Domain is a raw IP address instead of a standard name.")

    if '@' in url:
        flags.append("Contains '@' symbol (often used to obscure the destination host).")

    if malicious_prob >= 70:
        color = "fake"
        label = "LIKELY FAKE"
        title = "AI detected malicious patterns"
    elif malicious_prob >= 40:
        color = "suspicious"
        label = "SUSPICIOUS"
        title = "Proceed with caution"
    else:
        color = "safe"
        label = "LOOKS REAL"
        title = "AI assessed as safe"
        
    desc = f"Our Random Forest model is {max(malicious_prob, 100 - malicious_prob):.1f}% confident in this verdict."
        
    return {
        "score": int(malicious_prob),
        "label": label,
        "title": title,
        "desc": desc,
        "flags": flags,
        "goods": goods,
        "color": color
    }
