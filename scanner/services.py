
from urllib.parse import urlsplit
import ipaddress


SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "update",
    "secure", "password", "bank", "signin"
]

SHORTENER_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "shorturl.at"
]
BRAND_KEYWORDS = [
    "paypal",
    "google",
    "microsoft",
    "amazon",
    "facebook",
    "instagram",
    "apple"
]

def get_risk_level(score):
    if score >= 50:
        return "High"
    elif score >= 15:
        return "Medium"
    return "Low"
def analyze_url(url):



    
    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty")

    if any(char.isspace() for char in url):
        raise ValueError("URL cannot contain spaces")

    if "://" not in url:
        url = "http://" + url

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname or ""

        # Validate URL scheme
        if parsed.scheme not in ["http", "https"]:
            raise ValueError("Only HTTP and HTTPS URLs are supported")

        # Validate hostname
        if not hostname:
            raise ValueError("Invalid URL: hostname is missing")

        # Validate port if provided
        parsed.port

    except ValueError as e:
        raise ValueError(str(e))

    full_url = url.lower()


    score = 0
    reasons = []

    # Check HTTPS
    if parsed.scheme != "https":
        score += 10
        reasons.append("URL does not use HTTPS")

    # Check IP address
    try:
        ipaddress.ip_address(hostname)
        score += 25
        reasons.append("URL uses an IP address instead of a domain")
    except ValueError:
        pass

    # Check suspicious keywords
    found_keywords = [
        word for word in SUSPICIOUS_KEYWORDS
        if word in full_url
    ]

    if found_keywords:
        score += min(len(found_keywords) * 10, 30)
        reasons.append(
            "Suspicious keywords found: " +
            ", ".join(found_keywords)
        )

    # Check URL length
    if len(url) > 75:
        score += 10
        reasons.append("Unusually long URL")

    # Check @ symbol
    if "@" in url:
        score += 15
        reasons.append("URL contains an @ symbol")

    # Check punycode
    if "xn--" in hostname:
        score += 15
        reasons.append("Domain contains punycode")

    score = min(score, 100)

    
    risk = get_risk_level(score)


    
    # Check URL shorteners
    if hostname.lower() in SHORTENER_DOMAINS:
        score += 20
        reasons.append("URL uses a known shortening service")

    # Check multiple hyphens in hostname
    if hostname.count("-") >= 3:
        score += 15
        reasons.append("Hostname contains multiple hyphens")

        # Check suspicious brand impersonation in subdomains
    hostname_parts = hostname.lower().split(".")

    if len(hostname_parts) >= 3:
        subdomains = hostname_parts[:-2]

        for brand in BRAND_KEYWORDS:
            if any(brand in part for part in subdomains):
                score += 20
                reasons.append(
                    f"Brand name '{brand}' found in subdomain"
                )
                break


    return {
        "url": url,
        "risk_score": score,
        "risk_level": risk,
        "reasons": reasons
    }
    
    


