# utils/url_config.py
"""
utils/url_config.py
-------------------
Lists of targeted brands, known URL shorteners, suspicious keywords, and high-risk TLDs used
in advanced URL feature extraction and suspicious indicator analysis.
"""

# Targeted brands often spoofed in phishing/typosquatting attacks
TARGET_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook",
    "instagram", "twitter", "linkedin", "github", "bankofamerica", "chase",
    "wellsfargo", "binance", "coinbase", "dropbox", "adobe", "outlook", "office365",
    "yahoo", "icloud", "steam", "discord", "meta", "spotify", "slack", "ebay",
    "walmart", "target", "stripe", "square", "coinbase", "kraken", "trustwallet"
]

# Known URL shorteners often used to hide destination URLs
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "tiny.cc", "cutt.ly", "rb.gy", "shorturl.at", "s.id",
    "t.ly", "v.gd", "clck.ru", "shorte.st", "bc.vc"
}

# Suspicious keywords indicative of credential harvesting, urgency, or account action
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "billing", "signin",
    "confirm", "password", "wallet", "support", "admin", "portal", "auth",
    "identity", "service", "security", "recover", "free", "claim", "bonus",
    "reward", "unusual", "activity", "alert", "verification", "validation",
    "banking", "verification", "authenticate", "checkpoint", "reconnect"
]

# High-risk / commonly abused Top-Level Domains (TLDs)
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "link", "club", "gq", "ml", "ga", "cf",
    "tk", "zip", "mov", "icu", "buzz", "rest", "fit", "surf", "casa", "cyou",
    "monster", "cam", "quest", "racing", "tokyo", "barcelona"
}
