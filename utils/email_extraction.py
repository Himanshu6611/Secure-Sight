#!/usr/bin/env python3
"""
utils/email_extraction.py
-------------------------
Extract numeric and text features from a raw email string (subject + body).
"""

import re
import math
from collections import Counter

SUSPICIOUS_EMAIL_KEYWORDS = [
    "urgent", "action required", "account locked", "verify", "security alert",
    "password", "login", "bank", "paypal", "invoice", "payment", "unauthorized",
    "winner", "gift card", "limited time", "suspend", "confirm"
]

def extract_email_features(text: str) -> dict:
    """
    Returns a dictionary of features for a single email text.
    """
    if not text:
        text = ""
    
    # Structural features
    length = len(text)
    word_count = len(text.split())
    
    # Suspicious keywords
    lowered = text.lower()
    keyword_hits = sum(1 for kw in SUSPICIOUS_EMAIL_KEYWORDS if kw in lowered)
    
    # URL detection in body
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    url_count = len(urls)
    
    # Punctuation/Exclamation count (phishing often uses many !!!)
    exclamation_count = text.count('!')
    question_count = text.count('?')
    
    # Digit count
    digit_count = sum(c.isdigit() for c in text)
    
    # Entropy of text
    probs = [c / len(text) for c in Counter(text).values()] if text else []
    entropy = -sum(p * math.log2(p) for p in probs) if probs else 0
    
    return {
        "length": length,
        "word_count": word_count,
        "keyword_hits": keyword_hits,
        "url_count": url_count,
        "exclamation_count": exclamation_count,
        "question_count": question_count,
        "digit_count": digit_count,
        "entropy": round(entropy, 4)
    }
