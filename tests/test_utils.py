from utils.feature_extraction import extract_features
from utils.email_extraction import extract_email_features

def test_url_feature_extraction():
    url = "https://www.google.com"
    feats = extract_features(url)
    assert isinstance(feats, dict)
    assert "url_len" in feats
    assert feats["https"] == 1
    assert feats["dot_cnt"] == 2

def test_email_feature_extraction():
    text = "URGENT: Please verify your bank account at http://fake-login.com"
    feats = extract_email_features(text)
    assert isinstance(feats, dict)
    assert feats["keyword_hits"] >= 3 # urgent, verify, bank
    assert feats["url_count"] == 1
