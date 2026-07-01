"""
PhishRadar - Global System Constants & Signatures
"""

# Threat Classifications
THREAT_SAFE = "Safe"
THREAT_SUSPICIOUS = "Suspicious"
THREAT_DANGEROUS = "Dangerous"

# Risk Scoring Weights
SCORE_NO_HTTPS = 20
SCORE_IP_URL = 25
SCORE_SHORTENER = 10
SCORE_SUSPICIOUS_KEYWORD = 15
SCORE_EXCESSIVE_SUBDOMAINS = 15
SCORE_BRAND_IMPERSONATION = 30
SCORE_URGENT_LANGUAGE = 20
SCORE_MULTIPLE_REDIRECTS = 15

# Core Detection Signatures
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", 
    "banking", "password", "wallet", "signin", "auth"
]

KNOWN_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", 
    "shorturl.at", "is.gd", "buff.ly", "ow.ly"
]

TARGET_BRANDS = [
    "paypal", "google", "microsoft", "amazon",
    "netflix", "apple", "facebook", "linkedin", "chase",
    "youtube", "instagram", "twitter", "whatsapp",
    "dropbox", "adobe", "zoom", "github"
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz',
    '.top', '.club', '.work', '.click', '.link',
    '.live', '.online', '.site', '.website', '.space',
    '.fun', '.store', '.tech', '.pw', '.cc'
]

URGENT_PHRASES = [
    "act now", "immediate action", "account suspended", 
    "verify now", "limited time", "urgent action required",
    "security alert", "unauthorized login"
]