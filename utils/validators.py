"""
PhishRadar - Ingress Content Sanitation & Validation Validation
"""
from urllib.parse import urlparse

def sanitize_text(text: str) -> str:
    """Removes null bytes and strips whitespace to prevent injection vectors."""
    if not text:
        return ""
    return str(text).replace('\x00', '').strip()

def is_valid_url(url: str) -> bool:
    """Verifies syntactic structural validity of parsed tracking URLs."""
    if not url:
        return False
    try:
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and bool(parsed.netloc)
    except Exception:
        return False