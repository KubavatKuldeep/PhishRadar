"""
PhishRadar - Heuristic Domain Analyzer Component
"""
import re
import difflib
from urllib.parse import urlparse
from utils.constants import SUSPICIOUS_KEYWORDS, KNOWN_SHORTENERS, TARGET_BRANDS

class UrlAnalyzer:
    @staticmethod
    def analyze(url: str) -> list[str]:
        """
        Evaluates structural features of a URL against defined threat indicators.
        """
        findings = []
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname.lower() if parsed.hostname else ""
            path = parsed.path.lower() if parsed.path else ""
        except Exception:
            return ["Malformed URL Configuration"]

        # 1. HTTPS Check
        if parsed.scheme != 'https':
            findings.append("No HTTPS")

        # 2. IP Address Pattern Matching
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if ip_pattern.match(hostname) or (hostname.startswith('[') and hostname.endswith(']')):
            findings.append("IP Address URL Detected")

        # 3. Shortener Detection Loop
        if any(shortener in hostname for shortener in KNOWN_SHORTENERS):
            findings.append("URL Shortener Detected")

        # 4. Keyword Context Filtering
        combined_text = f"{hostname} {path} {parsed.query.lower()}"
        if any(keyword in combined_text for keyword in SUSPICIOUS_KEYWORDS):
            findings.append("Suspicious Keyword Detected")

        # 5. Excessive Subdomain Layer Checks
        domain_parts = hostname.strip('.').split('.')
        if len(domain_parts) > 4:
            findings.append("Excessive Subdomains Detected")

        # 6. Brand Impersonation Inspection
        for brand in TARGET_BRANDS:
            if brand in hostname:
                legitimate_patterns = [f"{brand}.com", f".{brand}.com", f"{brand}.net", f".{brand}.net"]
                if not any(hostname.endswith(p) for p in legitimate_patterns) and hostname != f"{brand}.com":
                    findings.append("Brand Impersonation Flags")
                    break
        
        # 7. Suspicious TLD Detection
        from utils.constants import SUSPICIOUS_TLDS
        if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
            findings.append("Suspicious TLD Detected")

        # 8. Hyphen Abuse Detection
        domain_only = domain_parts[-2] if len(domain_parts) >= 2 else hostname
        if domain_only.count('-') >= 2:
            findings.append("Hyphen Abuse in Domain")

        # 9. Digit in Domain Detection
        if any(char.isdigit() for char in domain_only):
            findings.append("Digits in Domain Name")
        
        # 10. Typosquatting Detection
        number_map = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't'}

        # Split all domain parts further by hyphens to catch instagam inside reels-instagam-shareonline
        expanded_parts = []
        for part in domain_parts:
            expanded_parts.append(part)
            if '-' in part:
                expanded_parts.extend(part.split('-'))

        for brand in TARGET_BRANDS:
            found = False
            for part in expanded_parts:
                if part != brand and len(part) > 4:
                    # Direct similarity check
                    similarity = difflib.SequenceMatcher(None, part, brand).ratio()
                    if similarity > 0.75:
                        if "Brand Impersonation Flags" not in findings:
                            findings.append("Brand Impersonation Flags")
                        found = True
                        break
                    # Number substitution normalized check
                    normalized = part
                    for num, letter in number_map.items():
                        normalized = normalized.replace(num, letter)
                    if normalized != part:
                        norm_similarity = difflib.SequenceMatcher(None, normalized, brand).ratio()
                        if norm_similarity > 0.75:
                            if "Brand Impersonation Flags" not in findings:
                                findings.append("Brand Impersonation Flags")
                            found = True
                            break
            if found:
                break

        # 11. URL Authority Spoofing Detection (@-based attacks)
        # e.g. https://youtube.com@evil.netlify.app
        raw_url_lower = url.lower()
        if '@' in raw_url_lower:
            # Extract everything after scheme and before @
            try:
                scheme_stripped = raw_url_lower.split('://', 1)[1] if '://' in raw_url_lower else raw_url_lower
                if '@' in scheme_stripped:
                    fake_authority = scheme_stripped.split('@')[0]
                    findings.append("URL Authority Spoofing Detected")
                    # Check if a brand name is in the fake authority part
                    for brand in TARGET_BRANDS:
                        if brand in fake_authority:
                            if "Brand Impersonation Flags" not in findings:
                                findings.append("Brand Impersonation Flags")
                            break
            except Exception:
                pass

        return findings