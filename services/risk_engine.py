"""
PhishRadar - Core Heuristic Risk Scoring Engine
"""
from utils.constants import (
    THREAT_SAFE, THREAT_SUSPICIOUS, THREAT_DANGEROUS,
    SCORE_NO_HTTPS, SCORE_IP_URL, SCORE_SHORTENER,
    SCORE_SUSPICIOUS_KEYWORD, SCORE_EXCESSIVE_SUBDOMAINS,
    SCORE_BRAND_IMPERSONATION, SCORE_URGENT_LANGUAGE,
    SCORE_MULTIPLE_REDIRECTS
)

class RiskEngine:
    @staticmethod
    def evaluate(findings: list) -> tuple[int, str]:
        """
        Calculates standardized threat limits based entirely on rule matrix outcomes.
        Returns a tuple of (risk_score, threat_level).
        """
        score = 0
        
        weight_mapping = {
            "No HTTPS": SCORE_NO_HTTPS,
            "IP Address URL Detected": SCORE_IP_URL,
            "URL Shortener Detected": SCORE_SHORTENER,
            "Suspicious Keyword Detected": SCORE_SUSPICIOUS_KEYWORD,
            "Excessive Subdomains Detected": SCORE_EXCESSIVE_SUBDOMAINS,
            "Brand Impersonation Flags": SCORE_BRAND_IMPERSONATION,
            "Urgent Language Detected": SCORE_URGENT_LANGUAGE,
            "Multiple Redirection Hops": SCORE_MULTIPLE_REDIRECTS,
            "Suspicious Sender Domain": 20,
            "Free Email Provider Used": 10,
            "URL Authority Spoofing Detected": 35,
            "Suspicious TLD Detected": 20,
            "Hyphen Abuse in Domain": 10,
            "Digits in Domain Name": 10
        }

        for finding in findings:
            if finding in weight_mapping:
                score += weight_mapping[finding]

        score = min(score, 100)

        if score <= 30:
            level = THREAT_SAFE
        elif score <= 60:
            level = THREAT_SUSPICIOUS
        else:
            level = THREAT_DANGEROUS

        return score, level