"""
PhishRadar - Structured Payload Mail Context Extraction Engine
"""
import re
from bs4 import BeautifulSoup
from utils.constants import URGENT_PHRASES, TARGET_BRANDS
from utils.validators import is_valid_url

class EmailAnalyzer:
    @staticmethod
    def extract_urls(body_text: str) -> list[str]:
        """Extracts valid URLs from plain text and raw HTML structures."""
        urls = set()
        
        raw_matches = re.findall(r'https?://[^\s<>"\']+', body_text)
        for url in raw_matches:
            clean_url = url.rstrip('.,;:)')
            if is_valid_url(clean_url):
                urls.add(clean_url)
                
        try:
            soup = BeautifulSoup(body_text, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                if is_valid_url(href):
                    urls.add(href)
        except Exception:
            pass
            
        return list(urls)

    @classmethod
    def analyze(cls, sender: str, subject: str, body: str) -> tuple[list[str], list[str]]:
        """
        Inspects textual and envelope assets for phishing traits.
        """
        findings = []
        sender_lower = sender.lower()
        subject_lower = subject.lower()
        body_lower = body.lower()

        # 1. Social Engineering Urgency Analysis
        combined_text = f"{subject_lower} {body_lower}"
        if any(phrase in combined_text for phrase in URGENT_PHRASES):
            findings.append("Urgent Language Detected")

        # 2. Sender Domain Lookalike Brand Checks
        for brand in TARGET_BRANDS:
            if brand in sender_lower:
                if not (sender_lower.endswith(f"@{brand}.com") or sender_lower.endswith(f".{brand}.com")):
                    findings.append("Brand Impersonation Flags")
                    break

        # 3. Suspicious Sender Domain Structure Check
        if '@' in sender_lower:
            domain_part = sender_lower.split('@')[-1]
            # Check for suspicious keywords in sender domain
            suspicious_domain_keywords = ['secure', 'verify', 'update', 'login', 'account', 'alert', 'support', 'helpdesk', 'noreply']
            if any(kw in domain_part for kw in suspicious_domain_keywords):
                if 'Suspicious Sender Domain' not in findings:
                    findings.append("Suspicious Sender Domain")

            # Check for free email providers pretending to be official
            free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com']
            if any(domain_part == provider for provider in free_providers):
                findings.append("Free Email Provider Used")

            # Check for excessive hyphens in domain (common in phishing)
            if domain_part.count('-') >= 2:
                findings.append("Suspicious Sender Domain")

        # 4. Deep URL Harvesting Extractor
        extracted_urls = cls.extract_urls(body)

        return findings, extracted_urls