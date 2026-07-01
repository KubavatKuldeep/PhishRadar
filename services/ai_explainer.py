"""
PhishRadar- Gemini Strategic Insight Translator
"""
import os
import json
from google import genai
from google.genai import types
from google.genai.errors import APIError

class AiExplainer:
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.client = None
        if self.api_key:
            self.client = genai.Client(api_key=self.api_key)

    def generate_explanation(self, risk_score: int, threat_level: str, findings: list, chain: list = None) -> tuple[str, list[str]]:
        """
        Translates metric data profiles into highly contextual, natural-language threat tutorials.
        """
        fallback_explanation = "The system successfully evaluated structural parameters based on heuristic engines."
        fallback_recommendations = ["Exercise caution when executing unverified active destination endpoints."]
        
        if not self.client:
            return f"{fallback_explanation} (AI Explanation offline: Missing Key Mapping)", fallback_recommendations

        findings_str = ", ".join(findings) if findings else "No categorical threat findings flagged."
        chain_str = " -> ".join(chain) if chain else "Direct Path Link Tracking Vector."

        system_instruction = (
            "You are an advanced automated Cybersecurity Threat Analysis Assistant working inside PhishRadar.\n"
            "CRITICAL PROTOCOL: You must NEVER independently determine the threat status or calculate the risk score.\n"
            "The security verdict has already been computed by our local rule-based inspection engine.\n"
            "Your sole objective is to explain the engineering significance behind the discovered findings and outline protective defensive recommendations for educational training purposes.\n"
            "Keep definitions clear, concise, objective, and clear of marketing fluff."
        )

        user_content = (
            f"Analyze and explain this diagnostic profile:\n"
            f"- Computed Risk Index: {risk_score}/100\n"
            f"- Assessed Threat Level Tier: {threat_level}\n"
            f"- Discovered Structural Rule Violations: {findings_str}\n"
            f"- Route Redirection Hop Sequence: {chain_str}\n\n"
            f"Format your response as a valid JSON object matching this schema blueprint:\n"
            f"{{\n"
            f"  \"explanation\": \"Clear analytical explanation paragraph detailing why these technical markers imply malicious behavior.\",\n"
            f"  \"recommendations\": [\"Actionable remediation defensive step 1\", \"Actionable remediation defensive step 2\"]\n"
            f"}}"
        )

        try:
            response = self.client.models.generate_content(
                model='gemini-2.5-flash',
                contents=user_content,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    response_mime_type="application/json",
                    temperature=0.2
                )
            )
            
            result = json.loads(response.text)
            return result.get("explanation", fallback_explanation), result.get("recommendations", fallback_recommendations)
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"AI Explainer Error: {type(e).__name__}: {e}")
            quota_note = "QUOTA_EXCEEDED"
            return quota_note, fallback_recommendations