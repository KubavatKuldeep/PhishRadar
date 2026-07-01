"""
PhishRadar - In-Memory Privacy-First Flask Routing Core
"""
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

from utils.validators import sanitize_text, is_valid_url
from analyzers.url_analyzer import UrlAnalyzer
from analyzers.email_analyzer import EmailAnalyzer
from analyzers.qr_analyzer import QrAnalyzer
from services.redirect_checker import RedirectChecker
from services.risk_engine import RiskEngine
from services.ai_explainer import AiExplainer

load_dotenv()

app = Flask(__name__, static_folder='static', static_url_path='')
CORS(app)

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/<path:path>')
def serve_static(path):
    if path.startswith('analyze'):
        from flask import abort
        abort(404)
    return app.send_static_file(path)

ai_explainer = AiExplainer()

@app.route('/analyze-url', methods=['POST'])
def analyze_url_endpoint():
    data = request.get_json() or {}
    raw_url = sanitize_text(data.get("url", ""))

    if not raw_url or not is_valid_url(raw_url):
        return jsonify({"error": "A valid target URL parameter containing an explicit schema protocol is required."}), 400

    redirect_chain = RedirectChecker.trace_chain(raw_url)
    final_destination = redirect_chain[-1]

    # Analyze final destination
    findings = UrlAnalyzer.analyze(final_destination)

    # Also analyze intermediate hops for threats
    for hop_url in redirect_chain[:-1]:
        hop_findings = UrlAnalyzer.analyze(hop_url)
        for f in hop_findings:
            if f not in findings and f != "Multiple Redirection Hops":
                findings.append(f)

    if len(redirect_chain) > 1:
        findings.append("Multiple Redirection Hops")

    risk_score, threat_level = RiskEngine.evaluate(findings)

    explanation, recommendations = ai_explainer.generate_explanation(
        risk_score=risk_score,
        threat_level=threat_level,
        findings=findings,
        chain=redirect_chain
    )

    quota_exceeded = explanation == "QUOTA_EXCEEDED"
    return jsonify({
        "risk_score": risk_score,
        "threat_level": threat_level,
        "findings": findings,
        "redirect_chain": redirect_chain,
        "ai_explanation": explanation if not quota_exceeded else "AI insights unavailable.",
        "recommendations": recommendations,
        "quota_exceeded": quota_exceeded
    })
@app.route('/analyze-email', methods=['POST'])
def analyze_email_endpoint():
    data = request.get_json() or {}
    sender = sanitize_text(data.get("sender", ""))
    subject = sanitize_text(data.get("subject", ""))
    body = sanitize_text(data.get("body", ""))

    if not sender or not body:
        return jsonify({"error": "Missing mandatory envelope elements: sender or content parameters."}), 400

    email_findings, discovered_urls = EmailAnalyzer.analyze(sender, subject, body)

    deep_url_findings = set(email_findings)
    aggregated_chain_samples = []

    for url in discovered_urls[:3]:
        chain = RedirectChecker.trace_chain(url)
        aggregated_chain_samples.extend(chain)
        resolved_url = chain[-1]
        
        url_findings = UrlAnalyzer.analyze(resolved_url)
        for finding in url_findings:
            deep_url_findings.add(finding)
            
        if len(chain) > 1:
            deep_url_findings.add("Multiple Redirection Hops")

    compiled_findings = list(deep_url_findings)
    risk_score, threat_level = RiskEngine.evaluate(compiled_findings)

    explanation, recommendations = ai_explainer.generate_explanation(
        risk_score=risk_score,
        threat_level=threat_level,
        findings=compiled_findings,
        chain=list(dict.fromkeys(aggregated_chain_samples))
    )

    quota_exceeded = explanation == "QUOTA_EXCEEDED"
    return jsonify({
        "risk_score": risk_score,
        "threat_level": threat_level,
        "findings": compiled_findings,
        "urls_found": discovered_urls,
        "ai_explanation": explanation if not quota_exceeded else "AI insights unavailable.",
        "recommendations": recommendations,
        "quota_exceeded": quota_exceeded
    })

@app.route('/analyze-qr', methods=['POST'])
def analyze_qr_endpoint():
    if 'image' not in request.files:
        return jsonify({"error": "Staged payload upload requires multipart form image target file allocation."}), 400

    file = request.files['image']
    if file.filename == '':
        return jsonify({"error": "Empty filename boundary token context metadata assigned."}), 400

    decoded_payload_url = QrAnalyzer.decode_stream(file.stream)

    if not decoded_payload_url or not is_valid_url(decoded_payload_url):
        return jsonify({
            "risk_score": 0,
            "threat_level": "Safe",
            "findings": ["No Actionable External Link Payload Found Inside Encrypted Grid Matrix"],
            "redirect_chain": [],
            "ai_explanation": "The processed image does not contain any readable, malicious high-density vector redirect paths.",
            "recommendations": ["No remediation response required for clear vector targets."]
        })

    redirect_chain = RedirectChecker.trace_chain(decoded_payload_url)
    final_destination = redirect_chain[-1]

    # Analyze final destination
    findings = UrlAnalyzer.analyze(final_destination)

    # Also analyze intermediate hops for threats
    for hop_url in redirect_chain[:-1]:
        hop_findings = UrlAnalyzer.analyze(hop_url)
        for f in hop_findings:
            if f not in findings and f != "Multiple Redirection Hops":
                findings.append(f)

    if len(redirect_chain) > 1:
        findings.append("Multiple Redirection Hops")

    risk_score, threat_level = RiskEngine.evaluate(findings)

    explanation, recommendations = ai_explainer.generate_explanation(
        risk_score=risk_score,
        threat_level=threat_level,
        findings=findings,
        chain=redirect_chain
    )

    quota_exceeded = explanation == "QUOTA_EXCEEDED"
    return jsonify({
        "decoded_url": decoded_payload_url,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "findings": findings,
        "redirect_chain": redirect_chain,
        "ai_explanation": explanation if not quota_exceeded else "AI insights unavailable.",
        "recommendations": recommendations,
        "quota_exceeded": quota_exceeded
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 7860))
    app.run(host='0.0.0.0', port=port, debug=False)