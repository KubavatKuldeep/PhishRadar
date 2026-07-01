# PhishRadar 🛡️
**Detect. Analyze. Protect.**

AI-Powered Multi-Vector Phishing Detection Platform

## Live Demo
🚀 [https://huggingface.co/spaces/Kuldip-Kubavat/PhishRadar](https://huggingface.co/spaces/Kuldip-Kubavat/PhishRadar)

## About
PhishRadar is a full-stack cybersecurity web application that detects 
phishing threats across URLs, Emails, and QR Codes using rule-based 
detection, redirect chain analysis, risk scoring, and Google Gemini 
AI-powered threat explanations.

## Features
- 🔗 URL phishing detection
- 📧 Email analysis with sender domain threat analysis
- 📷 QR code decoding and analysis
- 🔄 Real redirect chain tracing
- 🤖 Google Gemini AI threat explanations
- 📊 Risk scoring with individual finding severity
- 🔒 Privacy-first — no database, no stored data

## Detection Rules (11 Total)
- HTTPS Validation
- Brand Impersonation
- URL Shortener Detection
- Suspicious Keywords
- URL Authority Spoofing (@-based attacks)
- Typosquatting with Number Substitution
- Suspicious TLD Detection
- Hyphen Abuse in Domain
- Digits in Domain Name
- IP Address URL Detection
- Redirect Chain Analysis

## Tech Stack
- **Backend:** Python, Flask, Flask-CORS
- **Frontend:** HTML5, CSS3, JavaScript, Bootstrap 5
- **AI:** Google Gemini 2.5 Flash (google-genai SDK)
- **Libraries:** pyzbar, Pillow, BeautifulSoup4, requests
- **Deployment:** Docker, Hugging Face Spaces

## Setup Instructions

### 1. Clone the repository
git clone https://github.com/KubavatKuldeep/PhishRadar.git
cd PhishRadar/backend

### 2. Create virtual environment
python -m venv venv
venv\Scripts\activate

### 3. Install dependencies
pip install -r requirements.txt

### 4. Create .env file
FLASK_ENV=development
GEMINI_API_KEY=your_actual_gemini_api_key_here
APP_NAME=PhishRadar

### 5. Run the application
python app.py

### 6. Open in browser
http://127.0.0.1:7860

## Project Structure
- analyzers/ — Rule-based detection engines
- services/ — Core business logic (AI, redirect, risk scoring)
- utils/ — Helper functions and constants
- static/ — Frontend HTML, CSS, JavaScript files

## Built By
**Kubavat Kuldip T.**  
Diploma in Computer Engineering — Final Year  
R.C. Technical Institute, Ahmedabad  
2-Week Internship Project — GTU SBTP 2026

[

![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)

](https://www.linkedin.com/in/24-7094kuldeepkubavat)