# ============================================
# PHISHING ANALYZER - MAIN BRAIN
# ============================================

import os
import json
import requests
from datetime import datetime
from config import (
    OLLAMA_URL, OLLAMA_MODEL,
    REPORTS_DIR, EMAILS_DIR
)
from utils import (
    extract_email_parts,
    check_suspicious_keywords,
    check_suspicious_domain,
    calculate_risk_score,
    get_risk_level
)


def ask_ollama(prompt):
    """
    Sends a prompt to Ollama running locally.
    Returns AI response as plain text.
    """
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=300)
        result = response.json()
        return result.get("response", "No response from model.")
    except Exception as e:
        return f"Ollama error: {str(e)}"


def build_ai_prompt(email_data, keywords_found, suspicious_domain, risk_score):
    """
    Builds a concise prompt optimized for small local models.
    """
    prompt = f"""You are a phishing detection expert. Analyze this email briefly.

From: {email_data['sender']}
Subject: {email_data['subject']}
Body: {email_data['body'][:300]}
Risk Score: {risk_score}/100
Suspicious Keywords: {', '.join(keywords_found[:5]) if keywords_found else 'None'}
Suspicious Domain: {'YES' if suspicious_domain else 'NO'}
URLs: {len(email_data['urls'])} found

Answer these in 4 short lines:
1. Verdict: (PHISHING / CLEAN / SUSPICIOUS)
2. Technique: (what attack method)
3. MITRE ATT&CK: (technique code and name)
4. Action: (what recipient should do)"""
    return prompt


def generate_report(email_data, keywords_found,
                    suspicious_domain, risk_score,
                    risk_level, ai_analysis, filename):
    """
    Generates a clean formatted text report
    and saves it to the reports folder.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name = f"report_{timestamp}.txt"
    report_path = os.path.join(REPORTS_DIR, report_name)

    report = f"""
╔══════════════════════════════════════════════════════════════╗
║           PHISHING INVESTIGATION REPORT                      ║
║           Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}                  ║
╚══════════════════════════════════════════════════════════════╝

EMAIL DETAILS
─────────────────────────────────────────
From:    {email_data['sender']}
Subject: {email_data['subject']}
Date:    {email_data['date']}
File:    {filename}

AUTOMATED SCAN RESULTS
─────────────────────────────────────────
Risk Score:              {risk_score}/100
Risk Level:              {risk_level}
Suspicious Domain:       {'YES ⚠' if suspicious_domain else 'NO ✓'}
Suspicious Keywords:     {len(keywords_found)} found
Keywords Detected:       {', '.join(keywords_found) if keywords_found else 'None'}

URLS FOUND IN EMAIL
─────────────────────────────────────────
{chr(10).join(f'  → {url}' for url in email_data['urls']) if email_data['urls'] else '  No URLs found'}

AI ANALYSIS (phi3:mini)
─────────────────────────────────────────
{ai_analysis}

─────────────────────────────────────────
END OF REPORT
"""

    with open(report_path, "w") as f:
        f.write(report)

    return report_path, report


def analyze_email(filepath):
    """
    Master function — runs the full analysis
    pipeline on a single email file.
    """
    print(f"\n{'='*60}")
    print(f"  PHISHING ANALYZER")
    print(f"{'='*60}")
    print(f"  Analyzing: {filepath}")
    print(f"{'='*60}\n")

    # Step 1 — Read the email file
    print("[1/5] Reading email...")
    with open(filepath, "r") as f:
        raw_email = f.read()

    # Step 2 — Extract all parts
    print("[2/5] Extracting email parts...")
    email_data = extract_email_parts(raw_email)
    print(f"      From:    {email_data['sender']}")
    print(f"      Subject: {email_data['subject']}")
    print(f"      URLs:    {len(email_data['urls'])} found")

    # Step 3 — Run automated checks
    print("[3/5] Running automated checks...")
    keywords_found    = check_suspicious_keywords(email_data['body'])
    suspicious_domain = check_suspicious_domain(email_data['sender'])
    risk_score        = calculate_risk_score(
                            keywords_found,
                            suspicious_domain,
                            len(email_data['urls'])
                        )
    risk_level        = get_risk_level(risk_score)
    print(f"      Keywords found: {len(keywords_found)}")
    print(f"      Risk Score:     {risk_score}/100")
    print(f"      Risk Level:     {risk_level}")

    # Step 4 — Ask AI for analysis
    print("[4/5] Asking AI for analysis (this may take a moment)...")
    prompt      = build_ai_prompt(
                      email_data,
                      keywords_found,
                      suspicious_domain,
                      risk_score
                  )
    ai_analysis = ask_ollama(prompt)
    print("      AI analysis complete.")

    # Step 5 — Generate report
    print("[5/5] Generating report...")
    filename             = os.path.basename(filepath)
    report_path, report  = generate_report(
                               email_data,
                               keywords_found,
                               suspicious_domain,
                               risk_score,
                               risk_level,
                               ai_analysis,
                               filename
                           )

    print(f"\n{'='*60}")
    print(report)
    print(f"  Report saved to: {report_path}")
    print(f"{'='*60}\n")


# ============================================
# ENTRY POINT
# ============================================
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("\nUsage: python3 analyzer.py emails/sample.eml\n")
        sys.exit(1)

    email_file = sys.argv[1]

    if not os.path.exists(email_file):
        print(f"\nError: File not found — {email_file}\n")
        sys.exit(1)

    analyze_email(email_file)
