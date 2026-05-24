# ============================================
# PHISHING ANALYZER - BATCH PROCESSOR
# ============================================

import os
import glob
from datetime import datetime
from analyzer import analyze_email
from config import EMAILS_DIR, REPORTS_DIR


def get_all_emails():
    """
    Scans the emails folder and returns
    a list of all .eml files found.
    """
    pattern = os.path.join(EMAILS_DIR, "*.eml")
    emails  = glob.glob(pattern)
    return emails


def generate_summary(results):
    """
    Takes a list of analysis results and
    produces a single summary report.
    """
    timestamp    = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_path = os.path.join(REPORTS_DIR, f"summary_{timestamp}.txt")

    total     = len(results)
    high      = sum(1 for r in results if r['risk_level'] == "HIGH RISK")
    medium    = sum(1 for r in results if r['risk_level'] == "MEDIUM RISK")
    low       = sum(1 for r in results if r['risk_level'] == "LOW RISK")
    failed    = sum(1 for r in results if r['status'] == "FAILED")

    summary = f"""
╔══════════════════════════════════════════════════════════════╗
║           BATCH ANALYSIS SUMMARY                             ║
║           Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}                  ║
╚══════════════════════════════════════════════════════════════╝

OVERVIEW
─────────────────────────────────────────
Total Emails Analyzed:   {total}
Failed:                  {failed}
Successfully Analyzed:   {total - failed}

RISK BREAKDOWN
─────────────────────────────────────────
🔴 HIGH RISK:            {high}
🟡 MEDIUM RISK:          {medium}
🟢 LOW RISK:             {low}

INDIVIDUAL RESULTS
─────────────────────────────────────────
"""

    for r in results:
        if r['status'] == "FAILED":
            summary += f"  ❌ {r['filename']:<30} FAILED\n"
        else:
            risk_icon = (
                "🔴" if r['risk_level'] == "HIGH RISK"
                else "🟡" if r['risk_level'] == "MEDIUM RISK"
                else "🟢"
            )
            summary += (
                f"  {risk_icon} {r['filename']:<30} "
                f"Score: {r['risk_score']:>3}/100   "
                f"{r['risk_level']}\n"
            )

    summary += f"""
─────────────────────────────────────────
END OF SUMMARY
"""

    with open(summary_path, "w") as f:
        f.write(summary)

    return summary_path, summary


def run_batch():
    """
    Master batch function.
    Finds all emails, analyzes each one,
    then generates a summary report.
    """
    print(f"\n{'='*60}")
    print(f"  BATCH PHISHING ANALYZER")
    print(f"{'='*60}\n")

    # Step 1 — Find all emails
    emails = get_all_emails()

    if not emails:
        print(f"  No .eml files found in '{EMAILS_DIR}' folder.")
        print(f"  Add some .eml files and try again.\n")
        return

    print(f"  Found {len(emails)} email(s) to analyze.\n")
    print(f"{'='*60}\n")

    # Step 2 — Analyze each email
    results = []

    for i, filepath in enumerate(emails, start=1):
        filename = os.path.basename(filepath)
        print(f"  [{i}/{len(emails)}] Analyzing: {filename}")

        try:
            result = analyze_email_silent(filepath)
            results.append(result)
            print(f"         Score: {result['risk_score']}/100 — {result['risk_level']}\n")
        except Exception as e:
            results.append({
                "filename":   filename,
                "risk_score": 0,
                "risk_level": "UNKNOWN",
                "status":     "FAILED",
                "error":      str(e)
            })
            print(f"         FAILED: {str(e)}\n")

    # Step 3 — Generate summary
    print(f"{'='*60}")
    print(f"  Generating batch summary...")
    summary_path, summary = generate_summary(results)
    print(summary)
    print(f"  Summary saved to: {summary_path}\n")


def analyze_email_silent(filepath):
    """
    Runs the full analysis pipeline silently
    — no terminal printing, just returns results
    as a dictionary for batch processing.
    """
    import re
    from utils import (
        extract_email_parts,
        check_suspicious_keywords,
        check_suspicious_domain,
        calculate_risk_score,
        get_risk_level
    )
    from analyzer import ask_ollama, build_ai_prompt, generate_report

    filename = os.path.basename(filepath)

    with open(filepath, "r") as f:
        raw_email = f.read()

    email_data        = extract_email_parts(raw_email)
    keywords_found    = check_suspicious_keywords(email_data['body'])
    suspicious_domain = check_suspicious_domain(email_data['sender'])
    risk_score        = calculate_risk_score(
                            keywords_found,
                            suspicious_domain,
                            len(email_data['urls'])
                        )
    risk_level        = get_risk_level(risk_score)
    prompt            = build_ai_prompt(
                            email_data,
                            keywords_found,
                            suspicious_domain,
                            risk_score
                        )
    ai_analysis       = ask_ollama(prompt)

    generate_report(
        email_data, keywords_found,
        suspicious_domain, risk_score,
        risk_level, ai_analysis, filename
    )

    return {
        "filename":   filename,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "status":     "SUCCESS"
    }


# ============================================
# ENTRY POINT
# ============================================
if __name__ == "__main__":
    run_batch()
