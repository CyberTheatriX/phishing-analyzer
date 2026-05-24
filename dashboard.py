# ============================================
# PHISHING ANALYZER - WEB DASHBOARD
# ============================================

import os
import json
from flask import Flask, render_template, request, jsonify
from datetime import datetime
from utils import (
    extract_email_parts,
    check_suspicious_keywords,
    check_suspicious_domain,
    calculate_risk_score,
    get_risk_level
)
from analyzer import ask_ollama, build_ai_prompt, generate_report

app = Flask(__name__)

# ============================================
# HELPER — LOAD ALL EXISTING REPORTS
# ============================================

def load_reports():
    """
    Scans the reports folder and loads
    all existing report files into a list.
    """
    reports = []
    report_files = sorted(
        [f for f in os.listdir("reports") if f.endswith(".txt")
         and not f.startswith("summary")],
        reverse=True
    )

    for filename in report_files:
        filepath = os.path.join("reports", filename)
        with open(filepath, "r") as f:
            content = f.read()

        # Extract risk level from report content
        if "HIGH RISK" in content:
            risk_level = "HIGH RISK"
            risk_color = "red"
        elif "MEDIUM RISK" in content:
            risk_level = "MEDIUM RISK"
            risk_color = "orange"
        else:
            risk_level = "LOW RISK"
            risk_color = "green"

        reports.append({
            "filename": filename,
            "content":  content,
            "risk_level": risk_level,
            "risk_color": risk_color
        })

    return reports


# ============================================
# ROUTES
# ============================================

@app.route("/")
def index():
    """Main dashboard page."""
    reports = load_reports()

    # Count risk levels for summary cards
    high   = sum(1 for r in reports if r['risk_level'] == "HIGH RISK")
    medium = sum(1 for r in reports if r['risk_level'] == "MEDIUM RISK")
    low    = sum(1 for r in reports if r['risk_level'] == "LOW RISK")

    return render_template(
        "index.html",
        reports=reports,
        total=len(reports),
        high=high,
        medium=medium,
        low=low
    )


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Receives an uploaded email file,
    runs full analysis, returns results as JSON.
    """
    if "email_file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["email_file"]

    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    # Save uploaded file temporarily
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename  = f"uploaded_{timestamp}.eml"
    filepath  = os.path.join("emails", filename)
    file.save(filepath)

    try:
        # Run full analysis pipeline
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

        return jsonify({
            "status":           "success",
            "filename":         filename,
            "sender":           email_data['sender'],
            "subject":          email_data['subject'],
            "risk_score":       risk_score,
            "risk_level":       risk_level,
            "keywords_found":   keywords_found,
            "suspicious_domain": suspicious_domain,
            "url_count":        len(email_data['urls']),
            "urls":             email_data['urls'],
            "ai_analysis":      ai_analysis
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/reports")
def get_reports():
    """Returns all reports as JSON for dashboard refresh."""
    reports = load_reports()
    return jsonify(reports)


# ============================================
# ENTRY POINT
# ============================================
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
