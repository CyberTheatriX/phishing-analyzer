# Phishing Analyzer — AI-Powered Email Threat Detection

A command-line and web-based phishing detection tool that combines
automated heuristic analysis with a locally-running AI model to
investigate suspicious emails and generate structured threat reports.

Built as part of my cybersecurity portfolio to demonstrate practical
skills in Python, threat detection, SOC workflows, and AI integration.

---

## Why I Built This

Working through my SOC home lab, I kept running into the same
problem — phishing investigation is time-consuming and repetitive.
An analyst has to manually extract URLs, check sender domains,
look for manipulation tactics, cross-reference threat intel, and
write a report. I wanted to automate that workflow while keeping
a human-readable output that mirrors how a real SOC analyst thinks.

---

## What It Does

- Parses raw `.eml` email files and extracts all relevant fields
- Scans email body for known phishing keywords and manipulation tactics
- Flags suspicious sender domains (.ru, .tk, .ml, .ga and others)
- Extracts and lists all URLs found in the email body
- Calculates a risk score out of 100 based on weighted detection logic
- Sends findings to a locally-running AI model (phi3:mini via Ollama)
  for natural language threat assessment and MITRE ATT&CK mapping
- Generates a structured incident report saved to disk
- Supports batch processing of multiple emails in one run
- Provides a web-based SOC-style dashboard for uploading and
  reviewing analysis results in real time

---

## Architecture

Email File (.eml)
↓
Email Parser        — extracts sender, subject, body, URLs
↓
Heuristic Engine    — keyword scan, domain check, risk scoring
↓
AI Analysis         — phi3:mini via Ollama (local, no data leaves machine)
↓
Report Generator    — structured .txt report saved to /reports
↓
Web Dashboard       — Flask + HTML frontend for live review

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.12 |
| AI Model | phi3:mini (Microsoft) via Ollama |
| Web Framework | Flask |
| Email Parsing | Python `email` library |
| Pattern Matching | Python `re` library |
| Frontend | HTML, CSS, JavaScript |
| Storage | Local filesystem + SQLite-ready |

---

## Project Structure

phishing-analyzer/
├── analyzer.py          # Core analysis pipeline
├── batch.py             # Batch processing engine
├── dashboard.py         # Flask web server and routes
├── config.py            # Configuration and constants
├── utils.py             # Helper functions
├── emails/              # Email storage (.eml files)
│   ├── test_phishing_1.eml
│   ├── test_phishing_2.eml
│   └── test_legitimate.eml
├── reports/             # Generated analysis reports
└── templates/
└── index.html       # Web dashboard UI

---

## Detection Logic

Risk scoring is based on three independent signals:

**Suspicious Keywords (max 40 points)**
Scans email body for 14 known phishing phrases including urgency
triggers, account threat language, and credential request patterns.
Each keyword contributes 8 points, capped at 40.

**Sender Domain (max 30 points)**
Checks sender domain against a list of commonly abused TLDs
(.ru, .tk, .ml, .ga, .cf, .xyz, .top, .click, .link).
Binary signal — 30 points if suspicious, 0 if clean.

**URL Count (max 30 points)**
Counts URLs in email body. Each URL adds 10 points of suspicion,
capped at 30. Multiple URLs in an unsolicited email is a strong
phishing indicator.

**Risk Levels**
- 70–100 → HIGH RISK
- 40–69  → MEDIUM RISK
- 0–39   → LOW RISK

---

## AI Integration

The tool uses **phi3:mini** — Microsoft's 3.8B parameter model —
running locally via Ollama. This means:

- No data leaves the machine — sensitive email content stays private
- No API costs — fully offline capable
- Model is prompted to act as a SOC analyst and return:
  - Phishing verdict (PHISHING / SUSPICIOUS / CLEAN)
  - Attack technique used
  - MITRE ATT&CK technique mapping
  - Recommended action for the recipient

The AI layer is deliberately model-agnostic — swapping to a
different model requires changing one line in `config.py`.

---

## Setup and Installation

**Prerequisites**
- Python 3.10+
- Ollama installed and running
- phi3:mini model pulled

**Install Ollama**
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull phi3:mini
```

**Clone and install dependencies**
```bash
git clone https://github.com/YOUR_USERNAME/phishing-analyzer
cd phishing-analyzer
pip install flask requests
```

**Run single email analysis**
```bash
python3 analyzer.py emails/test_phishing_1.eml
```

**Run batch analysis**
```bash
python3 batch.py
```

**Run web dashboard**
```bash
python3 dashboard.py
```

Open browser at `http://localhost:5000`

---

## Sample Output

╔══════════════════════════════════════════════════════════════╗
║           PHISHING INVESTIGATION REPORT                      ║
║           Generated: 2026-05-24 18:06:32                     ║
╚══════════════════════════════════════════════════════════════╝
EMAIL DETAILS
─────────────────────────────────────────
From:    security@paypa1-verify.ru
Subject: URGENT: Your account has been suspended
AUTOMATED SCAN RESULTS
─────────────────────────────────────────
Risk Score:          80/100
Risk Level:          HIGH RISK
Suspicious Domain:   YES ⚠
Keywords Detected:   urgent, verify, suspended, click here,
unusual activity, limited time, act now,
password, credit card
URLS FOUND
─────────────────────────────────────────
→ http://paypal-secure-verify.tk/login?ref=urgent
AI ANALYSIS
─────────────────────────────────────────
Verdict:      PHISHING
Technique:    Credential Harvesting via Urgency Manipulation
MITRE ATT&CK: T1566.002 — Spearphishing Link
Action:       Do not click any links. Report to security team.
Block sender domain immediately.

---

## MITRE ATT&CK Coverage

This tool helps identify and document:

- **T1566** — Phishing
- **T1566.001** — Spearphishing Attachment
- **T1566.002** — Spearphishing Link
- **T1204** — User Execution
- **T1078** — Valid Accounts (credential harvesting attempts)

---

## Relevance to SOC Operations

This tool directly automates Tier 1 SOC analyst tasks:

- **Alert Triage** — automated risk scoring replaces manual first-pass
- **IOC Extraction** — URLs and domains extracted automatically
- **Incident Documentation** — structured reports generated per email
- **Threat Intel Correlation** — AI maps findings to MITRE ATT&CK
- **Batch Processing** — scales across high email volumes

---

## Future Improvements

- VirusTotal API integration for URL reputation checking
- AbuseIPDB integration for sender IP reputation
- YARA rule support for attachment scanning
- Email header analysis for SPF/DKIM/DMARC validation
- Export reports to PDF and JSON formats
- Integration with existing SOC SIEM pipeline (Wazuh)

---

## Author

Built by CyberTheatriX — aspiring SOC analyst and blue team engineer.
Part of an ongoing cybersecurity portfolio focused on detection
engineering, security automation, and AI-assisted threat analysis.
