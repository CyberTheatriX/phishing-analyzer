# ============================================
# PHISHING ANALYZER - UTILITY FUNCTIONS
# ============================================

import re
import email
from config import SUSPICIOUS_KEYWORDS, SUSPICIOUS_DOMAINS


def extract_urls(text):
    """Pull all URLs out of a block of text."""
    pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(pattern, text)
    return urls


def extract_email_parts(raw_email):
    """
    Takes a raw email and breaks it into clean parts:
    sender, subject, body, urls found inside.
    """
    msg = email.message_from_string(raw_email)

    # Pull basic header fields
    sender  = msg.get("From", "Unknown Sender")
    subject = msg.get("Subject", "No Subject")
    date    = msg.get("Date", "Unknown Date")

    # Pull the body text
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(errors="ignore")
    else:
        body = msg.get_payload(decode=True).decode(errors="ignore")

    # Extract URLs from body
    urls = extract_urls(body)

    return {
        "sender":  sender,
        "subject": subject,
        "date":    date,
        "body":    body,
        "urls":    urls
    }


def check_suspicious_keywords(text):
    """
    Scans email text for suspicious keywords.
    Returns list of keywords found.
    """
    text_lower = text.lower()
    found = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in text_lower:
            found.append(keyword)
    return found


def check_suspicious_domain(sender):
    """
    Checks if sender's email domain is suspicious.
    Returns True if suspicious, False if clean.
    """
    sender_lower = sender.lower()
    for domain in SUSPICIOUS_DOMAINS:
        if domain in sender_lower:
            return True
    return False


def calculate_risk_score(keywords_found, suspicious_domain, url_count):
    """
    Builds a simple risk score out of 100 based on:
    - Suspicious keywords found
    - Whether sender domain is suspicious
    - Number of URLs in the email
    """
    score = 0

    # Keywords contribute up to 40 points
    score += min(len(keywords_found) * 8, 40)

    # Suspicious domain adds 30 points
    if suspicious_domain:
        score += 30

    # URLs add up to 30 points
    score += min(url_count * 10, 30)

    return min(score, 100)    # cap at 100


def get_risk_level(score):
    """Converts numeric score to human readable risk level."""
    if score >= 70:
        return "HIGH RISK"
    elif score >= 40:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"
