# ============================================
# PHISHING ANALYZER - CONFIGURATION
# ============================================

# Ollama settings
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "phi3:mini"

# Report settings
REPORTS_DIR = "reports"
EMAILS_DIR = "emails"

# Analysis thresholds
HIGH_RISK_SCORE = 70      # above this = HIGH RISK
MEDIUM_RISK_SCORE = 40    # above this = MEDIUM RISK

# Suspicious keywords to scan for
SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "suspended", "click here",
    "confirm your account", "unusual activity",
    "limited time", "act now", "password",
    "bank account", "credit card", "social security",
    "congratulations", "winner", "prize"
]

# Suspicious sender domains to watch for
SUSPICIOUS_DOMAINS = [
    ".ru", ".tk", ".ml", ".ga", ".cf",
    ".xyz", ".top", ".click", ".link"
]
