KUYAY — Phishing & Password Security Analyzer
"Kuyay" means "I love you" in Quechua. We built this to protect the people we love most from digital threats.

A client-side security tool that detects phishing URLs, manipulative messages, and weak passwords — all without sending data to any external API. Everything runs locally.

The Problem
People of all ages fall for phishing every day. Not because they're careless, but because scam messages are designed to bypass rational thinking. Existing tools are either too technical, require API keys, or don't explain why something is dangerous.

The Solution
KUYAY analyzes three attack vectors in plain language:

Link Analyzer — 15 security checks on URLs (HTTPS, brand spoofing, punycode attacks, suspicious TLDs, URL shorteners, double extensions, encoded characters, and more)
Message Analyzer — Detects 6 categories of social engineering: urgency, false promises, threats, data theft attempts, manipulation tactics, and dangerous combinations
Password Analyzer — 15 checks including entropy calculation, keyboard walk detection, leet speak detection, common password lists, and sequence detection
How It Works
User input → Pattern analysis engine → Risk score + Confidence % + Plain language explanation

//

No external APIs. No data leaves the browser/server. Pure pattern matching and heuristic analysis in Python.

## Tech Stack

- Python 3 + Flask (backend)
- Vanilla JavaScript (frontend, no frameworks)
- Regex-based heuristic engine
- Zero external dependencies beyond Flask

## Run It

```bash
pip install flask
python app.py   


Open http://localhost:5000

Test Cases

Phishing URL (RED): http://verify-account-paypal.secure-login.tk/banking/confirm

Scam message (RED): URGENT! Your account will be closed in 30 minutes. Act now and enter your password at http://bank-verify.ml/login

Weak password (RED): Maria2024!

Why This Matters
Security tools shouldn't need a security expert to use. KUYAY speaks the language of a grandparent, not a pentester. That's the innovation — accessibility as a security feature.