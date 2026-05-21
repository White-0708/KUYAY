# -*- coding: utf-8 -*-
from urllib.parse import urlparse, unquote
import re

SUSPICIOUS_WORDS = [
    "verify", "confirm", "account", "secure", "update",
    "login", "signin", "password", "banking", "wallet",
    "free", "prize", "winner", "claim", "reward",
    "urgent", "alert", "notification", "suspend", "limited",
    "offer", "discount", "gift", "bonus", "reactivate",
    "verify-account", "secure-login", "account-update",
    "sign-in-verify", "identity-verify", "restore-access"
]

SPOOFABLE_BRANDS = [
    "paypal", "facebook", "google", "microsoft", "amazon",
    "netflix", "spotify", "whatsapp", "apple", "instagram",
    "tiktok", "linkedin", "twitter", "youtube", "dropbox",
    "gmail", "outlook", "yahoo", "hotmail", "protonmail",
    "chase", "wellsfargo", "bankofamerica", "citibank",
    "bbva", "santander", "bcp", "scotiabank", "interbank",
    "bancolombia", "bancodebogota", "mercadolibre", "mercado"
]

SHORTENERS = [
    "bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rb.gy", "cutt.ly", "shorturl",
    "tiny.cc", "adf.ly", "bc.vc", "su.pr", "cli.gs"
]

RISKY_TLDS = [
    "tk", "ml", "ga", "cf", "gq", "xyz", "top",
    "click", "buzz", "club", "work", "life", "icu"
]


def check_url(url_texto):
    url_texto = url_texto.strip()
    findings = []
    score = 0
    checks_passed = 0
    total_checks = 0

    if not url_texto.startswith(("http://", "https://")):
        url_texto = "https://" + url_texto

    try:
        parsed = urlparse(url_texto)
    except Exception:
        return {
            "nivel": "rojo",
            "puntuacion": 100,
            "alertas": ["The input does not appear to be a valid URL."],
            "mensaje": "This is not a valid web address. Please check what was sent to you."
        }

    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    query = parsed.query.lower()
    full = domain + path + query
    decoded_full = unquote(full)
    parts = domain.replace("www.", "").split(".")
    root_domain = parts[-2] if len(parts) >= 2 else domain
    tld = parts[-1] if parts else ""

    # CHECK 1: HTTPS
    total_checks += 1
    if parsed.scheme == "http":
        score += 15
        findings.append("Does not use secure connection (HTTPS). Legitimate sites always use HTTPS.")
    else:
        checks_passed += 1

    # CHECK 2: IP address instead of domain
    total_checks += 1
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        score += 35
        findings.append("Uses a raw IP address instead of a domain name. Almost no legitimate site does this.")
    else:
        checks_passed += 1

    # CHECK 3: @ symbol in URL (credential harvesting trick)
    total_checks += 1
    if "@" in domain:
        score += 40
        findings.append("Contains '@' in the address. This is a known trick to hide the real destination.")
    else:
        checks_passed += 1

    # CHECK 4: Too many subdomains
    total_checks += 1
    subdomain_count = len(parts) - 2
    if subdomain_count > 2:
        score += 20
        findings.append(f"Has {subdomain_count} subdomains. Attackers use extra subdomains to hide the real domain.")
    else:
        checks_passed += 1

    # CHECK 5: Suspiciously long root domain
    total_checks += 1
    if len(root_domain) > 18:
        score += 12
        findings.append(f"Root domain is {len(root_domain)} characters long. Real brands use short names.")
    else:
        checks_passed += 1

    # CHECK 6: Suspicious words in URL
    total_checks += 1
    found_words = []
    for word in SUSPICIOUS_WORDS:
        if word in decoded_full:
            found_words.append(word)
    if found_words:
        score += 18 * min(len(found_words), 3)
        findings.append(f"Contains phishing-related keywords: {', '.join(found_words[:3])}.")
    else:
        checks_passed += 1

    # CHECK 7: Brand spoofing
    total_checks += 1
    spoofed = False
    for brand in SPOOFABLE_BRANDS:
        if brand in domain:
            expected = brand + ".com"
            if domain != expected and not domain.endswith("." + expected):
                score += 30
                findings.append(f"Impersonates {brand.capitalize()}, but this is NOT the official site ({expected}).")
                spoofed = True
            break
    if not spoofed:
        checks_passed += 1

    # CHECK 8: URL shortener
    total_checks += 1
    is_shortened = False
    for s in SHORTENERS:
        if s in domain:
            score += 20
            findings.append(f"Uses URL shortener ({s}). The real destination is hidden.")
            is_shortened = True
            break
    if not is_shortened:
        checks_passed += 1

    # CHECK 9: Punycode / IDN homograph attack
    total_checks += 1
    if "xn--" in domain:
        score += 25
        findings.append("Uses punycode encoding (xn--). This can be used to fake domain names with lookalike characters.")
    else:
        checks_passed += 1

    # CHECK 10: Risky TLD
    total_checks += 1
    if tld in RISKY_TLDS:
        score += 12
        findings.append(f"Uses '.{tld}' extension — cheap and commonly abused by scammers.")
    else:
        checks_passed += 1

    # CHECK 11: Unusual port
    total_checks += 1
    if ":" in domain and not domain.endswith(":80") and not domain.endswith(":443"):
        port_match = re.search(r":(\d+)$", domain)
        if port_match:
            port = int(port_match.group(1))
            if port not in [80, 443, 8080]:
                score += 15
                findings.append(f"Uses non-standard port ({port}). Legitimate sites rarely do this.")
            else:
                checks_passed += 1
        else:
            checks_passed += 1
    else:
        checks_passed += 1

    # CHECK 12: Double extensions in path
    total_checks += 1
    if re.search(r"\.\w+\.\w{2,5}(\/|$|\?)", path):
        score += 20
        findings.append("Contains double file extensions (e.g., .pdf.exe). Common malware delivery technique.")
    else:
        checks_passed += 1

    # CHECK 13: Excessive query parameters
    total_checks += 1
    param_count = len([p for p in query.split("&") if p]) if query else 0
    if param_count > 5:
        score += 10
        findings.append(f"Has {param_count} URL parameters. Can be used to track you or hide the real target.")
    else:
        checks_passed += 1

    # CHECK 14: Encoded characters hiding suspicious content
    total_checks += 1
    if "%2f" in full or "%3a" in full or "%40" in full:
        score += 10
        findings.append("Contains URL-encoded special characters that may be hiding the real destination.")
    else:
        checks_passed += 1

    # CHECK 15: Data URI
    total_checks += 1
    if url_texto.lower().startswith("data:"):
        score += 45
        findings.append("Uses a data: URI. This is a technique to embed malicious content directly in the link.")
    else:
        checks_passed += 1

    score = min(score, 100)

    # Confidence based on how many checks we could run
    confidence = min(95, 60 + (total_checks * 2))

    if score >= 40:
        nivel = "rojo"
    elif score >= 15:
        nivel = "amarillo"
    else:
        nivel = "verde"

    if nivel == "verde":
        mensaje = f"This link passed {checks_passed} out of {total_checks} security checks. No red flags detected. Still, only click links you were expecting to receive."
    elif nivel == "amarillo":
        mensaje = f"This link raised {len(findings)} warning(s) out of {total_checks} checks. It may be legitimate, but exercise caution — especially if you weren't expecting this link."
    else:
        mensaje = f"This link triggered {len(findings)} red flags out of {total_checks} checks. Strong indicators of a phishing attempt. Do NOT click it, do NOT enter any information, and warn the person who sent it."

    if not findings:
        findings.append(f"Uses secure connection (HTTPS).")
        findings.append(f"Domain structure is normal.")
        findings.append(f"No suspicious keywords detected.")
        findings.append(f"No brand impersonation detected.")

    return {
        "nivel": nivel,
        "puntuacion": score,
        "alertas": findings,
        "mensaje": mensaje,
        "confidence": confidence,
        "checks_passed": checks_passed,
        "total_checks": total_checks
    }