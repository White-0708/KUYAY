# -*- coding: utf-8 -*-
import re

PATTERNS = {
    "urgency": [
        (r"\bact\s+(now|immediately|right\s+away|urgently)\b", "Demands immediate action to prevent you from thinking clearly."),
        (r"\b(urgent|immediate|asap|right\s+now|this\s+instant)\b", "Uses urgency words to pressure you into acting fast."),
        (r"\b(today\s+only|only\s+today|last\s+chance|final\s+(opportunity|hour|chance|warning))\b", "Creates artificial time pressure to rush your decision."),
        (r"\b(within?\s+\d+\s+(minutes?|hours?|seconds?))\b", "Sets a strict deadline to induce panic."),
        (r"\b(expires?|expiring|will\s+expire|about\s+to\s+expire|will\s+be\s+closed)\b", "Claims something is expiring to force quick action."),
        (r"\b(don't\s+wait|don't\s+delay|before\s+it's\s+too\s+late)\b", "Tells you not to wait — a classic pressure tactic."),
    ],
    "false_promises": [
        (r"\b(you\s+(won|have\s+won|have\s+been\s+selected|were\s+chosen))\b", "Says you won something. Did you enter any contest?"),
        (r"\b(prize|reward|bonus|gift|grant|inheritance|lottery|sweepstakes)\b", "Offers a prize or reward. If you didn't participate, it's fake."),
        (r"\b(money\s+without\s+working|guaranteed\s+(income|return|profit)|double\s+your)\b", "Promises easy money. That doesn't exist."),
        (r"\b(\$\s*[\d,]+|USD?\s*[\d,]+|\d+\s*(dollars?|pesos?|euros?|pounds?))\b", "Mentions specific amounts of money to tempt you."),
        (r"\b(congratulations?|congrats)\b", "Starts with congratulations — a common hook for scams."),
        (r"\b(100%\s+(free|guaranteed)|no\s+risk|risk\s+free)\b", "Claims no risk or 100% guarantee. Legitimate offers always have conditions."),
    ],
    "threats": [
        (r"\b(your\s+account\s+(will\s+be\s+(closed|suspended|deleted|locked|banned)|has\s+been\s+(suspended|locked|compromised)))\b", "Threatens to close your account to create fear."),
        (r"\b(suspended|deactivated|locked|banned|blocked|restricted)\b", "Uses account restriction language to scare you."),
        (r"\b(if\s+you\s+don't\s+(act|respond|confirm|verify|click|update))\b", "Conditions you: 'if you don't do X, something bad will happen.'"),
        (r"\b(unusual\s+(activity|login|sign-in)|suspicious\s+(activity|login))\b", "Claims unusual activity on your account — a very common scare tactic."),
        (r"\b(security\s+(alert|warning|notification|breach|issue|problem))\b", "Uses 'security' language to appear authoritative and alarming."),
        (r"\b(problem|error|issue)\s+(detected|found|identified|with\s+your)\b", "Invents a problem to make you panic and click."),
        (r"\b(your\s+(personal\s+)?information\s+(is\s+at\s+risk|has\s+been\s+compromised|was\s+leaked))\b", "Claims your data is at risk to provoke immediate action."),
    ],
    "data_theft": [
        (r"\b(enter\s+your|provide\s+your|submit\s+your|type\s+your|input\s+your)\s+(password|passcode|pin|cvv)\b", "Asks for your password or PIN. NO legitimate service does this via message."),
        (r"\b(credit\s+card|debit\s+card|card\s+number|bank\s+account|routing\s+number)\b", "Asks for banking or card details. This is always suspicious in a message."),
        (r"\b(username|user\s+name|email|login)\s+and\s+(password|passcode|pin)\b", "Asks for both username AND password — a clear theft attempt."),
        (r"\b(personal\s+details|personal\s+information|full\s+details|verify\s+your\s+identity)\b", "Asks for personal information without a clear reason."),
        (r"\b(click\s+(here|below|the\s+link|on\s+this\s+link)|tap\s+(here|below)|follow\s+this\s+link)\b", "Tells you to click a link without showing where it really leads."),
        (r"\b(download\s+(this|the|an?)\s+(file|attachment|document|app|software))\b", "Asks you to download something — could be malware."),
        (r"\b(fill\s+in\s+(this|the)\s+form|complete\s+this\s+form|update\s+your\s+records)\b", "Directs you to a form designed to steal your data."),
    ],
    "manipulation": [
        (r"\b(dear\s+(customer|user|member|client|subscriber|account\s+holder))\b", "Addresses you generically. Real services use your actual name."),
        (r"\b(don't\s+tell\s+anyone|keep\s+this\s+(secret|confidential|private)|do\s+not\s+share)\b", "Asks you to keep it secret so nobody warns you it's a scam."),
        (r"\b(only\s+you|you('re| are)\s+(the\s+only\s+one|selected|chosen|special))\b", "Makes you feel special to lower your defenses."),
        (r"\b(confirm\s+your\s+(identity|account|details|information)|verify\s+your\s+(identity|account|email|phone))\b", "Asks you to confirm identity via message. Companies don't do this."),
        (r"\b(we\s+noticed|our\s+system\s+detected|our\s+records\s+show|according\s+to\s+our\s+(records|system))\b", "Pretends to be from a system or automated process to seem legitimate."),
        (r"\b(official\s+(notice|communication|email)|this\s+is\s+not\s+a\s+joke|this\s+is\s+(real|serious|important))\b", "Insists it's real or official — the opposite is usually true."),
    ],
}

REDUNDANT_AUTHORITY = [
    (r"\b(please\s+note|important|attention|notice)\s*[:\-]?\s*$", "Uses formal headers to look like an official memo."),
]

GRAMMAR_RED_FLAGS = [
    (r"(.)\1{4,}", "Has exaggerated repeated characters (aaaa, !!!!!) — common in scam messages."),
    (r"([A-Z]{2,}\s+){2,}", "Multiple words in ALL CAPS — a desperation tactic."),
]

CONTEXT_TRIGGERS = [
    (r"https?://\S+", "Contains a link — always verify where it leads before clicking."),
    (r"\b[\w\.-]+@[\w\.-]+\.\w+\b", "Contains an email address embedded in the message."),
    (r"\+?\d{1,3}[\s\-\.]?\(?\d{2,4}\)?[\s\-\.]?\d{3,4}[\s\-\.]?\d{3,4}", "Contains a phone number — could redirect you to a scam call center."),
]


def check_text(texto):
    texto = texto.strip()
    findings = []
    categories = {}
    score = 0
    total_signals = 0

    if len(texto) < 5:
        return {
            "nivel": "amarillo",
            "puntuacion": 10,
            "alertas": ["Message is too short to analyze properly."],
            "categorias": {},
            "mensaje": "Please paste the complete message so I can review it thoroughly."
        }

    texto_lower = texto.lower()

    # Main pattern analysis
    for category, patterns in PATTERNS.items():
        count = 0
        for regex, explanation in patterns:
            if re.search(regex, texto_lower):
                findings.append(explanation)
                count += 1
                total_signals += 1
        if count > 0:
            categories[category] = count
            weights = {
                "urgency": 7,
                "false_promises": 10,
                "threats": 9,
                "data_theft": 14,
                "manipulation": 6,
            }
            score += weights.get(category, 5) * min(count, 4)

    # Redundant authority
    for regex, explanation in REDUNDANT_AUTHORITY:
        if re.search(regex, texto_lower, re.MULTILINE):
            findings.append(explanation)
            score += 4
            total_signals += 1

    # Grammar red flags
    for regex, explanation in GRAMMAR_RED_FLAGS:
        if re.search(regex, texto):
            findings.append(explanation)
            score += 4
            total_signals += 1

    # Dangerous combinations
    if "data_theft" in categories and "urgency" in categories:
        score += 18
        findings.append("DANGEROUS COMBINATION: Requests personal data WITH urgency. This is the most effective phishing technique.")
        total_signals += 1

    if "data_theft" in categories and "threats" in categories:
        score += 15
        findings.append("DANGEROUS COMBINATION: Threatens you AND asks for data. Classic credential harvesting.")
        total_signals += 1

    if "false_promises" in categories and "data_theft" in categories:
        score += 12
        findings.append("DANGEROUS COMBINATION: Offers a prize AND asks for personal info. Advance-fee scam pattern.")
        total_signals += 1

    # Multiple manipulation categories
    active_cats = len(categories)
    if active_cats >= 4:
        score += 12
        findings.append(f"Uses {active_cats} different manipulation techniques simultaneously. Extremely suspicious.")
    elif active_cats == 3:
        score += 6
        findings.append(f"Uses 3 different manipulation techniques. Highly suspicious.")

    # Context triggers (informational, lower weight)
    for regex, explanation in CONTEXT_TRIGGERS:
        if re.search(regex, texto_lower):
            if "data_theft" in categories:
                score += 8
                findings.append(explanation.replace("always verify", "WARNING: Contains a link + asks for data. Classic phishing pattern."))
            else:
                findings.append(explanation)

    # Message length analysis
    word_count = len(texto.split())
    if word_count < 15 and score > 0:
        score += 5
        findings.append("Very short message with suspicious content. Real official notices are usually more detailed.")

    score = min(score, 100)

    # Confidence score
    if total_signals >= 6:
        confidence = 92
    elif total_signals >= 3:
        confidence = 82
    elif total_signals >= 1:
        confidence = 65
    else:
        confidence = 55

    if score >= 40:
        nivel = "rojo"
    elif score >= 15:
        nivel = "amarillo"
    else:
        nivel = "verde"

    readable_names = {
        "urgency": "Urgency & Time Pressure",
        "false_promises": "False Promises & Lures",
        "threats": "Threats & Fear",
        "data_theft": "Data Theft Attempts",
        "manipulation": "Manipulation Tactics",
    }
    cats_readable = {readable_names.get(k, k): v for k, v in categories.items()}

    if nivel == "verde":
        mensaje = "This message passed the analysis. No manipulation techniques, threats, or data requests were detected. Still, if it's from someone you don't know, stay cautious."
    elif nivel == "amarillo":
        mensaje = f"This message triggered {len(findings)} warning(s). It's not clearly a scam, but it uses tactics that scammers also use. Read it carefully and don't rush to act."
    else:
        mensaje = f"This message triggered {len(findings)} red flags. It uses multiple scam techniques designed to make you act without thinking. Do NOT share any information, do NOT click any links, and talk to someone you trust."

    if not findings:
        findings.append("No manipulation patterns detected.")
        findings.append("No urgency, threats, or data requests found.")
        findings.append("Message structure appears normal.")

    return {
        "nivel": nivel,
        "puntuacion": score,
        "alertas": findings,
        "categorias": cats_readable,
        "mensaje": mensaje,
        "confidence": confidence,
        "total_signals": total_signals
    }