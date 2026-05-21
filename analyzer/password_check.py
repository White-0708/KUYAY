# -*- coding: utf-8 -*-
import re

COMMON_PASSWORDS = [
    "password", "123456", "12345678", "123456789", "qwerty",
    "abc123", "monkey", "master", "dragon", "111111",
    "baseball", "iloveyou", "trustno1", "sunshine", "princess",
    "football", "shadow", "superman", "michael", "letmein",
    "welcome", "passw0rd", "admin", "root", "toor",
    "guest", "test", "demo", "user", "login",
    "access", "hello", "charlie", "donald", "secret"
]

COMMON_NAMES = [
    "maria", "jose", "carlos", "luis", "juan", "pedro",
    "ana", "rosa", "carmen", "patricia", "garcia", "lopez",
    "martinez", "rodriguez", "hernandez", "gonzalez", "perez",
    "smith", "johnson", "williams", "brown", "jones", "davis",
    "mama", "papa", "mom", "dad", "hijo", "hija",
    "amor", "love", "beso", "kiss", "flor", "luna",
    "sol", "luz", "star", "baby", "honey", "sweet"
]

SEQUENCES = [
    "012", "123", "234", "345", "456", "567", "678", "789", "890",
    "abc", "bcd", "cde", "def", "efg", "fgh", "ghi", "hij",
    "qwe", "wer", "ert", "rty", "tyu", "yui", "uio", "iop",
    "asd", "sdf", "dfg", "fgh", "ghj", "hjk", "jkl", "klz",
    "zxc", "xcv", "cvb", "vbn", "bnm"
]

KEYBOARD_PATTERNS = [
    "qwerty", "qwertz", "azerty", "asdfgh", "zxcvbn",
    "qazwsx", "1qaz2wsx", "wsxedc", "!@#$%"
]

LEET_SUBS = {
    "4": "a", "@": "a", "3": "e", "1": "i", "!": "i",
    "0": "o", "$": "s", "5": "s", "7": "t", "+": "t"
}

KEYBOARDS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "0987654321"
]


def check_password(password):
    password = password.strip()
    findings = []
    suggestions = []
    score = 0
    checks_passed = 0
    total_checks = 0

    if not password:
        return {
            "nivel": "rojo",
            "puntuacion": 100,
            "alertas": ["No password was provided."],
            "sugerencias": ["Type a password to analyze it."],
            "mensaje": "Please enter a password so I can check it for you."
        }

    pw_lower = password.lower()
    length = len(password)
    unique_chars = len(set(password))

    # CHECK 1: Length
    total_checks += 1
    if length < 6:
        score += 35
        findings.append(f"Very short: only {length} characters. Minimum recommended is 12.")
    elif length < 8:
        score += 20
        findings.append(f"Short: {length} characters. Modern standards recommend at least 12.")
    elif length < 12:
        score += 8
        findings.append(f"Acceptable length ({length}), but 12+ characters is the current standard.")
        suggestions.append("Add a few more characters to reach the recommended 12+ length.")
    else:
        checks_passed += 1
        suggestions.append(f"Good length: {length} characters meets modern standards.")

    # CHECK 2: Common passwords
    total_checks += 1
    if pw_lower in COMMON_PASSWORDS:
        score += 55
        findings.append(f"'{password}' is one of the most used passwords in the world. It can be guessed in less than 1 second.")
    else:
        checks_passed += 1

    # CHECK 3: Birth year
    total_checks += 1
    years = re.findall(r"(19\d{2}|20\d{2})", password)
    if years:
        score += 18
        findings.append(f"Contains a year ({', '.join(years)}). If it's your birth year, anyone who knows you can guess it.")
        suggestions.append("Remove birth years from your password.")
    else:
        checks_passed += 1

    # CHECK 4: Common names
    total_checks += 1
    name_found = False
    for name in COMMON_NAMES:
        if name in pw_lower:
            score += 15
            findings.append(f"Contains the name '{name}'. Names are the first thing attackers try.")
            suggestions.append("Avoid names of family members, partners, or pets.")
            name_found = True
            break
    if not name_found:
        checks_passed += 1

    # CHECK 5: Numeric sequences
    total_checks += 1
    seq_found = False
    for seq in SEQUENCES:
        if seq in pw_lower:
            score += 10
            findings.append(f"Contains the sequence '{seq}'. Sequential characters are trivially easy to guess.")
            suggestions.append("Avoid sequential numbers or letters like 123, abc, qwe.")
            seq_found = True
            break
    if not seq_found:
        checks_passed += 1

    # CHECK 6: Keyboard patterns
    total_checks += 1
    kb_found = False
    for pattern in KEYBOARD_PATTERNS:
        if pattern in pw_lower:
            score += 15
            findings.append(f"Contains keyboard pattern '{pattern}'. Attackers check these first.")
            kb_found = True
            break
    if not kb_found:
        checks_passed += 1

    # CHECK 7: Repeated characters
    total_checks += 1
    if unique_chars == 1:
        score += 45
        findings.append("Is a single repeated character. This provides zero protection.")
    elif unique_chars <= 2 and length > 4:
        score += 30
        findings.append(f"Uses only {unique_chars} different characters. Extremely predictable.")
    elif unique_chars <= 3 and length > 6:
        score += 15
        findings.append(f"Uses only {unique_chars} different characters. Not enough variety.")
    else:
        checks_passed += 1

    # CHECK 8: Only numbers
    total_checks += 1
    if password.isdigit():
        score += 20
        findings.append("Contains only numbers. Strong passwords mix letters, numbers, and symbols.")
        suggestions.append("Add letters and symbols to make it significantly harder to crack.")
    else:
        checks_passed += 1

    # CHECK 9: Only letters
    total_checks += 1
    if password.isalpha():
        score += 15
        findings.append("Contains only letters. Add numbers and symbols for real strength.")
        suggestions.append("Include at least one number and one symbol.")
    else:
        checks_passed += 1

    # CHECK 10: Character diversity
    total_checks += 1
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_num = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    char_types = sum([has_upper, has_lower, has_num, has_symbol])

    if char_types >= 4:
        checks_passed += 1
        suggestions.append("Excellent character diversity: mixes uppercase, lowercase, numbers, and symbols.")
    elif char_types == 3:
        score += 5
        suggestions.append("Good diversity (3 of 4 types). Add " +
                          ("a symbol" if not has_symbol else
                           ("a number" if not has_num else
                            ("an uppercase letter" if not has_upper else "a lowercase letter"))) +
                          " to maximize strength.")
    elif char_types == 2:
        score += 10
        suggestions.append("Limited diversity. Use uppercase, lowercase, numbers, AND symbols (!@#$%^&*).")
    else:
        score += 15
        suggestions.append("Very low character diversity. Mix uppercase, lowercase, numbers, and symbols.")

    # CHECK 11: Looks like a document ID or phone
    total_checks += 1
    if re.match(r"^\d{7,15}$", password):
        score += 30
        findings.append("Looks like a document ID or phone number. Never use personal data as a password.")
        suggestions.append("Your ID or phone number should never be your password.")
    else:
        checks_passed += 1

    # CHECK 12: Trivial suffix (!, 1, 123)
    total_checks += 1
    if re.match(r"^[a-zA-Z]+[!1]$", password):
        score += 12
        findings.append("Ends with '!' or '1' after letters. One of the most common weak patterns.")
    elif re.match(r"^[a-zA-Z]+\d{1,3}$", password):
        score += 8
        findings.append("Ends with a few numbers after letters. Attackers test this pattern specifically.")
    else:
        checks_passed += 1

    # CHECK 13: Leet speak detection
    total_checks += 1
    leet_detected = False
    for symbol, letter in LEET_SUBS.items():
        if symbol in password:
            deleet = password
            for s, l in LEET_SUBS.items():
                deleet = deleet.replace(s, l)
            deleet_lower = deleet.lower()
            for name in COMMON_NAMES:
                if name in deleet_lower:
                    score += 10
                    findings.append(f"Uses letter substitutions ('{symbol}' instead of '{letter}') to spell '{name}'. Attackers know this trick.")
                    suggestions.append("Letter substitutions (p@ssw0rd) don't add real security. Use truly random combinations.")
                    leet_detected = True
                    break
            if leet_detected:
                break
    if not leet_detected:
        checks_passed += 1

    # CHECK 14: Keyboard walk detection
    total_checks += 1
    walk_found = False
    pw_low = pw_lower
    for kb in KEYBOARDS:
        for i in range(len(pw_low) - 3):
            fragment = pw_low[i:i+4]
            idx = kb.find(fragment[0])
            if idx == -1:
                continue
            is_walk = True
            for j in range(1, len(fragment)):
                next_pos = kb.find(fragment[j])
                if next_pos == -1 or abs(next_pos - idx) > 2:
                    is_walk = False
                    break
                idx = next_pos
            if is_walk and len(fragment) >= 4:
                score += 12
                findings.append(f"Contains a keyboard walk pattern ('{fragment}'). Easy to guess.")
                walk_found = True
                break
        if walk_found:
            break
    if not walk_found:
        checks_passed += 1

    # CHECK 15: Entropy estimation
    total_checks += 1
    charset_size = 0
    if has_lower: charset_size += 26
    if has_upper: charset_size += 26
    if has_num: charset_size += 10
    if has_symbol: charset_size += 32
    if charset_size > 0:
        import math
        entropy = length * math.log2(charset_size)
        if entropy < 28:
            score += 20
            findings.append(f"Very low entropy ({entropy:.0f} bits). Could be brute-forced quickly.")
        elif entropy < 40:
            score += 10
            findings.append(f"Low entropy ({entropy:.0f} bits). Vulnerable to modern cracking tools.")
        elif entropy >= 60:
            checks_passed += 1
            suggestions.append(f"High entropy ({entropy:.0f} bits). Resistant to brute-force attacks.")
        else:
            checks_passed += 1
    else:
        checks_passed += 1

    score = min(score, 100)

    # Confidence
    if total_checks >= 12:
        confidence = 90
    elif total_checks >= 8:
        confidence = 80
    else:
        confidence = 65

    if score >= 40:
        nivel = "rojo"
    elif score >= 15:
        nivel = "amarillo"
    else:
        nivel = "verde"

    if nivel == "verde":
        mensaje = f"This password passed {checks_passed} out of {total_checks} security checks. Remember: never reuse it across different services, and never share it with anyone."
    elif nivel == "amarillo":
        mensaje = f"This password has weaknesses ({len(findings)} issue(s) found). It's not the worst, but a determined attacker could crack it. See the suggestions below to strengthen it."
    else:
        mensaje = f"This password is critically weak ({len(findings)} issue(s) found). It could be guessed or cracked in seconds. Please change it immediately using the suggestions below."

    if not findings:
        findings.append("No common weak patterns detected.")
        if not suggestions:
            suggestions.append("Appears to be a reasonably strong password.")

    return {
        "nivel": nivel,
        "puntuacion": score,
        "alertas": findings,
        "sugerencias": suggestions,
        "mensaje": mensaje,
        "confidence": confidence,
        "checks_passed": checks_passed,
        "total_checks": total_checks
    }