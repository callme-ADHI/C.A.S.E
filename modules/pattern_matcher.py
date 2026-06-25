"""
C.A.S.E. — Cyber Attack Scene Examiner
Pattern Matcher Module

Heuristics-based crime pattern matcher evaluating OSINT metrics and free-text notes
to classify potential cybercrime indicators.
"""

def _notes_contains(notes: str, keywords: list) -> list:
    """
    Checks if notes contain any of the given keywords (case-insensitive).
    Returns a list of matched keywords.
    """
    if not notes:
        return []
    found = []
    notes_lower = notes.lower()
    for kw in keywords:
        if kw.lower() in notes_lower:
            found.append(kw)
    return found


def match_crime_patterns(full_result: dict) -> list:
    """
    Examines OSINT findings and complainant notes to categorize potential cybercrime patterns.
    
    Args:
        full_result: The complete dictionary output from run_full_osint().
        
    Returns:
        list of dicts containing pattern, confidence, and reasoning list.
    """
    patterns = []
    
    subject = full_result.get("subject", {})
    osint_results = full_result.get("osint_results", [])
    
    notes = subject.get("notes") or ""
    
    # ── Gather OSINT signals from results ──────────────────────────────────────
    vt_malicious_count = 0
    phishtank_phishing = False
    newly_registered = False
    disposable_domain = False
    hibp_breached = False
    repeat_offender_phone = False
    repeat_pattern_upi_wallet = False
    
    # Extract url/domain info
    url_or_domain_provided = bool(subject.get("url") or subject.get("domain"))
    
    for ioc in osint_results:
        ioc_type = ioc.get("ioc_type")
        
        for r in ioc.get("results", []):
            if not r:
                continue
            source = r.get("source")
            
            if source == "virustotal" and ioc_type in ("url", "domain"):
                vt_malicious_count = max(vt_malicious_count, r.get("malicious_count", 0))
                
            elif source == "phishtank" and ioc_type == "url":
                if r.get("is_phishing"):
                    phishtank_phishing = True
                    
            elif source == "domain_age_check":
                if r.get("is_newly_registered"):
                    newly_registered = True
                if r.get("is_disposable_domain"):
                    disposable_domain = True
                    
            elif source == "haveibeenpwned" and ioc_type == "email":
                if r.get("is_breached"):
                    hibp_breached = True
                    
            elif source == "phone_osint" and ioc_type == "phone":
                if r.get("is_repeat_offender_number"):
                    repeat_offender_phone = True
                    
            elif source == "cross_case_linker" and ioc_type in ("upi_id", "wallet"):
                if r.get("is_repeat_pattern"):
                    repeat_pattern_upi_wallet = True

    # ── RULE 1: Phishing / Fake Banking Site ───────────────────────────────────
    r1_keywords = ["bank", "kyc", "otp", "login", "verify", "suspend"]
    r1_matches = _notes_contains(notes, r1_keywords)
    
    if url_or_domain_provided and (vt_malicious_count >= 1 or phishtank_phishing or newly_registered) or r1_matches:
        reasoning = []
        confidence = "Low"
        
        if vt_malicious_count >= 1:
            reasoning.append(f"VirusTotal flagged URL/domain ({vt_malicious_count} malicious engines)")
            confidence = "High"
        if phishtank_phishing:
            reasoning.append("PhishTank confirmed phishing URL")
            confidence = "High"
        if newly_registered and url_or_domain_provided:
            reasoning.append("Domain age check flagged newly registered domain")
            if confidence != "High":
                confidence = "Low"
        if r1_matches:
            reasoning.append(f"Notes mention keywords: {', '.join([f'\'{m}\'' for m in r1_matches])}")
            if confidence != "High":
                confidence = "Medium"
                
        patterns.append({
            "pattern": "Phishing / Fake Banking Website",
            "confidence": confidence,
            "reasoning": reasoning
        })

    # ── RULE 2: UPI / Financial Fraud ──────────────────────────────────────────
    r2_keywords = ["payment", "upi", "transfer", "refund", "cashback", "customer care"]
    r2_matches = _notes_contains(notes, r2_keywords)
    has_financial_field = bool(subject.get("upi_id") or subject.get("phone"))
    
    if (has_financial_field and r2_matches) or repeat_offender_phone or repeat_pattern_upi_wallet:
        reasoning = []
        confidence = "Medium"
        
        if repeat_offender_phone:
            reasoning.append("Phone number is linked to prior case(s) (Repeat offender)")
            confidence = "High"
        if repeat_pattern_upi_wallet:
            reasoning.append("UPI ID/Wallet is linked to prior case(s) (Repeat offender)")
            confidence = "High"
        if r2_matches:
            reasoning.append(f"Notes mention keywords: {', '.join([f'\'{m}\'' for m in r2_matches])}")
            
        patterns.append({
            "pattern": "UPI / Digital Payment Fraud",
            "confidence": confidence,
            "reasoning": reasoning
        })

    # ── RULE 3: Digital Arrest / Impersonation Scam ───────────────────────────
    r3_keywords = ["cbi", "police", "customs", "arrest", "video call", "ed officer", "narcotics"]
    r3_matches = _notes_contains(notes, r3_keywords)
    
    if r3_matches:
        patterns.append({
            "pattern": "Digital Arrest / Impersonation Scam",
            "confidence": "Medium",
            "reasoning": [f"Notes mention keywords: {', '.join([f'\'{m}\'' for m in r3_matches])}"]
        })

    # ── RULE 4: Social Media Identity Crime ────────────────────────────────────
    r4_keywords = ["fake profile", "hacked", "morphed", "blackmail", "sextortion", "leaked photo"]
    r4_matches = _notes_contains(notes, r4_keywords)
    has_social_field = bool(subject.get("username") or subject.get("url"))
    
    if has_social_field and r4_matches:
        reasoning = []
        if subject.get("username"):
            reasoning.append(f"Username provided: '{subject.get('username')}'")
        if subject.get("url"):
            reasoning.append(f"Social URL provided: '{subject.get('url')}'")
        reasoning.append(f"Notes mention keywords: {', '.join([f'\'{m}\'' for m in r4_matches])}")
        
        patterns.append({
            "pattern": "Social Media Crime (Hack / Sextortion / Morphing)",
            "confidence": "Medium",
            "reasoning": reasoning
        })

    # ── RULE 5: Investment / Trading Scam ──────────────────────────────────────
    r5_keywords = ["invest", "trading", "returns", "profit", "telegram group", "whatsapp group"]
    r5_matches = _notes_contains(notes, r5_keywords)
    
    if r5_matches:
        confidence = "Medium"
        reasoning = [f"Notes mention keywords: {', '.join([f'\'{m}\'' for m in r5_matches])}"]
        
        if subject.get("url") and newly_registered:
            reasoning.append("Platform URL domain is newly registered")
            confidence = "High"
            
        patterns.append({
            "pattern": "Investment / Trading Scam",
            "confidence": confidence,
            "reasoning": reasoning
        })

    # ── RULE 6: Job Fraud ──────────────────────────────────────────────────────
    r6_keywords = ["job offer", "interview", "registration fee", "work from home", "hiring"]
    r6_matches = _notes_contains(notes, r6_keywords)
    
    if r6_matches:
        patterns.append({
            "pattern": "Job Fraud",
            "confidence": "Medium",
            "reasoning": [f"Notes mention keywords: {', '.join([f'\'{m}\'' for m in r6_matches])}"]
        })

    # ── RULE 7: Email-Based Phishing ───────────────────────────────────────────
    if subject.get("email") and (hibp_breached or disposable_domain or newly_registered):
        confidence = "Low"
        reasoning = []
        
        if disposable_domain:
            reasoning.append("Disposable email domain provider detected")
            confidence = "High"
        elif hibp_breached:
            reasoning.append("Email address leaked in HaveIBeenPwned breach history")
            confidence = "Medium"
        elif newly_registered:
            reasoning.append("Email domain is newly registered")
            confidence = "Low"
            
        patterns.append({
            "pattern": "Email Phishing / Compromised Account",
            "confidence": confidence,
            "reasoning": reasoning
        })

    # ── RULE 8: Cyberstalking / Harassment ────────────────────────────────────
    r8_keywords = ["threatening", "stalking", "following", "harassment", "doxxing", "tracking"]
    r8_matches = _notes_contains(notes, r8_keywords)
    
    if r8_matches:
        patterns.append({
            "pattern": "Cyberstalking / Online Harassment",
            "confidence": "Medium",
            "reasoning": [f"Notes mention keywords: {', '.join([f'\'{m}\'' for m in r8_matches])}"]
        })

    # ── RULE 9: Generic Hacking / Malicious Infrastructure ─────────────────────
    if url_or_domain_provided and vt_malicious_count >= 5:
        patterns.append({
            "pattern": "Hacking / Malicious Infrastructure",
            "confidence": "High",
            "reasoning": [f"VirusTotal flagged URL/domain as highly malicious ({vt_malicious_count} engines)"]
        })

    # ── DEFAULT: No matches ────────────────────────────────────────────────────
    if not patterns:
        patterns.append({
            "pattern": "No clear cybercrime pattern detected",
            "confidence": "—",
            "reasoning": [
                "The provided OSINT data and notes did not match any known fraud pattern. This does not mean the subject is safe — it may mean more information is needed."
            ]
        })
        return patterns

    # Sort by confidence descending (High -> 3, Medium -> 2, Low -> 1, — -> 0)
    score_map = {"High": 3, "Medium": 2, "Low": 1, "—": 0}
    patterns.sort(key=lambda x: score_map.get(x["confidence"], 0), reverse=True)
    
    return patterns
