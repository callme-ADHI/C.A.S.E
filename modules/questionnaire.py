"""
C.A.S.E. — Cyber Attack Scene Examiner
Dynamic Questionnaire Engine

Core module for Day 1: Builds crime-specific questionnaires based on
I4C classification codes, validates inputs, detects legal triggers
(PMLA / POCSO / 1930 Helpline), and returns structured case data.

Legal Notes:
  - IT Act Section 66A is STRUCK DOWN (Shreya Singhal v UOI 2015) — never referenced.
  - FIR filed under Section 173 BNSS 2023 (not old CrPC Section 154).
  - BNS 2023 sections apply (not IPC) — in effect from July 1, 2024.
"""

import re
from datetime import datetime
from colorama import Fore, Style

# ══════════════════════════════════════════════════════════════════════════════
#  CRIME TYPE REGISTRY (I4C Classification)
# ══════════════════════════════════════════════════════════════════════════════

CRIME_TYPES = {
    "C001": "Online Financial Fraud (UPI/Banking/Card)",
    "C002": "Digital Arrest / Impersonation Scam",
    "C003": "Phishing / Vishing / Smishing",
    "C004": "Social Media Crime (Hack/Sextortion/Morphing)",
    "C005": "Cyberstalking / Online Harassment",
    "C006": "Ransomware / Malware Attack",
    "C007": "Hacking / Unauthorized Access",
    "C008": "Investment / Trading Scam",
    "C009": "Data Breach / Privacy Violation",
    "C010": "Cyber Defamation / Fake News",
    "C011": "CSAM / POCSO Digital Offence",
    "C012": "Job Fraud",
}

# ══════════════════════════════════════════════════════════════════════════════
#  QUESTION DEFINITIONS PER CRIME TYPE
# ══════════════════════════════════════════════════════════════════════════════


def _q(id, question, qtype="text", required=True, options=None,
       pocso_trigger=False, pmla_trigger=False, helpline_trigger=False):
    """Helper to build a question dict with sane defaults."""
    q = {
        "id": id,
        "question": question,
        "type": qtype,
        "required": required,
    }
    if options:
        q["options"] = options
    if pocso_trigger:
        q["pocso_trigger"] = True
    if pmla_trigger:
        q["pmla_trigger"] = True
    if helpline_trigger:
        q["helpline_trigger"] = True
    return q


CRIME_QUESTIONS = {
    # ── C001 — Online Financial Fraud ─────────────────────────────────────
    "C001": [
        _q("complainant_name", "Full name of the complainant?"),
        _q("complainant_phone", "Complainant's phone number?", "phone"),
        _q("complainant_bank", "Complainant's bank name?"),
        _q("account_number", "Complainant's account number?"),
        _q("fraud_subtype", "Type of financial fraud?", "choice",
           options=["UPI Fraud", "Net Banking", "Card Fraud",
                    "SIM Swap", "Fake KYC", "Other"]),
        _q("suspect_phone", "Suspect's phone number?", "phone", required=False),
        _q("suspect_upi_id", "Suspect's UPI ID?", required=False),
        _q("beneficiary_account", "Beneficiary account number?", required=False),
        _q("beneficiary_bank", "Beneficiary bank name?", required=False),
        _q("transaction_id", "Transaction ID / Reference number?"),
        _q("amount_lost", "Amount lost (₹)?", "number",
           pmla_trigger=True, helpline_trigger=True),
        _q("transaction_date", "Date of transaction?", "date"),
        _q("mode_of_contact", "How did the suspect contact you?", "choice",
           options=["Phone Call", "WhatsApp", "SMS", "Email", "Other"]),
        _q("modus_operandi", "Describe the modus operandi in brief?"),
        _q("evidence_available", "What evidence is available?", "choice",
           options=["Screenshots", "Bank Statement", "Call Recording",
                    "All", "None"]),
    ],

    # ── C002 — Digital Arrest / Impersonation Scam ────────────────────────
    "C002": [
        _q("complainant_name", "Full name of the complainant?"),
        _q("complainant_phone", "Complainant's phone number?", "phone"),
        _q("caller_number", "Caller's phone number?", "phone"),
        _q("impersonated_agency", "Which agency did the caller impersonate?", "choice",
           options=["CBI", "ED", "TRAI", "Customs", "Police",
                    "Narcotics", "Other"]),
        _q("communication_mode", "Mode of communication?", "choice",
           options=["WhatsApp Video", "Regular Call", "Telegram", "Other"]),
        _q("call_date", "Date of the call?", "date"),
        _q("call_duration", "Approximate call duration?", required=False),
        _q("amount_extorted", "Amount extorted (₹)?", "number",
           pmla_trigger=True, helpline_trigger=True),
        _q("payment_method", "Payment method used?", "choice",
           options=["UPI", "Bank Transfer", "Crypto", "Not Paid"]),
        _q("transaction_details", "Transaction ID / details?", required=False),
        _q("fake_documents_received", "Were fake documents received?", "yesno",
           required=False),
        _q("isolation_instructions_given",
           "Was the victim given isolation instructions (stay on call, don't tell anyone)?",
           "yesno", required=False),
    ],

    # ── C003 — Phishing / Vishing / Smishing ─────────────────────────────
    "C003": [
        _q("complainant_name", "Full name of the complainant?"),
        _q("complainant_email", "Complainant's email address?", "email"),
        _q("phishing_vector", "Phishing attack vector?", "choice",
           options=["Email", "SMS", "WhatsApp", "Voice Call", "Fake Website"]),
        _q("sender_email_or_number", "Sender's email address or phone number?"),
        _q("spoofed_entity", "Which entity was spoofed (bank, govt, etc.)?"),
        _q("phishing_url", "Phishing URL (if available)?", "url", required=False),
        _q("data_compromised", "What data was compromised?", "choice",
           options=["Password", "Card Details", "OTP", "Aadhaar",
                    "PAN", "Bank Credentials", "Other"]),
        _q("financial_loss", "Financial loss amount (₹)?", "number",
           required=False, helpline_trigger=True),
        _q("date_of_attack", "Date of the phishing attack?", "date"),
        _q("email_headers_available", "Are email headers available?", "yesno",
           required=False),
    ],

    # ── C004 — Social Media Crime ─────────────────────────────────────────
    "C004": [
        _q("complainant_name", "Full name of the complainant?"),
        _q("complainant_phone", "Complainant's phone number?", "phone"),
        _q("platform", "Social media platform involved?", "choice",
           options=["Instagram", "Facebook", "WhatsApp", "Twitter-X",
                    "Telegram", "YouTube", "Other"]),
        _q("victim_profile_url", "Victim's profile URL?", "url", required=False),
        _q("suspect_profile_url", "Suspect's profile URL?", "url", required=False),
        _q("crime_subtype", "Type of social media crime?", "choice",
           options=["Account Hack", "Fake Profile", "Morphed Images",
                    "Sextortion", "Defamation", "Other"]),
        _q("content_type", "Type of content involved?", "choice",
           options=["Image", "Video", "Text", "Multiple"]),
        _q("content_circulated_publicly",
           "Was the content circulated publicly?", "yesno"),
        _q("victim_is_minor", "Is the victim a minor (below 18)?", "yesno",
           pocso_trigger=True),
        _q("threatening_messages",
           "Were threatening messages received?", "yesno"),
        _q("financial_demand", "Financial demand amount (₹)?", "number",
           required=False),
    ],

    # ── C005 — Cyberstalking / Online Harassment ──────────────────────────
    "C005": [
        _q("complainant_name", "Full name of the complainant?"),
        _q("complainant_phone", "Complainant's phone number?", "phone"),
        _q("suspect_phone_or_username",
           "Suspect's phone number or username?"),
        _q("platforms_used", "Platforms used for harassment (comma-separated)?"),
        _q("harassment_duration",
           "Duration of harassment (e.g., '3 months')?"),
        _q("harassment_type", "Type of harassment?", "choice",
           options=["Threatening Messages", "Doxxing", "Tracking App",
                    "Fake Profile", "Morphed Content",
                    "Coordinated Attack"]),
        _q("know_suspect_personally",
           "Does the complainant know the suspect personally?", "yesno"),
        _q("previous_complaint_filed",
           "Has a previous complaint been filed?", "yesno", required=False),
        _q("victim_is_minor", "Is the victim a minor (below 18)?", "yesno",
           pocso_trigger=True),
        _q("physical_threat_made",
           "Was a physical threat made?", "yesno"),
    ],

    # ── C006 — Ransomware / Malware Attack ────────────────────────────────
    "C006": [
        _q("organization_or_victim",
           "Organization or individual victim name?"),
        _q("contact_phone", "Contact phone number?", "phone"),
        _q("attack_date", "Date of the ransomware attack?", "date"),
        _q("systems_affected_count",
           "Number of systems affected?", "number"),
        _q("attack_vector", "Suspected attack vector?", "choice",
           options=["Phishing Email", "RDP", "USB",
                    "Software Vulnerability", "Unknown"]),
        _q("ransomware_variant",
           "Ransomware variant name (if known)?", required=False),
        _q("ransom_amount",
           "Ransom amount demanded (in currency or crypto)?", required=False),
        _q("crypto_wallet_address",
           "Crypto wallet address for ransom?", required=False),
        _q("data_encrypted", "Was data encrypted?", "yesno"),
        _q("data_exfiltrated", "Was data exfiltrated (stolen)?", "yesno"),
        _q("backup_available", "Are clean backups available?", "yesno"),
        _q("ransom_paid", "Was the ransom paid?", "yesno"),
        _q("c2_server_ip",
           "C2 (Command & Control) server IP address?", required=False),
        _q("malware_hash",
           "Malware file hash (MD5/SHA256)?", required=False),
    ],

    # ── C007 — Hacking / Unauthorized Access ─────────────────────────────
    "C007": [
        _q("complainant_name", "Full name of the complainant?"),
        _q("target_system_url_or_ip",
           "Target system URL or IP address?"),
        _q("intrusion_date", "Date of intrusion?", "date"),
        _q("attack_type", "Type of attack?", "choice",
           options=["Web Defacement", "Data Exfiltration",
                    "Account Takeover", "Credential Theft", "Other"]),
        _q("attack_vector", "Attack vector used?", "choice",
           options=["SQL Injection", "Brute Force", "Phishing",
                    "Zero-Day", "Insider", "Unknown"]),
        _q("data_accessed",
           "What data was accessed (if known)?", required=False),
        _q("logs_available",
           "Are system/server logs available?", "yesno"),
        _q("is_critical_infrastructure",
           "Is this a critical infrastructure system?", "yesno"),
    ],

    # ── C008 — Investment / Trading Scam ──────────────────────────────────
    "C008": [
        _q("complainant_name", "Full name of the complainant?"),
        _q("complainant_phone", "Complainant's phone number?", "phone"),
        _q("platform_name",
           "Name of the investment platform/app?"),
        _q("platform_url", "Platform URL (if available)?", "url",
           required=False),
        _q("contact_method", "How were you contacted?", "choice",
           options=["WhatsApp Group", "Telegram", "App",
                    "Website", "Other"]),
        _q("total_invested", "Total amount invested (₹)?", "number",
           pmla_trigger=True, helpline_trigger=True),
        _q("promised_returns",
           "Promised returns (e.g., '30% monthly')?", required=False),
        _q("withdrawal_refused",
           "Was withdrawal refused?", "yesno"),
        _q("refusal_date", "Date when withdrawal was refused?", "date",
           required=False),
        _q("apk_file_used",
           "Was a custom APK file required to install?", "yesno",
           required=False),
        _q("telegram_group_link",
           "Telegram group link (if any)?", "url", required=False),
    ],

    # ── C009 — Data Breach / Privacy Violation ────────────────────────────
    "C009": [
        _q("organization_name", "Organization name?"),
        _q("contact_phone", "Contact phone number?", "phone"),
        _q("data_type_breached", "Type of data breached?", "choice",
           options=["Personal Data", "Financial Data", "Health Records",
                    "Credentials", "Source Code", "Other"]),
        _q("records_affected",
           "Number of records affected?", "number", required=False),
        _q("breach_discovery_date",
           "Date the breach was discovered?", "date"),
        _q("breach_source", "Source of the breach?", "choice",
           options=["Cloud Misconfiguration", "Insider", "Hacking",
                    "Third Party", "Unknown"]),
        _q("dark_web_posting_url",
           "Dark web posting URL (if known)?", "url", required=False),
        _q("is_government_data",
           "Is government data involved?", "yesno"),
    ],

    # ── C010 — Cyber Defamation / Fake News ───────────────────────────────
    "C010": [
        _q("complainant_name", "Full name of the complainant?"),
        _q("complainant_phone", "Complainant's phone number?", "phone"),
        _q("defamatory_url", "URL of the defamatory content?", "url"),
        _q("content_type", "Type of defamatory content?", "choice",
           options=["Text Article", "Morphed Image", "Deepfake Video",
                    "Fake Profile", "Other"]),
        _q("platform",
           "Platform where content was posted?"),
        _q("estimated_views",
           "Estimated views/reach?", "number", required=False),
        _q("responsible_account_id",
           "Account ID of the responsible person?", required=False),
        _q("content_archived",
           "Has the content been archived/screenshotted?", "yesno",
           required=False),
    ],

    # ── C011 — CSAM / POCSO Digital Offence ───────────────────────────────
    "C011": [
        _q("reporting_source", "Reporting source?", "choice",
           options=["Victim Complaint", "NCMEC Tip", "Suo Motu",
                    "INTERPOL", "Other"]),
        _q("platform_or_app",
           "Platform or app where content was found?"),
        _q("victim_age_known",
           "Is the victim's age known?", "yesno", pocso_trigger=True),
        _q("victim_age", "Victim's age?", "number", required=False),
        _q("content_type", "Type of content?", "choice",
           options=["Image", "Video", "Live Stream",
                    "Chat Grooming", "Other"]),
        _q("content_distributed",
           "Was the content distributed/shared?", "yesno"),
        _q("suspect_account_id",
           "Suspect's account ID or username?", required=False),
        _q("physical_meeting_arranged",
           "Was a physical meeting arranged with the minor?", "yesno"),
    ],

    # ── C012 — Job Fraud ──────────────────────────────────────────────────
    "C012": [
        _q("complainant_name", "Full name of the complainant?"),
        _q("complainant_phone", "Complainant's phone number?", "phone"),
        _q("job_portal_or_source",
           "Job portal or source (e.g., LinkedIn, Naukri, WhatsApp)?"),
        _q("fake_company_name", "Name of the fake company?"),
        _q("contact_phone_or_email",
           "Contact phone number or email of the fraudster?"),
        _q("job_position_offered",
           "Job position offered?", required=False),
        _q("amount_paid", "Amount paid (₹)?", "number",
           pmla_trigger=True, helpline_trigger=True),
        _q("payment_method", "Payment method used?", "choice",
           options=["UPI", "Bank Transfer", "Other"]),
        _q("transaction_details", "Transaction ID / details?"),
        _q("fake_website_url",
           "Fake website URL (if any)?", "url", required=False),
        _q("documents_received",
           "Were any fake appointment letters/documents received?",
           "yesno", required=False),
    ],
}

# ══════════════════════════════════════════════════════════════════════════════
#  INPUT VALIDATORS
# ══════════════════════════════════════════════════════════════════════════════

def _validate_phone(value):
    """Validate 10-digit Indian phone number (with optional +91 / 0 prefix)."""
    cleaned = re.sub(r"[\s\-\(\)]", "", value)
    cleaned = re.sub(r"^(\+91|91|0)", "", cleaned)
    if re.fullmatch(r"\d{10}", cleaned):
        return cleaned
    return None


def _validate_email(value):
    """Basic email format validation."""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if re.fullmatch(pattern, value):
        return value
    return None


def _validate_number(value):
    """Validate numeric input (int or float)."""
    try:
        return float(value) if "." in value else int(value)
    except ValueError:
        return None


def _validate_url(value):
    """Basic URL format validation."""
    pattern = r"^https?://[^\s]+$"
    if re.fullmatch(pattern, value, re.IGNORECASE):
        return value
    # Accept without protocol — prepend https://
    if re.fullmatch(r"[a-zA-Z0-9][^\s]*\.[a-zA-Z]{2,}[^\s]*", value):
        return "https://" + value
    return None


def _validate_date(value):
    """Validate date in DD-MM-YYYY or DD/MM/YYYY format."""
    for fmt in ("%d-%m-%Y", "%d/%m/%Y", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(value, fmt)
            return dt.strftime("%Y-%m-%d")
        except ValueError:
            continue
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  QUESTIONNAIRE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def run_questionnaire(crime_type_code):
    """
    Run the dynamic questionnaire for the given crime type code.

    Args:
        crime_type_code: One of C001–C012.

    Returns:
        dict with keys:
            "answers"  — dict of field_id → value
            "flags"    — dict of triggered flags (pmla, pocso, helpline)
    """
    questions = CRIME_QUESTIONS.get(crime_type_code)
    if not questions:
        print(f"{Fore.RED}✗ Unknown crime type: {crime_type_code}{Style.RESET_ALL}")
        return None

    crime_name = CRIME_TYPES[crime_type_code]
    print(f"\n{Fore.WHITE}{'═' * 60}")
    print(f"  📋  Questionnaire: {crime_name}")
    print(f"{'═' * 60}{Style.RESET_ALL}\n")

    answers = {}
    flags = {"pmla": False, "pocso": False, "helpline": False}
    total = len(questions)

    for idx, q in enumerate(questions, 1):
        qid = q["id"]
        required = q["required"]
        qtype = q["type"]
        req_tag = f"{Fore.RED}*{Style.RESET_ALL}" if required else f"{Fore.YELLOW}(optional){Style.RESET_ALL}"

        # ── Print question ────────────────────────────────────────────
        print(f"{Fore.CYAN}[{idx}/{total}] {q['question']} {req_tag}{Style.RESET_ALL}")

        # ── Handle choice type ────────────────────────────────────────
        if qtype == "choice":
            options = q.get("options", [])
            for i, opt in enumerate(options, 1):
                print(f"  {Fore.WHITE}{i}. {opt}{Style.RESET_ALL}")

        # ── Handle yesno type ─────────────────────────────────────────
        if qtype == "yesno":
            print(f"  {Fore.WHITE}(y/n){Style.RESET_ALL}")

        # ── Input loop with validation ────────────────────────────────
        while True:
            raw = input(f"  {Fore.GREEN}➤ {Style.RESET_ALL}").strip()

            # Skip optional fields on empty input
            if not raw and not required:
                answers[qid] = ""
                break

            # Require input for required fields
            if not raw and required:
                print(f"  {Fore.RED}✗ This field is required.{Style.RESET_ALL}")
                continue

            # ── Validate by type ──────────────────────────────────────
            if qtype == "phone":
                validated = _validate_phone(raw)
                if validated is None:
                    print(f"  {Fore.RED}✗ Invalid phone number. Enter 10-digit Indian number.{Style.RESET_ALL}")
                    continue
                answers[qid] = validated
                break

            elif qtype == "email":
                validated = _validate_email(raw)
                if validated is None:
                    print(f"  {Fore.RED}✗ Invalid email format.{Style.RESET_ALL}")
                    continue
                answers[qid] = validated
                break

            elif qtype == "number":
                validated = _validate_number(raw)
                if validated is None:
                    print(f"  {Fore.RED}✗ Please enter a valid number.{Style.RESET_ALL}")
                    continue
                answers[qid] = validated

                # ── PMLA trigger check ────────────────────────────────
                if q.get("pmla_trigger") and validated > 300000:
                    flags["pmla"] = True

                # ── Helpline trigger check ────────────────────────────
                if q.get("helpline_trigger") and validated > 0:
                    flags["helpline"] = True

                break

            elif qtype == "url":
                validated = _validate_url(raw)
                if validated is None:
                    print(f"  {Fore.RED}✗ Invalid URL. Include http:// or https://{Style.RESET_ALL}")
                    continue
                answers[qid] = validated
                break

            elif qtype == "date":
                validated = _validate_date(raw)
                if validated is None:
                    print(f"  {Fore.RED}✗ Invalid date. Use DD-MM-YYYY or DD/MM/YYYY format.{Style.RESET_ALL}")
                    continue
                answers[qid] = validated
                break

            elif qtype == "choice":
                options = q.get("options", [])
                try:
                    choice_idx = int(raw) - 1
                    if 0 <= choice_idx < len(options):
                        answers[qid] = options[choice_idx]
                        break
                    else:
                        print(f"  {Fore.RED}✗ Choose between 1 and {len(options)}.{Style.RESET_ALL}")
                except ValueError:
                    # Allow typing the option text directly
                    if raw in options:
                        answers[qid] = raw
                        break
                    print(f"  {Fore.RED}✗ Enter a number (1–{len(options)}) or the option text.{Style.RESET_ALL}")

            elif qtype == "yesno":
                if raw.lower() in ("y", "yes"):
                    answers[qid] = "yes"
                    # ── POCSO trigger ─────────────────────────────────
                    if q.get("pocso_trigger"):
                        flags["pocso"] = True
                    break
                elif raw.lower() in ("n", "no"):
                    answers[qid] = "no"
                    break
                else:
                    print(f"  {Fore.RED}✗ Please enter y or n.{Style.RESET_ALL}")

            else:
                # text type — no validation needed
                answers[qid] = raw
                break

        print()  # spacing between questions

    # ── C011 (CSAM) — ALWAYS flag POCSO regardless of input ───────────────
    if crime_type_code == "C011":
        flags["pocso"] = True

    # ── Print triggered flags ─────────────────────────────────────────────
    print(f"\n{Fore.WHITE}{'─' * 60}")
    print(f"  🔍  Legal Trigger Analysis")
    print(f"{'─' * 60}{Style.RESET_ALL}\n")

    if flags["pmla"]:
        print(f"  {Fore.RED}⚠️  PMLA FLAG: Amount exceeds ₹3,00,000 — "
              f"PMLA sections may apply{Style.RESET_ALL}")

    if flags["helpline"]:
        print(f"  {Fore.RED}🚨 1930 ALERT: Advise complainant to call "
              f"1930 immediately for fund freeze!{Style.RESET_ALL}")

    if flags["pocso"]:
        print(f"  {Fore.RED}🔴 POCSO FLAG: Victim is a minor — "
              f"POCSO sections are MANDATORY{Style.RESET_ALL}")

    if not any(flags.values()):
        print(f"  {Fore.GREEN}✓ No special legal triggers detected.{Style.RESET_ALL}")

    print()

    return {
        "answers": answers,
        "flags": flags,
    }
