#!/usr/bin/env python3
"""
C.A.S.E. — Cyber Attack Scene Examiner
OSINT Runner — Day 3

CLI tool that loads a case from the database, runs OSINT analysis
on all extracted IOCs, and updates the database with results.
Enriched with Day 3 modules for Identity, Breach, and Dark Web OSINT.

Usage:
    python osint_runner.py <case_number>
    python osint_runner.py KL-CYB-2025-0001

Built for Kerala Police Cyber Cell.
"""

import json
import os
import sqlite3
import sys
from datetime import datetime

from colorama import init, Fore, Back, Style

from config.config import DB_PATH, APP_NAME, VERSION, JURISDICTION, OUTPUTS_DIR
from modules.osint_engine import run_osint

# ── Initialize colorama ───────────────────────────────────────────────────────
init(autoreset=False)


# ══════════════════════════════════════════════════════════════════════════════
#  OSINT BANNER
# ══════════════════════════════════════════════════════════════════════════════

OSINT_BANNER = rf"""
{Fore.CYAN}
   ██████╗    █████╗   ███████╗  ███████╗
  ██╔════╝   ██╔══██╗  ██╔════╝  ██╔════╝
  ██║        ███████║  ███████╗  █████╗  
  ██║        ██╔══██║  ╚════██║  ██╔══╝  
  ╚██████╗   ██║  ██║  ███████║  ███████╗
   ╚═════╝   ╚═╝  ╚═╝  ╚══════╝  ╚══════╝
{Style.RESET_ALL}
{Fore.WHITE}  ╔══════════════════════════════════════════════════╗
  ║  {Fore.CYAN}OSINT Engine{Fore.WHITE} — Day 3                            ║
  ║  Identity, Breach & Dark Web Analysis            ║
  ║  {JURISDICTION:<44s}  ║
  ╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
"""


# ══════════════════════════════════════════════════════════════════════════════
#  DATABASE HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def load_case(case_number):
    """Load a case record from the database by case number."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM cases WHERE case_number = ?",
                   (case_number,))
    case = cursor.fetchone()
    conn.close()

    return dict(case) if case else None


def load_iocs(case_id):
    """Load all IOCs for a given case ID."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM iocs WHERE case_id = ?", (case_id,))
    iocs = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return iocs


def update_ioc_malicious(ioc_id):
    """Mark an IOC as malicious in the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE iocs SET is_malicious = 1 WHERE id = ?",
                   (ioc_id,))
    conn.commit()
    conn.close()


def save_suspect(case_id, identifier, identifier_type,
                 osint_data, threat_score):
    """Save OSINT results to the suspects table."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO suspects (case_id, identifier, identifier_type,
                              osint_data, threat_score)
        VALUES (?, ?, ?, ?, ?)
    """, (case_id, identifier, identifier_type,
          json.dumps(osint_data, ensure_ascii=False, default=str),
          threat_score))
    conn.commit()
    conn.close()


def update_case_threat_score(case_number, score):
    """Update the overall threat score for a case."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE cases SET threat_score = ? WHERE case_number = ?",
                   (score, case_number))
    conn.commit()
    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
#  THREAT SCORE CALCULATOR
# ══════════════════════════════════════════════════════════════════════════════

def calculate_threat_score(osint_result):
    """
    Calculate a threat score (0–100) from OSINT results.
    """
    scores = []

    for r in osint_result.get("results", []):
        if not r or (r.get("error") is not None and r.get("error") != "no_api_key"):
            continue

        source = r.get("source", "")

        # Day 2 Sources
        if source == "abuseipdb":
            scores.append(r.get("abuse_score", 0))

        elif source == "virustotal":
            vt_score = r.get("malicious_count", 0) * 10
            scores.append(min(vt_score, 100))  # cap at 100

        elif source == "phishtank":
            if r.get("is_phishing", False):
                scores.append(90)

        elif source == "urlscan":
            if r.get("verdict_malicious", False):
                scores.append(85)
            else:
                scores.append(r.get("verdict_score", 0))

        # Day 3 Sources
        elif source == "haveibeenpwned":
            if r.get("is_breached", False):
                scores.append(min(r.get("breach_count", 0) * 20, 60))

        elif source == "domain_age_check":
            if r.get("is_disposable_domain", False):
                scores.append(85)
            elif r.get("is_newly_registered", False):
                scores.append(60)

        elif source == "username_presence":
            if r.get("platforms_found"):
                scores.append(min(len(r.get("platforms_found")) * 10, 30))

        elif source == "phone_osint":
            if r.get("is_repeat_offender_number", False):
                scores.append(95)
            elif not r.get("is_valid_format", True):
                scores.append(30)

        elif source == "cross_case_linker":
            if r.get("is_repeat_pattern", False):
                scores.append(95)

    return max(scores) if scores else 0


# ══════════════════════════════════════════════════════════════════════════════
#  UNIFIED OSINT CARD BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def build_osint_card(case_id):
    """
    Build a unified OSINT card for the case and save it to the outputs directory.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Load case number and metadata
    cursor.execute("SELECT case_number, crime_name FROM cases WHERE id = ?", (case_id,))
    case_row = cursor.fetchone()
    if not case_row:
        conn.close()
        return None

    case_number = case_row["case_number"]
    crime_name = case_row["crime_name"]

    # Load suspect entries
    cursor.execute("SELECT * FROM suspects WHERE case_id = ?", (case_id,))
    suspect_rows = cursor.fetchall()
    conn.close()

    entities = []
    overall_scores = []
    repeat_offender_flags = set()
    recommended_next_steps = []

    for row in suspect_rows:
        try:
            osint_data = json.loads(row["osint_data"])
        except Exception:
            osint_data = {}

        threat_score = row["threat_score"]
        overall_scores.append(threat_score)

        entity = {
            "identifier": row["identifier"],
            "identifier_type": row["identifier_type"],
            "osint_data": osint_data,
            "threat_score": threat_score
        }
        entities.append(entity)

        # Extract cross-case linkages
        for r in osint_data.get("results", []):
            if not r:
                continue
            source = r.get("source", "")
            if source in ("phone_osint", "cross_case_linker"):
                for lc in r.get("linked_cases", []):
                    case_num = lc.get("case_number")
                    if case_num:
                        repeat_offender_flags.add(case_num)

        # Generate recommended next steps
        ident = row["identifier"]
        itype = row["identifier_type"]

        if itype == "phone":
            phone_data = {}
            for r in osint_data.get("results", []):
                if r and r.get("source") == "phone_osint":
                    phone_data = r
                    break
            
            if phone_data.get("is_repeat_offender_number"):
                linked_cases_str = ", ".join([lc["case_number"] for lc in phone_data.get("linked_cases", [])])
                recommended_next_steps.append(
                    f"Cross-reference suspect phone +91{ident} with linked cases: {linked_cases_str}"
                )
            
            if phone_data.get("is_valid_format"):
                recommended_next_steps.append(
                    f"Request subscriber details and Call Detail Records (CDR) for +91{ident} from telecom service providers"
                )
            else:
                recommended_next_steps.append(
                    f"Flag phone number {ident} for verification (invalid Indian 10-digit mobile format)"
                )

        elif itype == "email":
            hibp_data = {}
            domain_data = {}
            username_data = {}
            for r in osint_data.get("results", []):
                if not r:
                    continue
                src = r.get("source")
                if src == "haveibeenpwned":
                    hibp_data = r
                elif src == "domain_age_check":
                    domain_data = r
                elif src == "username_presence":
                    username_data = r

            if domain_data.get("is_disposable_domain"):
                recommended_next_steps.append(
                    f"Submit legal notices to disposable mail provider ({domain_data.get('domain')}) to trace creator of {ident}"
                )
            elif domain_data.get("is_newly_registered"):
                recommended_next_steps.append(
                    f"Query WHOIS/RDAP and send hosting provider preservation request for newly registered domain {domain_data.get('domain')}"
                )

            if hibp_data.get("is_breached"):
                breaches_str = ", ".join(hibp_data.get("breaches", [])[:3])
                recommended_next_steps.append(
                    f"Trace email {ident} breach footprint (leaked in: {breaches_str}); request account access logs from email provider"
                )

            if username_data.get("platforms_found"):
                platforms_str = ", ".join(username_data.get("platforms_found"))
                recommended_next_steps.append(
                    f"Preserve profiles and issue Section 91 BNSS notice to platforms for username '{username_data.get('username')}': {platforms_str}"
                )

        elif itype == "upi_id":
            upi_data = {}
            for r in osint_data.get("results", []):
                if r and r.get("source") == "cross_case_linker":
                    upi_data = r
                    break
            
            if upi_data.get("is_repeat_pattern"):
                linked_cases_str = ", ".join([lc["case_number"] for lc in upi_data.get("linked_cases", [])])
                recommended_next_steps.append(
                    f"Cross-reference suspect UPI ID {ident} with linked cases: {linked_cases_str}"
                )
            
            recommended_next_steps.append(
                f"Issue Section 91 BNSS notice to the merchant/acquiring bank for UPI ID {ident} to freeze account, reverse funds, and retrieve KYC details"
            )

        elif itype == "wallet":
            wallet_data = {}
            for r in osint_data.get("results", []):
                if r and r.get("source") == "cross_case_linker":
                    wallet_data = r
                    break
            
            if wallet_data.get("is_repeat_pattern"):
                linked_cases_str = ", ".join([lc["case_number"] for lc in wallet_data.get("linked_cases", [])])
                recommended_next_steps.append(
                    f"Cross-reference suspect Crypto Wallet {ident} with linked cases: {linked_cases_str}"
                )
            
            recommended_next_steps.append(
                f"Track blockchain transactions for wallet {ident} using analytics and submit disclosure notices to cryptocurrency exchanges"
            )

        elif itype == "ip":
            recommended_next_steps.append(
                f"Request connection logs, port mapping, and subscriber details from the ISP for IP address {ident}"
            )
        
        elif itype == "url":
            recommended_next_steps.append(
                f"Submit takedown request for phishing/malicious URL {ident} to the registrar and notify CERT-In"
            )
        
        elif itype == "hash":
            recommended_next_steps.append(
                f"Perform digital forensic sweep on suspect endpoints to locate file matching MD5/SHA256 hash {ident}"
            )

    # Determine overall threat level
    max_score = max(overall_scores) if overall_scores else 0
    if max_score >= 50 or len(repeat_offender_flags) > 0:
        overall_threat_level = "HIGH"
    elif max_score >= 20:
        overall_threat_level = "MEDIUM"
    else:
        overall_threat_level = "LOW"

    # Deduplicate recommended next steps
    seen_steps = set()
    dedup_steps = []
    for step in recommended_next_steps:
        if step not in seen_steps:
            seen_steps.add(step)
            dedup_steps.append(step)

    # If empty, add standard step
    if not dedup_steps:
        dedup_steps.append("No immediate threat indicators found; proceed with regular investigative steps.")

    card = {
        "case_number": case_number,
        "crime_name": crime_name,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "entities": entities,
        "overall_threat_level": overall_threat_level,
        "overall_threat_score": max_score,
        "repeat_offender_flags": list(repeat_offender_flags),
        "recommended_next_steps": dedup_steps
    }

    # Ensure outputs directory exists
    os.makedirs(OUTPUTS_DIR, exist_ok=True)
    card_filename = f"osint_card_{case_number}.json"
    card_path = os.path.join(OUTPUTS_DIR, card_filename)

    with open(card_path, "w", encoding="utf-8") as f:
        json.dump(card, f, indent=2, ensure_ascii=False)

    return card_path


# ══════════════════════════════════════════════════════════════════════════════
#  DISPLAY FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def print_case_header(case, ioc_count):
    """Print the case analysis header."""
    print(f"\n{Fore.WHITE}{'═' * 60}")
    print(f"  🔍  OSINT ANALYSIS — {Fore.CYAN}{case['case_number']}{Fore.WHITE}")
    print(f"{'─' * 60}")
    print(f"  Crime   : {Fore.CYAN}[{case['crime_code']}] {case['crime_name']}{Fore.WHITE}")
    print(f"  Officer : {Fore.CYAN}{case['officer_name']}{Fore.WHITE}")
    print(f"  Filed   : {Fore.CYAN}{case['date_filed']}{Fore.WHITE}")
    print(f"  IOCs    : {Fore.CYAN}{ioc_count}{Fore.WHITE}")
    print(f"{'═' * 60}{Style.RESET_ALL}\n")


def print_ioc_header(idx, total, ioc_type, ioc_value):
    """Print a header for the IOC being analysed."""
    print(f"\n{Fore.WHITE}{'─' * 60}")
    print(f"  [{idx}/{total}] Analysing {Fore.YELLOW}{ioc_type}{Fore.WHITE}: "
          f"{Fore.CYAN}{ioc_value}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{'─' * 60}{Style.RESET_ALL}")


def print_vt_results(r):
    """Print VirusTotal results with color coding."""
    if not r or r.get("error"):
        print(f"  {Fore.YELLOW}⚠️  VirusTotal lookup failed: "
              f"{r.get('error') if r else 'No data'}{Style.RESET_ALL}")
        return

    malicious = r.get("malicious_count", 0)
    total = r.get("total_engines", 0)
    ioc_type = r.get("ioc_type", "")

    if malicious >= 5:
        print(f"  {Fore.RED}🔴 MALICIOUS — {malicious}/{total} engines "
              f"flagged{Style.RESET_ALL}")
    elif malicious >= 1:
        print(f"  {Fore.YELLOW}🟡 SUSPICIOUS — {malicious}/{total} engines "
              f"flagged{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}🟢 CLEAN — 0/{total} engines "
              f"flagged{Style.RESET_ALL}")

    print(f"  {Fore.WHITE}   Source     : VirusTotal")
    print(f"     Malicious : {malicious}  |  Suspicious: "
          f"{r.get('suspicious_count', 0)}  |  "
          f"Harmless: {r.get('harmless_count', 0)}")
    print(f"     Reputation: {r.get('reputation', 'N/A')}")

    if r.get("threat_label"):
        print(f"     Threat    : {Fore.RED}{r['threat_label']}{Fore.WHITE}")

    if ioc_type == "ip":
        if r.get("country"):
            print(f"     Country   : {r['country']}")
        if r.get("as_owner"):
            print(f"     ASN Owner : {r['as_owner']} (AS{r.get('asn', '')})")

    if r.get("last_analysis_date"):
        print(f"     Last Scan : {r['last_analysis_date']}")

    print(f"     VT Link   : {Fore.CYAN}{r.get('raw_url', '')}"
          f"{Style.RESET_ALL}")


def print_abuseipdb_results(r):
    """Print AbuseIPDB results with color coding."""
    if not r or r.get("error"):
        print(f"  {Fore.YELLOW}⚠️  AbuseIPDB lookup failed: "
              f"{r.get('error') if r else 'No data'}{Style.RESET_ALL}")
        return

    abuse_score = r.get("abuse_score", 0)
    risk = r.get("risk_level", "LOW")

    if abuse_score >= 75:
        print(f"  {Fore.RED}🔴 HIGH RISK — Abuse confidence: "
              f"{abuse_score}%{Style.RESET_ALL}")
    elif abuse_score >= 25:
        print(f"  {Fore.YELLOW}🟡 MEDIUM RISK — Abuse confidence: "
              f"{abuse_score}%{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}🟢 LOW RISK — Abuse confidence: "
              f"{abuse_score}%{Style.RESET_ALL}")

    if r.get("is_tor"):
        print(f"  {Fore.RED}⚠️  TOR EXIT NODE DETECTED{Style.RESET_ALL}")
    if r.get("is_vpn"):
        print(f"  {Fore.YELLOW}⚠️  VPN DETECTED{Style.RESET_ALL}")

    print(f"  {Fore.WHITE}   Source     : AbuseIPDB")
    print(f"     ISP       : {r.get('isp', 'N/A')}")
    print(f"     Usage     : {r.get('usage_type', 'N/A')}")
    print(f"     Country   : {r.get('country_code', 'N/A')}")
    print(f"     Reports   : {r.get('total_reports', 0)} "
          f"(last 90 days)")
    if r.get("last_reported"):
        print(f"     Last Rpt  : {r['last_reported']}")
    print(f"     Risk Level: {risk}{Style.RESET_ALL}")


def print_ipinfo_results(r):
    """Print IPInfo geolocation results."""
    if not r or r.get("error"):
        print(f"  {Fore.YELLOW}⚠️  IPInfo lookup failed: "
              f"{r.get('error') if r else 'No data'}{Style.RESET_ALL}")
        return

    print(f"  {Fore.WHITE}   Source     : IPInfo (Geolocation)")
    print(f"     Location  : {r.get('city', '')}, "
          f"{r.get('region', '')}, "
          f"{r.get('country_name', r.get('country', ''))}")
    print(f"     ISP/Org   : {r.get('org', 'N/A')}")
    print(f"     Timezone  : {r.get('timezone', 'N/A')}")

    if r.get("loc"):
        print(f"     Coords    : {r['loc']}")

    if r.get("is_india"):
        print(f"     {Fore.GREEN}📍 IP is located in India{Style.RESET_ALL}")
    else:
        print(f"     {Fore.YELLOW}📍 IP is located OUTSIDE India"
              f"{Style.RESET_ALL}")

    print(Style.RESET_ALL, end="")


def print_phishtank_results(r):
    """Print PhishTank results with color coding."""
    if not r or r.get("error"):
        print(f"  {Fore.YELLOW}⚠️  PhishTank lookup failed: "
              f"{r.get('error') if r else 'No data'}{Style.RESET_ALL}")
        return

    if r.get("is_phishing"):
        print(f"  {Fore.RED}🎣 CONFIRMED PHISHING URL{Style.RESET_ALL}")
        if r.get("phish_detail_url"):
            print(f"  {Fore.WHITE}   Detail URL : "
                  f"{Fore.CYAN}{r['phish_detail_url']}{Style.RESET_ALL}")
    else:
        if r.get("in_database"):
            print(f"  {Fore.YELLOW}⚠️  URL is in PhishTank DB but "
                  f"not confirmed{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}✓ Not in PhishTank DB{Style.RESET_ALL}")

    print(f"  {Fore.WHITE}   Source     : PhishTank{Style.RESET_ALL}")


def print_urlscan_results(r):
    """Print URLScan.io results."""
    if not r or r.get("error"):
        print(f"  {Fore.YELLOW}⚠️  URLScan lookup failed: "
              f"{r.get('error') if r else 'No data'}{Style.RESET_ALL}")
        return

    if r.get("note") == "scan_still_processing":
        print(f"  {Fore.YELLOW}⏳ URLScan — scan still processing")
        print(f"  {Fore.WHITE}   Check results at: "
              f"{Fore.CYAN}{r.get('result_url', '')}{Style.RESET_ALL}")
        return

    if r.get("verdict_malicious"):
        print(f"  {Fore.RED}🔴 URLScan verdict: MALICIOUS "
              f"(score: {r.get('verdict_score', 0)}){Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}🟢 URLScan verdict: CLEAN "
              f"(score: {r.get('verdict_score', 0)}){Style.RESET_ALL}")

    print(f"  {Fore.WHITE}   Source     : URLScan.io")
    if r.get("page_title"):
        print(f"     Page Title: {r['page_title']}")
    if r.get("page_domain"):
        print(f"     Domain    : {r['page_domain']}")
    if r.get("server_ip"):
        print(f"     Server IP : {r['server_ip']} "
              f"({r.get('server_country', '')})")
    if r.get("technologies"):
        techs = ", ".join(r["technologies"][:5])
        print(f"     Tech Stack: {techs}")
    if r.get("screenshot_url"):
        print(f"     Screenshot: {Fore.CYAN}{r['screenshot_url']}"
              f"{Fore.WHITE}")
    print(f"     Result    : {Fore.CYAN}{r.get('result_url', '')}"
          f"{Style.RESET_ALL}")


def print_hibp_results(r):
    """Print HaveIBeenPwned breach results."""
    if not r:
        return
    
    err = r.get("error")

    if err == "no_api_key":
        print(f"  {Fore.YELLOW}⚠️  HIBP skipped — no API key{Style.RESET_ALL}")
        return
    elif err == "invalid_api_key":
        print(f"  {Fore.YELLOW}⚠️  HIBP lookup failed — invalid API key{Style.RESET_ALL}")
        return
    elif err:
        print(f"  {Fore.YELLOW}⚠️  HIBP lookup failed: {err}{Style.RESET_ALL}")
        return

    if r.get("is_breached"):
        count = r.get("breach_count", 0)
        print(f"  {Fore.RED}🔴 EMAIL FOUND IN {count} BREACHES{Style.RESET_ALL}")
        breaches = ", ".join(r.get("breaches", [])[:5])
        print(f"  {Fore.WHITE}   Source     : HaveIBeenPwned")
        print(f"     Breaches   : {breaches}")
    else:
        print(f"  {Fore.GREEN}🟢 No known breaches{Style.RESET_ALL}")


def print_domain_age_results(r):
    """Print email domain analysis results."""
    if not r:
        return
    
    err = r.get("error")
    if err:
        print(f"  {Fore.YELLOW}⚠️  Email domain check failed: {err}{Style.RESET_ALL}")
        return

    print(f"  {Fore.WHITE}   Source     : Domain Age & Disposable Check")
    domain = r.get("domain", "N/A")
    print(f"     Domain     : {domain}")

    if r.get("is_disposable_domain"):
        print(f"  {Fore.RED}🔴 DISPOSABLE EMAIL DOMAIN DETECTED{Style.RESET_ALL}")
    
    if r.get("is_newly_registered"):
        age = r.get("domain_age_days", "N/A")
        print(f"  {Fore.RED}🔴 Domain registered {age} days ago{Style.RESET_ALL}")
    elif r.get("domain_age_days") is not None:
        print(f"     Domain Age : {r.get('domain_age_days')} days")

    if r.get("domain_created_date"):
        print(f"     Created At : {r.get('domain_created_date')}")
    if r.get("registrar"):
        print(f"     Registrar  : {r.get('registrar')}")


def print_username_results(r):
    """Print username presence check results."""
    if not r:
        return
    
    found = r.get("platforms_found", [])
    if found:
        platforms_str = ", ".join(found)
        print(f"  {Fore.CYAN}🔍 Found on: {platforms_str}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}✓ No social profiles detected (checked major platforms){Style.RESET_ALL}")


def print_phone_results(r):
    """Print phone number OSINT results."""
    if not r:
        return
    
    phone = r.get("phone", "")
    print(f"  {Fore.WHITE}   Source     : Phone OSINT")
    
    if r.get("is_valid_format"):
        print(f"     Format     : Valid Indian Mobile")
    else:
        print(f"  {Fore.YELLOW}⚠️  Format     : Invalid Indian Mobile Format{Style.RESET_ALL}")

    if r.get("is_repeat_offender_number"):
        linked = r.get("linked_cases", [])
        cases = ", ".join([c["case_number"] for c in linked])
        print(f"  {Fore.RED}🚨 REPEAT OFFENDER PATTERN — linked to {len(linked)} other case(s): {cases}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}✓ No prior case linkage found{Style.RESET_ALL}")


def print_upi_wallet_results(r):
    """Print UPI ID or Crypto Wallet cross-case results."""
    if not r:
        return
    
    ioc_type = r.get("ioc_type", "upi_id")
    label = "UPI ID" if ioc_type == "upi_id" else "Wallet Address"
    print(f"  {Fore.WHITE}   Source     : Cross-case Linker ({label})")
    
    if r.get("note"):
        print(f"     Note       : {r.get('note')}")

    if r.get("is_repeat_pattern"):
        linked = r.get("linked_cases", [])
        cases = ", ".join([c["case_number"] for c in linked])
        print(f"  {Fore.RED}🚨 REPEAT OFFENDER PATTERN — linked to {len(linked)} other case(s): {cases}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}✓ No prior case linkage found{Style.RESET_ALL}")


def print_osint_results(osint_result):
    """
    Route each sub-result to the correct display function based on its source.
    """
    results = osint_result.get("results", [])

    if osint_result.get("note") and not results:
        return

    for r in results:
        if not r:
            continue
        source = r.get("source", "")
        print()

        if source == "virustotal":
            print_vt_results(r)
        elif source == "abuseipdb":
            print_abuseipdb_results(r)
        elif source == "ipinfo":
            print_ipinfo_results(r)
        elif source == "phishtank":
            print_phishtank_results(r)
        elif source == "urlscan":
            print_urlscan_results(r)
        elif source == "haveibeenpwned":
            print_hibp_results(r)
        elif source == "domain_age_check":
            print_domain_age_results(r)
        elif source == "username_presence":
            print_username_results(r)
        elif source == "phone_osint":
            print_phone_results(r)
        elif source == "cross_case_linker":
            print_upi_wallet_results(r)
        else:
            if r and r.get("error"):
                print(f"  {Fore.YELLOW}⚠️  {source} lookup failed: {r.get('error')}{Style.RESET_ALL}")


def print_case_summary(case_number, total, malicious_count,
                       clean_count, skipped_count, threat_level,
                       overall_score):
    """Print the final case threat summary."""
    if threat_level == "HIGH":
        level_color = Fore.RED
    elif threat_level == "MEDIUM":
        level_color = Fore.YELLOW
    else:
        level_color = Fore.GREEN

    if threat_level == "HIGH":
        action = ("Immediate investigation required. "
                  "Escalate to senior officer. "
                  "Preserve all digital evidence.")
    elif threat_level == "MEDIUM":
        action = ("Further analysis recommended. "
                  "Cross-reference with 1930 Helpline data. "
                  "Monitor suspect IOCs.")
    else:
        action = ("Low risk indicators. "
                  "Continue with standard investigation protocol.")

    print(f"\n\n{Fore.WHITE}{'═' * 60}")
    print(f"  📊  CASE THREAT SUMMARY — {Fore.CYAN}{case_number}{Fore.WHITE}")
    print(f"{'─' * 60}")
    print(f"  Total IOCs analysed   : {Fore.CYAN}{total}{Fore.WHITE}")
    print(f"  Malicious flagged     : {Fore.RED}{malicious_count}{Fore.WHITE}")
    print(f"  Clean                 : {Fore.GREEN}{clean_count}{Fore.WHITE}")
    print(f"  Skipped (Private IPs) : {Fore.YELLOW}{skipped_count}{Fore.WHITE}")
    print(f"{'─' * 60}")
    print(f"  Overall Threat Score  : {level_color}{overall_score}/100{Fore.WHITE}")
    print(f"  Overall Threat Level  : {level_color}■ {threat_level}{Fore.WHITE}")
    print(f"{'─' * 60}")
    print(f"  Recommended action    :")
    print(f"  {level_color}{action}{Fore.WHITE}")
    print(f"{'═' * 60}{Style.RESET_ALL}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN RUNNER
# ══════════════════════════════════════════════════════════════════════════════

def main():
    """Main OSINT runner entry point."""
    print(OSINT_BANNER)

    if len(sys.argv) < 2:
        print(f"  {Fore.RED}✗ Usage: python osint_runner.py "
              f"<case_number>{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}  Example: python osint_runner.py "
              f"KL-CYB-2025-0001{Style.RESET_ALL}\n")
        sys.exit(1)

    case_number = sys.argv[1].strip()

    print(f"  {Fore.WHITE}Loading case: {Fore.CYAN}{case_number}"
          f"{Style.RESET_ALL}...")

    case = load_case(case_number)
    if not case:
        print(f"  {Fore.RED}✗ Case not found: {case_number}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}  Run 'python main.py' to create a case "
              f"first.{Style.RESET_ALL}\n")
        sys.exit(1)

    case_id = case["id"]
    iocs = load_iocs(case_id)

    if not iocs:
        print(f"  {Fore.YELLOW}⚠  No IOCs found for this case."
              f"{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}  The questionnaire did not extract any "
              f"IOCs.{Style.RESET_ALL}\n")
        sys.exit(0)

    print_case_header(case, len(iocs))

    malicious_count = 0
    clean_count = 0
    skipped_count = 0
    all_scores = []

    start_time = datetime.now()

    for idx, ioc in enumerate(iocs, 1):
        ioc_id = ioc["id"]
        ioc_type = ioc["ioc_type"]
        ioc_value = ioc["ioc_value"]

        print_ioc_header(idx, len(iocs), ioc_type, ioc_value)

        # ── Run OSINT ─────────────────────────────────────────────────────
        osint_result = run_osint(ioc_type, ioc_value, current_case_id=case_id)

        # ── Handle private IP skip ────────────────────────────────────────
        if osint_result.get("note") == "private_ip_skipped":
            print(f"  {Fore.CYAN}⏭  Skipping private IP: "
                  f"{ioc_value}{Style.RESET_ALL}")
            skipped_count += 1
            continue

        # ── Print results ─────────────────────────────────────────────────
        print_osint_results(osint_result)

        # ── Calculate threat score ────────────────────────────────────────
        threat_score = calculate_threat_score(osint_result)
        all_scores.append(threat_score)

        # ── Update database ───────────────────────────────────────────────
        is_malicious = osint_result.get("is_malicious", False)

        if is_malicious:
            update_ioc_malicious(ioc_id)
            malicious_count += 1
            print(f"\n  {Fore.RED}⬤  IOC flagged as MALICIOUS — "
                  f"database updated{Style.RESET_ALL}")
        else:
            clean_count += 1
            print(f"\n  {Fore.GREEN}⬤  IOC appears CLEAN{Style.RESET_ALL}")

        # ── Save to suspects table ────────────────────────────────────────
        save_suspect(
            case_id=case_id,
            identifier=ioc_value,
            identifier_type=ioc_type,
            osint_data=osint_result,
            threat_score=threat_score,
        )

    # ── Calculate overall threat level ────────────────────────────────────
    overall_score = max(all_scores) if all_scores else 0

    # Retrieve case linkages to check repeat offenders
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM suspects WHERE case_id = ?", (case_id,))
    suspect_rows = cursor.fetchall()
    conn.close()
    
    repeat_linkages = False
    for row in suspect_rows:
        try:
            data = json.loads(row[3]) # osint_data is index 3 (id, case_id, identifier, identifier_type, osint_data, threat_score, created_at)
        except Exception:
            data = {}
        for r in data.get("results", []):
            if r and r.get("source") in ("phone_osint", "cross_case_linker") and r.get("linked_cases"):
                repeat_linkages = True
                break

    if malicious_count > 0 or overall_score >= 50 or repeat_linkages:
        threat_level = "HIGH"
    elif overall_score >= 20 or any(s >= 20 for s in all_scores):
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    # ── Update case threat score ──────────────────────────────────────────
    update_case_threat_score(case_number, overall_score)

    # ── Build and Save OSINT Card ─────────────────────────────────────────
    card_path = build_osint_card(case_id)
    if card_path:
        print(f"\n  {Fore.GREEN}📄 OSINT Card saved: {card_path}{Style.RESET_ALL}")

    # ── Print summary ─────────────────────────────────────────────────────
    total_processed = malicious_count + clean_count + skipped_count
    print_case_summary(
        case_number, total_processed,
        malicious_count, clean_count, skipped_count,
        threat_level, overall_score,
    )

    # ── Elapsed time ──────────────────────────────────────────────────────
    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"  {Fore.WHITE}Analysis completed in {elapsed:.1f}s")
    print(f"  Results saved to: {DB_PATH}")
    print(f"  {Fore.CYAN}Run 'sqlite3 {DB_PATH}' to inspect "
          f"results.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Fore.YELLOW}⚠  OSINT analysis interrupted. "
              f"Partial results may have been saved.{Style.RESET_ALL}\n")
        sys.exit(0)
