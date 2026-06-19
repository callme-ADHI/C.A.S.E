#!/usr/bin/env python3
"""
C.A.S.E. — Cyber Attack Scene Examiner
OSINT Runner — Day 2

CLI tool that loads a case from the database, runs OSINT analysis
on all extracted IOCs, and updates the database with results.

Usage:
    python osint_runner.py <case_number>
    python osint_runner.py KL-CYB-2025-0001

Built for Kerala Police Cyber Cell.
"""

import json
import sqlite3
import sys
from datetime import datetime

from colorama import init, Fore, Back, Style

from config.config import DB_PATH, APP_NAME, VERSION, JURISDICTION
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
  ║  {Fore.CYAN}OSINT Engine{Fore.WHITE} — Day 2                            ║
  ║  IP · URL · Domain · Hash Analysis              ║
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

    Uses the highest value between:
      - AbuseIPDB abuse_score
      - VirusTotal malicious_count × 10
    """
    scores = []

    for r in osint_result.get("results", []):
        if "error" in r:
            continue

        source = r.get("source", "")

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

    return max(scores) if scores else 0


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
    if "error" in r:
        print(f"  {Fore.YELLOW}⚠️  VirusTotal lookup failed: "
              f"{r['error']}{Style.RESET_ALL}")
        return

    malicious = r.get("malicious_count", 0)
    total = r.get("total_engines", 0)
    ioc_type = r.get("ioc_type", "")

    # ── Verdict line ──────────────────────────────────────────────────────
    if malicious >= 5:
        print(f"  {Fore.RED}🔴 MALICIOUS — {malicious}/{total} engines "
              f"flagged{Style.RESET_ALL}")
    elif malicious >= 1:
        print(f"  {Fore.YELLOW}🟡 SUSPICIOUS — {malicious}/{total} engines "
              f"flagged{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}🟢 CLEAN — 0/{total} engines "
              f"flagged{Style.RESET_ALL}")

    # ── Detail lines ──────────────────────────────────────────────────────
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
    if "error" in r:
        print(f"  {Fore.YELLOW}⚠️  AbuseIPDB lookup failed: "
              f"{r['error']}{Style.RESET_ALL}")
        return

    abuse_score = r.get("abuse_score", 0)
    risk = r.get("risk_level", "LOW")

    # ── Verdict line ──────────────────────────────────────────────────────
    if abuse_score >= 75:
        print(f"  {Fore.RED}🔴 HIGH RISK — Abuse confidence: "
              f"{abuse_score}%{Style.RESET_ALL}")
    elif abuse_score >= 25:
        print(f"  {Fore.YELLOW}🟡 MEDIUM RISK — Abuse confidence: "
              f"{abuse_score}%{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}🟢 LOW RISK — Abuse confidence: "
              f"{abuse_score}%{Style.RESET_ALL}")

    # ── Special flags ─────────────────────────────────────────────────────
    if r.get("is_tor"):
        print(f"  {Fore.RED}⚠️  TOR EXIT NODE DETECTED{Style.RESET_ALL}")
    if r.get("is_vpn"):
        print(f"  {Fore.YELLOW}⚠️  VPN DETECTED{Style.RESET_ALL}")

    # ── Detail lines ──────────────────────────────────────────────────────
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
    if "error" in r:
        print(f"  {Fore.YELLOW}⚠️  IPInfo lookup failed: "
              f"{r['error']}{Style.RESET_ALL}")
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
    if "error" in r:
        print(f"  {Fore.YELLOW}⚠️  PhishTank lookup failed: "
              f"{r['error']}{Style.RESET_ALL}")
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
    if "error" in r:
        print(f"  {Fore.YELLOW}⚠️  URLScan lookup failed: "
              f"{r['error']}{Style.RESET_ALL}")
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


def print_skip_message(ioc_type, ioc_value):
    """Print a skip message for Day 3 IOC types."""
    messages = {
        "phone": f"⏭  Phone OSINT queued for Day 3 "
                 f"(Truecaller + DOT FRI)",
        "email": f"⏭  Email OSINT queued for Day 3 "
                 f"(HIBP + Holehe + Sherlock)",
        "upi_id": f"⏭  UPI OSINT queued for Day 3 "
                  f"(NPCI trace)",
        "wallet": f"⏭  Wallet tracing queued for Day 3 "
                  f"(blockchain explorer)",
    }
    msg = messages.get(ioc_type, f"⏭  {ioc_type} queued for Day 3")
    print(f"  {Fore.CYAN}{msg}{Style.RESET_ALL}")


def print_osint_results(osint_result):
    """
    Route each sub-result to the correct display function
    based on its source.
    """
    results = osint_result.get("results", [])

    if osint_result.get("note") and not results:
        # Day 3 skip or private IP
        return

    for r in results:
        source = r.get("source", "")
        print()  # spacing

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
        else:
            if "error" in r:
                print(f"  {Fore.YELLOW}⚠️  {source} lookup failed: "
                      f"{r['error']}{Style.RESET_ALL}")


def print_case_summary(case_number, total, malicious_count,
                       clean_count, skipped_count, threat_level,
                       overall_score):
    """Print the final case threat summary."""
    # ── Colour for threat level ───────────────────────────────────────────
    if threat_level == "HIGH":
        level_color = Fore.RED
    elif threat_level == "MEDIUM":
        level_color = Fore.YELLOW
    else:
        level_color = Fore.GREEN

    # ── Recommended action ────────────────────────────────────────────────
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
                  "Continue with standard investigation protocol. "
                  "Day 3 identity OSINT may reveal more.")

    print(f"\n\n{Fore.WHITE}{'═' * 60}")
    print(f"  📊  CASE THREAT SUMMARY — {Fore.CYAN}{case_number}{Fore.WHITE}")
    print(f"{'─' * 60}")
    print(f"  Total IOCs analysed   : {Fore.CYAN}{total}{Fore.WHITE}")
    print(f"  Malicious flagged     : {Fore.RED}{malicious_count}{Fore.WHITE}")
    print(f"  Clean                 : {Fore.GREEN}{clean_count}{Fore.WHITE}")
    print(f"  Skipped (Day 3)       : {Fore.YELLOW}{skipped_count}{Fore.WHITE}")
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

    # ── Parse arguments ───────────────────────────────────────────────────
    if len(sys.argv) < 2:
        print(f"  {Fore.RED}✗ Usage: python osint_runner.py "
              f"<case_number>{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}  Example: python osint_runner.py "
              f"KL-CYB-2025-0001{Style.RESET_ALL}\n")
        sys.exit(1)

    case_number = sys.argv[1].strip()

    # ── Load case ─────────────────────────────────────────────────────────
    print(f"  {Fore.WHITE}Loading case: {Fore.CYAN}{case_number}"
          f"{Style.RESET_ALL}...")

    case = load_case(case_number)
    if not case:
        print(f"  {Fore.RED}✗ Case not found: {case_number}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}  Run 'python main.py' to create a case "
              f"first.{Style.RESET_ALL}\n")
        sys.exit(1)

    # ── Load IOCs ─────────────────────────────────────────────────────────
    case_id = case["id"]
    iocs = load_iocs(case_id)

    if not iocs:
        print(f"  {Fore.YELLOW}⚠  No IOCs found for this case."
              f"{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}  The questionnaire did not extract any "
              f"IOCs.{Style.RESET_ALL}\n")
        sys.exit(0)

    # ── Print case header ─────────────────────────────────────────────────
    print_case_header(case, len(iocs))

    # ── Check if there are any IP/URL/domain/hash IOCs ────────────────────
    osint_types = {"ip", "url", "domain", "hash"}
    has_osint_iocs = any(ioc["ioc_type"] in osint_types for ioc in iocs)

    if not has_osint_iocs:
        print(f"  {Fore.CYAN}ℹ  No IP/URL/domain IOCs found. Day 3 will "
              f"handle")
        print(f"     phone/email/identity OSINT for this case."
              f"{Style.RESET_ALL}\n")

    # ── Process each IOC ──────────────────────────────────────────────────
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

        # ── Skip Day 3 IOC types ─────────────────────────────────────────
        if ioc_type in ("phone", "email", "upi_id", "wallet"):
            print_skip_message(ioc_type, ioc_value)
            skipped_count += 1
            continue

        # ── Run OSINT ─────────────────────────────────────────────────────
        osint_result = run_osint(ioc_type, ioc_value)

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

    if malicious_count > 0 or overall_score >= 50:
        threat_level = "HIGH"
    elif overall_score >= 20 or any(s >= 20 for s in all_scores):
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    # ── Update case threat score ──────────────────────────────────────────
    update_case_threat_score(case_number, overall_score)

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
