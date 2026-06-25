"""
C.A.S.E. — Cyber Attack Scene Examiner
Report Engine Module

Aggregates OSINT queries for all subject indicators, formats the results,
and outputs a subject report.
"""

import sys
from datetime import datetime, timezone
from colorama import Fore, Style

# Local imports
from modules.osint_engine import run_osint, username_presence_check

# ══════════════════════════════════════════════════════════════════════════════
#  SUB-RESULT DISPLAY PRINTERS (Copied from osint_runner.py)
# ══════════════════════════════════════════════════════════════════════════════

def _print_vt_results(r):
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


def _print_abuseipdb_results(r):
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


def _print_ipinfo_results(r):
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


def _print_phishtank_results(r):
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


def _print_urlscan_results(r):
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


def _print_hibp_results(r):
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


def _print_domain_age_results(r):
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


def _print_username_results(r):
    """Print username presence check results."""
    if not r:
        return
    
    found = r.get("platforms_found", [])
    if found:
        platforms_str = ", ".join(found)
        print(f"  {Fore.CYAN}🔍 Found on: {platforms_str}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}✓ No social profiles detected (checked major platforms){Style.RESET_ALL}")


def _print_phone_results(r):
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


def _print_upi_wallet_results(r):
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


# ══════════════════════════════════════════════════════════════════════════════
#  REPORT ENGINE HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def display_ioc_result(result):
    """
    Displays the formatted sub-results for a single checked IOC.
    """
    ioc_type = result.get("ioc_type")
    ioc_value = result.get("ioc_value")

    print(f"\n{Fore.WHITE}  * {Fore.YELLOW}{ioc_type}{Fore.WHITE}: {Fore.CYAN}{ioc_value}{Style.RESET_ALL}")

    # Check for private IP exception
    if result.get("note") == "private_ip_skipped":
        print(f"    {Fore.YELLOW}ℹ  Skipped — Private IP address{Style.RESET_ALL}")
        return

    sub_results = result.get("results", [])
    if not sub_results:
        print(f"    {Fore.YELLOW}ℹ  No scans or data returned.{Style.RESET_ALL}")
        return

    for r in sub_results:
        if not r:
            continue
        source = r.get("source", "")
        print()

        if source == "virustotal":
            _print_vt_results(r)
        elif source == "abuseipdb":
            _print_abuseipdb_results(r)
        elif source == "ipinfo":
            _print_ipinfo_results(r)
        elif source == "phishtank":
            _print_phishtank_results(r)
        elif source == "urlscan":
            _print_urlscan_results(r)
        elif source == "haveibeenpwned":
            _print_hibp_results(r)
        elif source == "domain_age_check":
            _print_domain_age_results(r)
        elif source == "username_presence":
            _print_username_results(r)
        elif source == "phone_osint":
            _print_phone_results(r)
        elif source == "cross_case_linker":
            _print_upi_wallet_results(r)
        else:
            if r.get("error"):
                print(f"    {Fore.YELLOW}⚠️  {source} lookup failed: {r.get('error')}{Style.RESET_ALL}")


def run_full_osint(subject_dict: dict) -> dict:
    """
    Executes public OSINT queries for all non-empty subject fields.
    
    Args:
        subject_dict: Dict with subject parameters.
        
    Returns:
        dict with complete results dataset.
    """
    # 1. Map fields to appropriate ioc_types
    mapping = {
        "phone": "phone",
        "email": "email",
        "url": "url",
        "domain": "domain",
        "upi_id": "upi_id",
        "wallet": "wallet"
    }

    # 2. Iterate and collect
    osint_results = []

    # Count inputs to show progress index
    non_empty_keys = [k for k, v in subject_dict.items() if v and k != "timestamp" and k != "notes"]
    total_iocs = len(non_empty_keys)
    idx = 1

    # Route username separately
    username_val = subject_dict.get("username")
    if username_val:
        print(f"\n{Fore.WHITE}─" * 60)
        print(f"  [{idx}/{total_iocs}] Analysing {Fore.YELLOW}username{Fore.WHITE}: {Fore.CYAN}{username_val}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}─" * 60 + Style.RESET_ALL)
        
        try:
            presence_result = username_presence_check(username_val)
        except Exception as e:
            presence_result = {"source": "username_presence", "username": username_val, "platforms_found": [], "error": str(e)}

        res_obj = {
            "ioc_type": "username",
            "ioc_value": username_val,
            "results": [presence_result],
            "is_malicious": False
        }
        osint_results.append(res_obj)
        display_ioc_result(res_obj)
        idx += 1

    # Route other fields
    for field_name, ioc_type in mapping.items():
        ioc_val = subject_dict.get(field_name)
        if not ioc_val:
            continue

        print(f"\n{Fore.WHITE}─" * 60)
        print(f"  [{idx}/{total_iocs}] Analysing {Fore.YELLOW}{ioc_type}{Fore.WHITE}: {Fore.CYAN}{ioc_val}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}─" * 60 + Style.RESET_ALL)

        try:
            res_obj = run_osint(ioc_type, ioc_val, current_case_id=None)
        except Exception as e:
            res_obj = {
                "ioc_type": ioc_type,
                "ioc_value": ioc_val,
                "results": [{"source": "orchestrator", "error": str(e)}],
                "is_malicious": False
            }
        
        osint_results.append(res_obj)
        display_ioc_result(res_obj)
        idx += 1

    return {
        "subject": subject_dict,
        "osint_results": osint_results,
        "generated_at": datetime.now(timezone.utc).isoformat()
    }


def print_subject_report(full_result: dict) -> None:
    """
    Prints a structured Subject Report in the terminal.
    """
    subject = full_result["subject"]
    osint_results = full_result.get("osint_results", [])
    
    total_checks = len(osint_results)
    flagged_risky = sum(1 for r in osint_results if r.get("is_malicious", False))
    clean_findings = total_checks - flagged_risky

    print(f"\n{Fore.WHITE}═══════════════════════════════════════════════════════")
    print(f"  📄  SUBJECT REPORT")
    print(f"═══════════════════════════════════════════════════════")
    print(f"  Generated: {full_result['generated_at']}")
    print(f"───────────────────────────────────────────────────────")
    print(f"  INPUT PROVIDED")
    print(f"  Phone     : {subject.get('phone') or '—'}")
    print(f"  Email     : {subject.get('email') or '—'}")
    print(f"  URL       : {subject.get('url') or '—'}")
    print(f"  Domain    : {subject.get('domain') or '—'}")
    print(f"  Username  : {subject.get('username') or '—'}")
    print(f"  UPI ID    : {subject.get('upi_id') or '—'}")
    print(f"  Wallet    : {subject.get('wallet') or '—'}")
    print(f"  Notes     : {subject.get('notes') or '—'}")
    print(f"───────────────────────────────────────────────────────")
    print(f"  OSINT FINDINGS")
    
    for res in osint_results:
        display_ioc_result(res)
        
    print(f"\n───────────────────────────────────────────────────────")
    print(f"  THREAT INDICATOR SUMMARY")
    print(f"  Total checks run    : {total_checks}")
    
    risky_color = Fore.RED if flagged_risky > 0 else Fore.WHITE
    print(f"  Flagged as risky     : {risky_color}{flagged_risky}{Style.RESET_ALL}")
    print(f"  Clean / no findings  : {Fore.GREEN}{clean_findings}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}═══════════════════════════════════════════════════════{Style.RESET_ALL}\n")
