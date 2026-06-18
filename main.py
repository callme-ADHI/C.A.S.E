#!/usr/bin/env python3
"""
C.A.S.E. — Cyber Attack Scene Examiner
Day 1: Project Setup + Dynamic Questionnaire Engine

Main entry point for the CLI investigation system.
Built for Kerala Police Cyber Cell.

Legal Framework:
  - BNS 2023 (effective July 1, 2024) — NOT IPC
  - FIR under Section 173 BNSS 2023 — NOT old CrPC Section 154
  - IT Act Section 66A is STRUCK DOWN (Shreya Singhal v UOI 2015)
"""

import json
import os
import re
import sqlite3
import sys
from datetime import datetime, date

from colorama import init, Fore, Back, Style

# ── Local imports ─────────────────────────────────────────────────────────────
from config.config import DB_PATH, APP_NAME, VERSION, JURISDICTION
from modules.questionnaire import (
    CRIME_TYPES,
    run_questionnaire,
)

# ── Initialize colorama (Windows compat) ──────────────────────────────────────
init(autoreset=False)

# ══════════════════════════════════════════════════════════════════════════════
#  ASCII BANNER
# ══════════════════════════════════════════════════════════════════════════════

BANNER = rf"""
{Fore.CYAN}
   ██████╗    █████╗   ███████╗  ███████╗
  ██╔════╝   ██╔══██╗  ██╔════╝  ██╔════╝
  ██║        ███████║  ███████╗  █████╗  
  ██║        ██╔══██║  ╚════██║  ██╔══╝  
  ╚██████╗   ██║  ██║  ███████║  ███████╗
   ╚═════╝   ╚═╝  ╚═╝  ╚══════╝  ╚══════╝
{Style.RESET_ALL}
{Fore.WHITE}  ╔══════════════════════════════════════════════════╗
  ║  {Fore.CYAN}C{Fore.WHITE}yber {Fore.CYAN}A{Fore.WHITE}ttack {Fore.CYAN}S{Fore.WHITE}cene {Fore.CYAN}E{Fore.WHITE}xaminer               ║
  ║  Version {VERSION}                                   ║
  ║  {JURISDICTION:<44s}  ║
  ╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
"""


# ══════════════════════════════════════════════════════════════════════════════
#  DATABASE SETUP
# ══════════════════════════════════════════════════════════════════════════════

def init_database():
    """Initialize SQLite database with the required schema."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            case_number     TEXT UNIQUE,
            crime_code      TEXT NOT NULL,
            crime_name      TEXT NOT NULL,
            officer_name    TEXT NOT NULL,
            complainant_name TEXT,
            date_filed      TEXT NOT NULL,
            status          TEXT DEFAULT 'open',
            raw_inputs      TEXT,
            flags           TEXT,
            threat_score    INTEGER DEFAULT 0,
            created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id         INTEGER REFERENCES cases(id),
            ioc_type        TEXT NOT NULL,
            ioc_value       TEXT NOT NULL,
            is_malicious    INTEGER DEFAULT 0,
            source          TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS suspects (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id         INTEGER REFERENCES cases(id),
            identifier      TEXT NOT NULL,
            identifier_type TEXT,
            osint_data      TEXT,
            threat_score    INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()


# ══════════════════════════════════════════════════════════════════════════════
#  CASE NUMBER GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

def generate_case_number():
    """
    Generate a unique case number in format: KL-CYB-YYYY-NNNN
    Sequential numbering per year.
    """
    current_year = datetime.now().year
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM cases WHERE case_number LIKE ?",
        (f"KL-CYB-{current_year}-%",)
    )
    count = cursor.fetchone()[0]
    conn.close()

    return f"KL-CYB-{current_year}-{count + 1:04d}"


# ══════════════════════════════════════════════════════════════════════════════
#  IOC EXTRACTOR
# ══════════════════════════════════════════════════════════════════════════════

def extract_iocs(answers, questions_meta):
    """
    Automatically extract IOCs from questionnaire answers.

    Detects:
        - Phone numbers → ioc_type="phone"
        - Email addresses → ioc_type="email"
        - URLs → ioc_type="url"
        - IP addresses → ioc_type="ip"
        - UPI IDs → ioc_type="upi_id"
        - Crypto wallets → ioc_type="wallet"
        - File hashes → ioc_type="hash"

    Returns:
        list of dicts: [{"ioc_type": str, "ioc_value": str}, ...]
    """
    iocs = []
    seen = set()

    # Build a type-map from question metadata
    field_types = {}
    for q in questions_meta:
        field_types[q["id"]] = q["type"]

    for field_id, value in answers.items():
        if not value or value == "":
            continue

        val_str = str(value).strip()
        if not val_str:
            continue

        # ── Phone numbers (from phone-type fields or detected) ────────
        if field_types.get(field_id) == "phone":
            key = ("phone", val_str)
            if key not in seen:
                iocs.append({"ioc_type": "phone", "ioc_value": val_str})
                seen.add(key)
            continue

        # ── Email addresses ───────────────────────────────────────────
        if field_types.get(field_id) == "email":
            key = ("email", val_str)
            if key not in seen:
                iocs.append({"ioc_type": "email", "ioc_value": val_str})
                seen.add(key)
            continue

        # ── URLs ──────────────────────────────────────────────────────
        if field_types.get(field_id) == "url":
            key = ("url", val_str)
            if key not in seen:
                iocs.append({"ioc_type": "url", "ioc_value": val_str})
                seen.add(key)
            continue

        # ── UPI IDs (pattern: name@bank) ──────────────────────────────
        if "upi" in field_id.lower() and re.search(r"[\w.]+@[\w]+", val_str):
            key = ("upi_id", val_str)
            if key not in seen:
                iocs.append({"ioc_type": "upi_id", "ioc_value": val_str})
                seen.add(key)
            continue

        # ── Crypto wallet addresses ───────────────────────────────────
        if "wallet" in field_id.lower() or "crypto" in field_id.lower():
            if len(val_str) >= 20:
                key = ("wallet", val_str)
                if key not in seen:
                    iocs.append({"ioc_type": "wallet", "ioc_value": val_str})
                    seen.add(key)
            continue

        # ── File hashes (MD5 / SHA256) ────────────────────────────────
        if "hash" in field_id.lower():
            if re.fullmatch(r"[a-fA-F0-9]{32,64}", val_str):
                key = ("hash", val_str)
                if key not in seen:
                    iocs.append({"ioc_type": "hash", "ioc_value": val_str})
                    seen.add(key)
            continue

        # ── IP addresses (from c2_server_ip or detected in text) ──────
        if "ip" in field_id.lower() and field_id != "complainant_zip":
            ip_match = re.search(
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b", val_str
            )
            if ip_match:
                ip = ip_match.group()
                key = ("ip", ip)
                if key not in seen:
                    iocs.append({"ioc_type": "ip", "ioc_value": ip})
                    seen.add(key)
            continue

        # ── Detect emails in text fields ──────────────────────────────
        if field_types.get(field_id) == "text":
            email_match = re.search(
                r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
                val_str
            )
            if email_match:
                email = email_match.group()
                key = ("email", email)
                if key not in seen:
                    iocs.append({"ioc_type": "email", "ioc_value": email})
                    seen.add(key)

            # Detect phone numbers in text fields
            phone_match = re.search(r"\b\d{10}\b", val_str)
            if phone_match:
                phone = phone_match.group()
                key = ("phone", phone)
                if key not in seen:
                    iocs.append({"ioc_type": "phone", "ioc_value": phone})
                    seen.add(key)

    return iocs


# ══════════════════════════════════════════════════════════════════════════════
#  SAVE CASE TO DATABASE
# ══════════════════════════════════════════════════════════════════════════════

def save_case(case_number, crime_code, crime_name, officer_name,
              answers, flags, iocs):
    """Save a completed case to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    complainant_name = (
        answers.get("complainant_name", "") or
        answers.get("organization_name", "") or
        answers.get("organization_or_victim", "")
    )

    cursor.execute("""
        INSERT INTO cases (case_number, crime_code, crime_name,
                          officer_name, complainant_name, date_filed,
                          status, raw_inputs, flags, threat_score)
        VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, 0)
    """, (
        case_number,
        crime_code,
        crime_name,
        officer_name,
        complainant_name,
        date.today().isoformat(),
        json.dumps(answers, ensure_ascii=False, default=str),
        json.dumps(flags),
    ))

    case_id = cursor.lastrowid

    # ── Save IOCs ─────────────────────────────────────────────────────────
    for ioc in iocs:
        cursor.execute("""
            INSERT INTO iocs (case_id, ioc_type, ioc_value,
                             is_malicious, source)
            VALUES (?, ?, ?, 0, 'questionnaire')
        """, (case_id, ioc["ioc_type"], ioc["ioc_value"]))

    conn.commit()
    conn.close()
    return case_id


# ══════════════════════════════════════════════════════════════════════════════
#  CASE SUMMARY PRINTER
# ══════════════════════════════════════════════════════════════════════════════

def print_case_summary(case_number, crime_code, crime_name,
                       officer_name, answers, flags, iocs):
    """Print a formatted case summary to the terminal."""
    complainant_name = (
        answers.get("complainant_name", "") or
        answers.get("organization_name", "") or
        answers.get("organization_or_victim", "N/A")
    )

    print(f"\n{Fore.GREEN}{'═' * 60}")
    print(f"  ✅  CASE SAVED SUCCESSFULLY")
    print(f"{'═' * 60}{Style.RESET_ALL}\n")

    print(f"  {Fore.WHITE}Case Number   : {Fore.CYAN}{case_number}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Crime Type    : {Fore.CYAN}[{crime_code}] {crime_name}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Complainant   : {Fore.CYAN}{complainant_name}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Officer       : {Fore.CYAN}{officer_name}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Date Filed    : {Fore.CYAN}{date.today().isoformat()}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Status        : {Fore.GREEN}Open{Style.RESET_ALL}")

    # ── Active Flags ──────────────────────────────────────────────────────
    active_flags = [k.upper() for k, v in flags.items() if v]
    if active_flags:
        print(f"  {Fore.WHITE}Active Flags  : {Fore.RED}{', '.join(active_flags)}{Style.RESET_ALL}")
    else:
        print(f"  {Fore.WHITE}Active Flags  : {Fore.GREEN}None{Style.RESET_ALL}")

    # ── IOCs for Day 2 OSINT ──────────────────────────────────────────────
    if iocs:
        print(f"\n  {Fore.WHITE}{'─' * 50}")
        print(f"  🔎  Day 2 will run OSINT on:{Style.RESET_ALL}")
        for ioc in iocs:
            print(f"     {Fore.YELLOW}{ioc['ioc_type']:>8}: "
                  f"{Fore.WHITE}{ioc['ioc_value']}{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.YELLOW}  ℹ  No IOCs extracted for OSINT.{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}{'═' * 60}{Style.RESET_ALL}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  CRIME TYPE MENU
# ══════════════════════════════════════════════════════════════════════════════

def show_crime_menu():
    """Display the crime type selection menu."""
    print(f"\n{Fore.WHITE}{'═' * 60}")
    print(f"  📂  SELECT CRIME TYPE (I4C Classification)")
    print(f"{'═' * 60}{Style.RESET_ALL}\n")

    codes = list(CRIME_TYPES.keys())
    for i, (code, name) in enumerate(CRIME_TYPES.items(), 1):
        print(f"  {Fore.CYAN}{i:>3}. {Fore.WHITE}[{code}] {name}{Style.RESET_ALL}")

    print()

    while True:
        try:
            raw = input(
                f"  {Fore.GREEN}Select crime type (1–{len(codes)}): "
                f"{Style.RESET_ALL}"
            ).strip()
            choice = int(raw)
            if 1 <= choice <= len(codes):
                return codes[choice - 1]
            print(f"  {Fore.RED}✗ Choose between 1 and {len(codes)}.{Style.RESET_ALL}")
        except ValueError:
            # Allow entering the code directly (e.g. C001)
            if raw.upper() in CRIME_TYPES:
                return raw.upper()
            print(f"  {Fore.RED}✗ Enter a number or crime code (e.g. C001).{Style.RESET_ALL}")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION LOOP
# ══════════════════════════════════════════════════════════════════════════════

def main():
    """Main CLI entry point for C.A.S.E."""
    # ── Initialize ────────────────────────────────────────────────────────
    init_database()
    print(BANNER)

    # ── Officer identification ────────────────────────────────────────────
    print(f"  {Fore.WHITE}Authorized personnel only. "
          f"Unauthorized access is an offence under BNS 2023.{Style.RESET_ALL}\n")

    officer_name = ""
    while not officer_name:
        officer_name = input(
            f"  {Fore.CYAN}Enter officer name: {Style.RESET_ALL}"
        ).strip()
        if not officer_name:
            print(f"  {Fore.RED}✗ Officer name is required.{Style.RESET_ALL}")

    print(f"\n  {Fore.GREEN}✓ Welcome, {officer_name}. "
          f"Session started at {datetime.now().strftime('%H:%M:%S')}.{Style.RESET_ALL}")

    # ── Main loop ─────────────────────────────────────────────────────────
    while True:
        # ── Crime type selection ──────────────────────────────────────
        crime_code = show_crime_menu()
        crime_name = CRIME_TYPES[crime_code]

        print(f"\n  {Fore.GREEN}✓ Selected: [{crime_code}] {crime_name}{Style.RESET_ALL}")

        # ── Run questionnaire ─────────────────────────────────────────
        from modules.questionnaire import CRIME_QUESTIONS
        result = run_questionnaire(crime_code)

        if result is None:
            continue

        answers = result["answers"]
        flags = result["flags"]

        # ── Extract IOCs ──────────────────────────────────────────────
        questions_meta = CRIME_QUESTIONS[crime_code]
        iocs = extract_iocs(answers, questions_meta)

        # ── Confirm save ──────────────────────────────────────────────
        print(f"  {Fore.CYAN}Save this case? (y/n): {Style.RESET_ALL}", end="")
        save_confirm = input().strip().lower()

        if save_confirm in ("y", "yes"):
            case_number = generate_case_number()
            save_case(
                case_number, crime_code, crime_name,
                officer_name, answers, flags, iocs
            )
            print_case_summary(
                case_number, crime_code, crime_name,
                officer_name, answers, flags, iocs
            )
        else:
            print(f"\n  {Fore.YELLOW}⚠  Case not saved.{Style.RESET_ALL}\n")

        # ── Continue or exit ──────────────────────────────────────────
        print(f"  {Fore.CYAN}Open another case? (y/n): {Style.RESET_ALL}", end="")
        again = input().strip().lower()

        if again not in ("y", "yes"):
            print(f"\n  {Fore.WHITE}{'─' * 60}")
            print(f"  {APP_NAME}")
            print(f"  Session ended at {datetime.now().strftime('%H:%M:%S')}")
            print(f"  FIR filing reference: Section 173, BNSS 2023")
            print(f"  {JURISDICTION}")
            print(f"  {'─' * 60}{Style.RESET_ALL}\n")
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Fore.YELLOW}⚠  Session interrupted. "
              f"Unsaved data has been discarded.{Style.RESET_ALL}\n")
        sys.exit(0)
