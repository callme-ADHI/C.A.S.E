"""
C.A.S.E. — Cyber Attack Scene Examiner
Subject Intake Module

Presents a simple form to collect suspect indicators, validates them,
and returns structured data for personal OSINT lookup.
"""

import os
import re
import json
from datetime import datetime
from colorama import Fore, Style

# Import config safely to handle optional local history logging
try:
    import config.config as config
except ImportError:
    try:
        from config import config
    except ImportError:
        config = None

# ══════════════════════════════════════════════════════════════════════════════
#  INPUT VALIDATORS
# ══════════════════════════════════════════════════════════════════════════════

def _validate_phone(value):
    """
    Validate 10-digit Indian phone number.
    Only strips +91/91/0 prefix when total length confirms
    a prefix is present. Indian mobiles start with 6-9.
    """
    cleaned = re.sub(r"[\s\-\(\)]", "", value)
    if cleaned.startswith("+91") and len(cleaned) == 13:
        cleaned = cleaned[3:]
    elif cleaned.startswith("91") and len(cleaned) == 12:
        cleaned = cleaned[2:]
    elif cleaned.startswith("0") and len(cleaned) == 11:
        cleaned = cleaned[1:]
    if re.fullmatch(r"[6-9]\d{9}", cleaned):
        return cleaned
    return None

def _validate_email(value):
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if re.fullmatch(pattern, value):
        return value
    return None

def _validate_url(value):
    pattern = r"^https?://[^\s]+$"
    if re.fullmatch(pattern, value, re.IGNORECASE):
        return value
    if re.fullmatch(r"[a-zA-Z0-9][^\s]*\.[a-zA-Z]{2,}[^\s]*", value):
        return "https://" + value
    return None

def _validate_domain(value):
    """Accept a bare domain like 'example.com' — no protocol."""
    pattern = r"^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$"
    if re.fullmatch(pattern, value):
        return value.lower()
    return None

# ══════════════════════════════════════════════════════════════════════════════
#  SUBJECT INTAKE FLOW
# ══════════════════════════════════════════════════════════════════════════════

def collect_subject_info() -> dict:
    """
    Collects information about the suspect through a CLI interface.
    Validates inputs and prompts again on invalid ones.
    At least one field must be provided.
    
    Returns:
        dict: Collected subject data or None if OSINT run is declined.
    """
    while True:
        print(f"\n{Fore.WHITE}═══════════════════════════════════════")
        print(f"  🔍  C.A.S.E. — Subject Lookup")
        print(f"═══════════════════════════════════════{Style.RESET_ALL}")
        print("Enter what you know about the suspect.")
        print("Leave any field blank if unknown.\n")

        # 1. Suspect's phone number
        phone = None
        while True:
            print(f"{Fore.CYAN}1. Suspect's phone number (optional):{Style.RESET_ALL}")
            raw = input(f"  {Fore.GREEN}➤ {Style.RESET_ALL}").strip()
            if not raw:
                break
            validated = _validate_phone(raw)
            if validated:
                phone = validated
                break
            print(f"  {Fore.RED}✗ Invalid phone number. Enter 10-digit Indian number.{Style.RESET_ALL}")

        # 2. Suspect's email address
        email = None
        while True:
            print(f"{Fore.CYAN}2. Suspect's email address (optional):{Style.RESET_ALL}")
            raw = input(f"  {Fore.GREEN}➤ {Style.RESET_ALL}").strip()
            if not raw:
                break
            validated = _validate_email(raw)
            if validated:
                email = validated
                break
            print(f"  {Fore.RED}✗ Invalid email format.{Style.RESET_ALL}")

        # 3. Suspect's URL / website
        url = None
        while True:
            print(f"{Fore.CYAN}3. Suspect's URL / website (optional):{Style.RESET_ALL}")
            raw = input(f"  {Fore.GREEN}➤ {Style.RESET_ALL}").strip()
            if not raw:
                break
            validated = _validate_url(raw)
            if validated:
                url = validated
                break
            print(f"  {Fore.RED}✗ Invalid URL. Include http:// or https://{Style.RESET_ALL}")

        # 4. Suspect's domain name
        domain = None
        while True:
            print(f"{Fore.CYAN}4. Suspect's domain name (optional):{Style.RESET_ALL}")
            raw = input(f"  {Fore.GREEN}➤ {Style.RESET_ALL}").strip()
            if not raw:
                break
            validated = _validate_domain(raw)
            if validated:
                domain = validated
                break
            print(f"  {Fore.RED}✗ Invalid domain format (e.g. example.com).{Style.RESET_ALL}")

        # 5. Suspect's username/handle
        print(f"{Fore.CYAN}5. Suspect's username/handle (optional):{Style.RESET_ALL}")
        username = input(f"  {Fore.GREEN}➤ {Style.RESET_ALL}").strip() or None

        # 6. Suspect's UPI ID
        print(f"{Fore.CYAN}6. Suspect's UPI ID (optional):{Style.RESET_ALL}")
        upi_id = input(f"  {Fore.GREEN}➤ {Style.RESET_ALL}").strip() or None

        # 7. Suspect's crypto wallet
        print(f"{Fore.CYAN}7. Suspect's crypto wallet (optional):{Style.RESET_ALL}")
        wallet = input(f"  {Fore.GREEN}➤ {Style.RESET_ALL}").strip() or None

        # 8. Any additional notes
        print(f"{Fore.CYAN}8. Any additional notes (optional):{Style.RESET_ALL}")
        notes = input(f"  {Fore.GREEN}➤ {Style.RESET_ALL}").strip() or None

        # Check that at least one field was filled
        collected_fields = [phone, email, url, domain, username, upi_id, wallet, notes]
        if not any(collected_fields):
            print(f"\n{Fore.RED}✗ You must provide at least one piece of information to investigate.{Style.RESET_ALL}")
            continue

        # Build dict
        subject_dict = {
            "phone": phone,
            "email": email,
            "url": url,
            "domain": domain,
            "username": username,
            "upi_id": upi_id,
            "wallet": wallet,
            "notes": notes,
            "timestamp": datetime.now().isoformat()
        }

        # Optional local history toggle
        save_history = False
        if config is not None:
            save_history = getattr(config, "SAVE_HISTORY", False)

        if save_history:
            try:
                # Ensure data directory exists
                project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                data_dir = os.path.join(project_root, "data")
                os.makedirs(data_dir, exist_ok=True)
                history_path = os.path.join(data_dir, "lookup_history.jsonl")
                with open(history_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(subject_dict, ensure_ascii=False) + "\n")
            except Exception as e:
                # Silently fail or log to stderr to avoid UX disruption
                pass

        # Print confirmation summary
        print(f"\n{Fore.WHITE}═══════════════════════════════════════")
        print(f"  📝  Subject Summary")
        print(f"═══════════════════════════════════════{Style.RESET_ALL}")
        
        field_labels = {
            "phone": "Phone",
            "email": "Email",
            "url": "URL/Website",
            "domain": "Domain",
            "username": "Username",
            "upi_id": "UPI ID",
            "wallet": "Crypto Wallet",
            "notes": "Notes"
        }
        
        for key, label in field_labels.items():
            val = subject_dict[key]
            if val:
                print(f"  {Fore.WHITE}{label:<15}: {Fore.CYAN}{val}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}═══════════════════════════════════════{Style.RESET_ALL}\n")

        # Ask: "Run OSINT analysis on this subject? (y/n)"
        while True:
            choice = input(f"  {Fore.CYAN}Run OSINT analysis on this subject? (y/n): {Style.RESET_ALL}").strip().lower()
            if choice in ("y", "yes"):
                return subject_dict
            elif choice in ("n", "no"):
                return None
            print(f"  {Fore.RED}✗ Please enter y or n.{Style.RESET_ALL}")
