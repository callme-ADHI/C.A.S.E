#!/usr/bin/env python3
"""
C.A.S.E. — Cyber Attack Scene Examiner
Personal OSINT Investigation Tool
"""

import sys
from datetime import datetime
from colorama import init, Fore, Style

# ── Local imports ─────────────────────────────────────────────────────────────
from config.config import APP_NAME
from modules.subject_intake import collect_subject_info

# ── Initialize colorama ───────────────────────────────────────────────────────
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
  ║  {Fore.CYAN}C{Fore.WHITE}yber {Fore.CYAN}A{Fore.WHITE}ttack {Fore.CYAN}S{Fore.WHITE}cene {Fore.CYAN}E{Fore.WHITE}xaminer                     ║
  ║  {Fore.CYAN}Personal OSINT Investigation Tool{Fore.WHITE}               ║
  ╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
"""


try:
    import config.config as config
except ImportError:
    try:
        from config import config
    except ImportError:
        config = None

from modules.report_engine import run_full_osint, print_subject_report
from modules.pattern_matcher import match_crime_patterns
import json


def main():
    """Main CLI entry point for C.A.S.E. Personal OSINT Lookup."""
    print(BANNER)

    while True:
        # Call collect_subject_info from subject_intake
        subject_info = collect_subject_info()

        if subject_info is not None:
            # 1. Run Real OSINT analysis
            full_result = run_full_osint(subject_info)

            # 2. Print Terminal Subject Report
            print_subject_report(full_result)

            # 3. Match Crime Patterns with Try/Except Error Handling
            patterns = []
            try:
                patterns = match_crime_patterns(full_result)
            except Exception as e:
                print(f"\n{Fore.YELLOW}⚠️  Warning: Crime pattern analysis failed: {e}{Style.RESET_ALL}")
                patterns = []

            # 4. Display Crime Patterns (if matched successfully)
            if patterns:
                print("\n" + "═"*55)
                print("  🎯  CRIME PATTERN ANALYSIS")
                print("═"*55)
                for p in patterns:
                    color = Fore.RED if p["confidence"] == "High" else \
                            Fore.YELLOW if p["confidence"] == "Medium" else \
                            Fore.CYAN if p["confidence"] == "Low" else Fore.WHITE
                    print(f"\n  Pattern    : {color}{p['pattern']}{Style.RESET_ALL}")
                    print(f"  Confidence : {color}{p['confidence']}{Style.RESET_ALL}")
                    print(f"  Why        :")
                    for reason in p["reasoning"]:
                        print(f"    • {reason}")
                print("\n" + "═"*55)

            # 5. Save History if SAVE_HISTORY is True
            save_history = False
            if config is not None:
                save_history = getattr(config, "SAVE_HISTORY", False)

            if save_history:
                try:
                    import os
                    project_root = os.path.dirname(os.path.abspath(__file__))
                    data_dir = os.path.join(project_root, "data")
                    os.makedirs(data_dir, exist_ok=True)
                    with open(os.path.join(data_dir, "lookup_history.jsonl"), "a") as f:
                        record = {
                            "subject": subject_info,
                            "patterns_matched": patterns,
                            "saved_at": datetime.now().isoformat()
                        }
                        f.write(json.dumps(record) + "\n")
                    print("  💾 Saved to local history.")
                except Exception as e:
                    print(f"  {Fore.YELLOW}⚠️  Warning: Failed to save to local history: {e}{Style.RESET_ALL}")

        # Ask: "Investigate another subject? (y/n)"
        while True:
            again = input(f"  {Fore.CYAN}Investigate another subject? (y/n): {Style.RESET_ALL}").strip().lower()
            if again in ("y", "yes"):
                break
            elif again in ("n", "no"):
                print(f"\n  {Fore.WHITE}{'─' * 60}")
                print(f"  {APP_NAME}")
                print(f"  Session ended at {datetime.now().strftime('%H:%M:%S')}")
                print(f"  {'─' * 60}{Style.RESET_ALL}\n")
                sys.exit(0)
            print(f"  {Fore.RED}✗ Please enter y or n.{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Fore.YELLOW}⚠  Session interrupted. Exiting.{Style.RESET_ALL}\n")
        sys.exit(0)
