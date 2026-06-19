"""
C.A.S.E. — Cyber Attack Scene Examiner
Configuration Module

Loads API keys from .env and defines application-wide constants.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# ─── Load .env from project root ─────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

# ─── API Keys (used in Day 2+ for OSINT) ─────────────────────────────────────
VT_KEY = os.getenv("VT_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
IPINFO_KEY = os.getenv("IPINFO_KEY", "")
URLSCAN_KEY = os.getenv("URLSCAN_KEY", "")
HIBP_KEY = os.getenv("HIBP_KEY", "")

# ─── Paths ────────────────────────────────────────────────────────────────────
DB_PATH = str(PROJECT_ROOT / "data" / "cases.db")
OUTPUTS_DIR = str(PROJECT_ROOT / "outputs")

# ─── Application Metadata ────────────────────────────────────────────────────
APP_NAME = "C.A.S.E. — Cyber Attack Scene Examiner"
VERSION = "1.0.0"
JURISDICTION = "Kerala Police Cyber Cell"
