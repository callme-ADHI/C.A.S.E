"""
C.A.S.E. — Cyber Attack Scene Examiner
OSINT Engine — Day 2 + Day 3

Unified OSINT module containing:
  Day 2:
    1. VirusTotal     — IP, URL, domain, hash lookups
    2. AbuseIPDB      — IP abuse scoring
    3. IPInfo         — IP geolocation + ASN
    4. PhishTank      — URL phishing check (no key needed)
    5. URLScan.io     — URL scanning + screenshot capture
  Day 3:
    6. HaveIBeenPwned — Email breach check
    7. Email Domain   — Domain age + disposable check
    8. Username       — Platform presence check
    9. Phone          — Format validation + cross-case linking
   10. UPI/Wallet     — Cross-case pattern linking

Orchestrator function run_osint() dispatches IOCs to the correct
module(s) and returns structured, aggregated results.
"""

import base64
import ipaddress
import json
import re
import sqlite3
import time
from datetime import datetime
from urllib.parse import urlparse

import requests

from config.config import (VT_KEY, ABUSEIPDB_KEY, IPINFO_KEY,
                           URLSCAN_KEY, HIBP_KEY, DB_PATH)

# ── Timeout for all HTTP requests (seconds) ───────────────────────────────
REQUEST_TIMEOUT = 10

# ── Country code → full name (common subset for display) ──────────────────
COUNTRY_NAMES = {
    "IN": "India", "US": "United States", "GB": "United Kingdom",
    "CN": "China", "RU": "Russia", "DE": "Germany", "FR": "France",
    "JP": "Japan", "KR": "South Korea", "AU": "Australia",
    "CA": "Canada", "BR": "Brazil", "NL": "Netherlands",
    "SG": "Singapore", "AE": "United Arab Emirates", "PK": "Pakistan",
    "BD": "Bangladesh", "LK": "Sri Lanka", "NP": "Nepal",
    "HK": "Hong Kong", "TW": "Taiwan", "UA": "Ukraine",
    "IR": "Iran", "NG": "Nigeria", "ZA": "South Africa",
}


# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def extract_domain(url):
    """Extract domain from a URL, stripping www. prefix."""
    try:
        parsed = urlparse(url)
        domain = parsed.hostname or parsed.path.split("/")[0]
        if domain and domain.startswith("www."):
            domain = domain[4:]
        return domain or ""
    except Exception:
        return ""


def is_private_ip(ip_str):
    """Check if an IP address belongs to a private/reserved range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_reserved or ip.is_loopback
    except ValueError:
        return False


def _make_error_result(source, ioc_value, error_msg, ioc_type=None):
    """Build a standardised error result dict."""
    result = {
        "source": source,
        "error": error_msg,
        "ioc_value": ioc_value,
    }
    if ioc_type:
        result["ioc_type"] = ioc_type
    return result


def _api_request(method, url, headers=None, params=None, data=None,
                 json_body=None, source="api", ioc_value="",
                 ioc_type=None):
    """
    Centralised HTTP request wrapper with retry-on-429 logic.

    Returns (response_json, error_dict_or_None).
    If an error occurs, response_json is None and error_dict is populated.
    """
    for attempt in range(2):  # first try + one retry after 429
        try:
            resp = requests.request(
                method, url,
                headers=headers,
                params=params,
                data=data,
                json=json_body,
                timeout=REQUEST_TIMEOUT,
            )

            if resp.status_code == 404:
                return None, _make_error_result(
                    source, ioc_value, "not_found", ioc_type)

            if resp.status_code == 429:
                if attempt == 0:
                    time.sleep(60)  # rate-limited — wait and retry once
                    continue
                return None, _make_error_result(
                    source, ioc_value, "rate_limited", ioc_type)

            resp.raise_for_status()
            return resp.json(), None

        except requests.exceptions.Timeout:
            return None, _make_error_result(
                source, ioc_value, "timeout", ioc_type)
        except requests.exceptions.RequestException as e:
            return None, _make_error_result(
                source, ioc_value, str(e), ioc_type)
        except json.JSONDecodeError:
            return None, _make_error_result(
                source, ioc_value, "invalid_json_response", ioc_type)

    return None, _make_error_result(
        source, ioc_value, "unexpected_failure", ioc_type)


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 1 — VirusTotal
# ══════════════════════════════════════════════════════════════════════════════

def vt_lookup(value, ioc_type):
    """
    Query VirusTotal for an IP, URL, domain, or hash.

    Args:
        value:    The IOC value to look up.
        ioc_type: One of "ip", "url", "domain", "hash".

    Returns:
        dict with enrichment data or error information.
    """
    if not VT_KEY:
        return _make_error_result("virustotal", value,
                                  "api_key_missing", ioc_type)

    base = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": VT_KEY, "Accept": "application/json"}

    # ══════════════════════════════════════════════════════════════════════
    #  URL type — special two-step flow (POST submit → GET analysis)
    # ══════════════════════════════════════════════════════════════════════
    if ioc_type == "url":
        # Step 1: Submit the URL via POST /urls (form-encoded)
        time.sleep(15)

        submit_data, err = _api_request(
            "POST", f"{base}/urls",
            headers={"x-apikey": VT_KEY,
                     "Content-Type": "application/x-www-form-urlencoded"},
            data=f"url={value}",
            source="virustotal", ioc_value=value, ioc_type="url")

        if err:
            return err

        # Extract the analysis ID from the submission response
        analysis_id = submit_data.get("data", {}).get("id", "")
        if not analysis_id:
            return _make_error_result("virustotal", value,
                                      "no_analysis_id_returned", "url")

        # Step 2: Wait for VT to process the scan
        time.sleep(15)

        # Step 3: Fetch the analysis results via GET /analyses/{id}
        analysis_json, err = _api_request(
            "GET", f"{base}/analyses/{analysis_id}",
            headers=headers,
            source="virustotal", ioc_value=value, ioc_type="url")

        if err:
            return err

        # Parse the /analyses response (uses "stats" not "last_analysis_stats")
        try:
            attrs = analysis_json.get("data", {}).get("attributes", {})
            stats = attrs.get("stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            # URL-safe base64 ID for the VT GUI link
            url_id = base64.urlsafe_b64encode(
                value.encode()).decode().rstrip("=")

            return {
                "source": "virustotal",
                "ioc_type": "url",
                "ioc_value": value,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "harmless_count": harmless,
                "undetected_count": undetected,
                "total_engines": (malicious + suspicious
                                  + harmless + undetected),
                "reputation": 0,
                "country": "",
                "asn": "",
                "as_owner": "",
                "tags": [],
                "last_analysis_date": attrs.get("date", ""),
                "is_malicious": malicious >= 3,
                "threat_label": "",
                "raw_url": (f"https://www.virustotal.com/gui/"
                            f"url/{url_id}"),
            }

        except Exception as e:
            return _make_error_result("virustotal", value, str(e), "url")

    # ══════════════════════════════════════════════════════════════════════
    #  IP / Domain / Hash — standard GET flow
    # ══════════════════════════════════════════════════════════════════════
    if ioc_type == "ip":
        endpoint = f"{base}/ip_addresses/{value}"
    elif ioc_type == "domain":
        endpoint = f"{base}/domains/{value}"
    elif ioc_type == "hash":
        endpoint = f"{base}/files/{value}"
    else:
        return _make_error_result("virustotal", value,
                                  f"unsupported_ioc_type: {ioc_type}",
                                  ioc_type)

    # ── Rate-limit safety (VT free tier: 4 req/min) ───────────────────────
    time.sleep(15)

    data_json, err = _api_request(
        "GET", endpoint, headers=headers,
        source="virustotal", ioc_value=value, ioc_type=ioc_type)

    if err:
        return err

    # ── Parse response ────────────────────────────────────────────────────
    try:
        attrs = data_json.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        # Threat classification
        threat_label = ""
        ptc = attrs.get("popular_threat_classification", {})
        if ptc:
            suggested = ptc.get("suggested_threat_label", "")
            threat_label = suggested

        # Analysis date
        last_date = attrs.get("last_analysis_date", "")
        if isinstance(last_date, int):
            last_date = time.strftime("%Y-%m-%d %H:%M:%S",
                                     time.gmtime(last_date))

        result = {
            "source": "virustotal",
            "ioc_type": ioc_type,
            "ioc_value": value,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "harmless_count": harmless,
            "undetected_count": undetected,
            "total_engines": malicious + suspicious + harmless + undetected,
            "reputation": attrs.get("reputation", 0),
            "country": attrs.get("country", ""),
            "asn": str(attrs.get("asn", "")),
            "as_owner": attrs.get("as_owner", ""),
            "tags": attrs.get("tags", []),
            "last_analysis_date": str(last_date),
            "is_malicious": malicious >= 3,
            "threat_label": threat_label,
            "raw_url": f"https://www.virustotal.com/gui/{ioc_type}/{value}",
        }

        return result

    except Exception as e:
        return _make_error_result("virustotal", value, str(e), ioc_type)


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 2 — AbuseIPDB
# ══════════════════════════════════════════════════════════════════════════════

def abuseipdb_lookup(ip_address):
    """
    Query AbuseIPDB for abuse reports on an IP address.

    Args:
        ip_address: IPv4 or IPv6 address string.

    Returns:
        dict with abuse scoring data or error information.
    """
    if not ABUSEIPDB_KEY:
        return _make_error_result("abuseipdb", ip_address,
                                  "api_key_missing", "ip")

    endpoint = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": "true",
    }

    data_json, err = _api_request(
        "GET", endpoint, headers=headers, params=params,
        source="abuseipdb", ioc_value=ip_address, ioc_type="ip")

    if err:
        return err

    try:
        d = data_json.get("data", {})
        abuse_score = d.get("abuseConfidenceScore", 0)
        usage_type = d.get("usageType", "") or ""

        # Risk level classification
        if abuse_score >= 75:
            risk_level = "HIGH"
        elif abuse_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "source": "abuseipdb",
            "ip": ip_address,
            "abuse_score": abuse_score,
            "country_code": d.get("countryCode", ""),
            "usage_type": usage_type,
            "isp": d.get("isp", ""),
            "domain": d.get("domain", ""),
            "is_tor": "tor" in usage_type.lower(),
            "is_vpn": "vpn" in usage_type.lower(),
            "total_reports": d.get("totalReports", 0),
            "last_reported": d.get("lastReportedAt", "") or "",
            "is_whitelisted": d.get("isWhitelisted", False) or False,
            "is_malicious": abuse_score >= 25,
            "risk_level": risk_level,
        }

    except Exception as e:
        return _make_error_result("abuseipdb", ip_address, str(e), "ip")


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 3 — IPInfo
# ══════════════════════════════════════════════════════════════════════════════

def ipinfo_lookup(ip_address):
    """
    Query IPInfo for geolocation and ASN data on an IP address.

    Args:
        ip_address: IPv4 or IPv6 address string.

    Returns:
        dict with geolocation data or error information.
    """
    if not IPINFO_KEY:
        return _make_error_result("ipinfo", ip_address,
                                  "api_key_missing", "ip")

    endpoint = f"https://ipinfo.io/{ip_address}"
    params = {"token": IPINFO_KEY}

    data_json, err = _api_request(
        "GET", endpoint, params=params,
        source="ipinfo", ioc_value=ip_address, ioc_type="ip")

    if err:
        return err

    try:
        org_raw = data_json.get("org", "")
        asn = ""
        isp = org_raw
        if org_raw and " " in org_raw:
            parts = org_raw.split(" ", 1)
            asn = parts[0]    # e.g. "AS13335"
            isp = parts[1]    # e.g. "Cloudflare"

        loc = data_json.get("loc", "")
        latitude = 0.0
        longitude = 0.0
        if loc and "," in loc:
            lat_str, lon_str = loc.split(",", 1)
            try:
                latitude = float(lat_str)
                longitude = float(lon_str)
            except ValueError:
                pass

        country_code = data_json.get("country", "")

        return {
            "source": "ipinfo",
            "ip": ip_address,
            "city": data_json.get("city", ""),
            "region": data_json.get("region", ""),
            "country": country_code,
            "country_name": COUNTRY_NAMES.get(country_code, country_code),
            "org": org_raw,
            "asn": asn,
            "isp": isp,
            "hostname": data_json.get("hostname", ""),
            "timezone": data_json.get("timezone", ""),
            "loc": loc,
            "latitude": latitude,
            "longitude": longitude,
            "is_india": country_code == "IN",
            "postal": data_json.get("postal", ""),
        }

    except Exception as e:
        return _make_error_result("ipinfo", ip_address, str(e), "ip")


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 4 — PhishTank
# ══════════════════════════════════════════════════════════════════════════════

def phishtank_lookup(url):
    """
    Query PhishTank to check if a URL is a known phishing page.
    No API key required (anonymous access).

    Args:
        url: The URL to check.

    Returns:
        dict with phishing status or error information.
    """
    endpoint = "https://checkurl.phishtank.com/checkurl/"
    headers = {
        "User-Agent": "phishtank/C.A.S.E-Kerala-Cyber-Cell",
    }
    form_data = {
        "url": url,
        "format": "json",
        "app_key": "",
    }

    try:
        resp = requests.post(
            endpoint, data=form_data, headers=headers,
            timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        results = data.get("results", {})
        return {
            "source": "phishtank",
            "url": url,
            "in_database": results.get("in_database", False),
            "is_phishing": results.get("valid", False)
                           if results.get("in_database") else False,
            "verified": results.get("verified", False),
            "phish_id": str(results.get("phish_id", "")),
            "phish_detail_url": results.get("phish_detail_page", ""),
        }

    except requests.exceptions.Timeout:
        return _make_error_result("phishtank", url, "timeout")
    except requests.exceptions.RequestException as e:
        return _make_error_result("phishtank", url, str(e))
    except Exception as e:
        return _make_error_result("phishtank", url, str(e))


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 5 — URLScan.io
# ══════════════════════════════════════════════════════════════════════════════

def urlscan_lookup(url):
    """
    Submit a URL to URLScan.io for analysis, wait for the result.

    Args:
        url: The URL to scan.

    Returns:
        dict with scan results or error information.
    """
    submit_endpoint = "https://urlscan.io/api/v1/scan/"

    headers = {"Content-Type": "application/json"}
    if URLSCAN_KEY:
        headers["API-Key"] = URLSCAN_KEY

    body = {"url": url, "visibility": "private"}

    # ── Submit the scan ───────────────────────────────────────────────────
    try:
        resp = requests.post(
            submit_endpoint, headers=headers, json=body,
            timeout=REQUEST_TIMEOUT)

        if resp.status_code in (401, 403, 429):
            return _make_error_result("urlscan", url,
                                      f"submit_rejected_{resp.status_code}")

        resp.raise_for_status()
        submit_data = resp.json()
        uuid = submit_data.get("uuid", "")

        if not uuid:
            return _make_error_result("urlscan", url, "no_uuid_returned")

    except requests.exceptions.RequestException as e:
        return _make_error_result("urlscan", url, f"submit_failed: {e}")

    # ── Wait for the scan to complete ─────────────────────────────────────
    time.sleep(10)

    result_endpoint = f"https://urlscan.io/api/v1/result/{uuid}/"

    try:
        resp = requests.get(result_endpoint, timeout=REQUEST_TIMEOUT)

        if resp.status_code == 404:
            # Scan still processing — try once more after extra wait
            time.sleep(10)
            resp = requests.get(result_endpoint, timeout=REQUEST_TIMEOUT)

        if resp.status_code == 404:
            return {
                "source": "urlscan",
                "url": url,
                "uuid": uuid,
                "note": "scan_still_processing",
                "result_url": f"https://urlscan.io/result/{uuid}/",
            }

        resp.raise_for_status()
        data = resp.json()

        verdicts = data.get("verdicts", {}).get("overall", {})
        page = data.get("page", {})
        lists = data.get("lists", {})

        return {
            "source": "urlscan",
            "url": url,
            "uuid": uuid,
            "verdict_malicious": verdicts.get("malicious", False),
            "verdict_score": verdicts.get("score", 0),
            "categories": verdicts.get("categories", []),
            "screenshot_url": data.get("task", {}).get("screenshotURL", ""),
            "dom_url": data.get("task", {}).get("domURL", ""),
            "server_ip": page.get("ip", ""),
            "server_country": page.get("country", ""),
            "page_domain": page.get("domain", ""),
            "page_title": page.get("title", ""),
            "technologies": lists.get("technologies", []),
            "result_url": f"https://urlscan.io/result/{uuid}/",
        }

    except requests.exceptions.RequestException as e:
        return _make_error_result("urlscan", url, f"result_fetch_failed: {e}")
    except Exception as e:
        return _make_error_result("urlscan", url, str(e))


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 6 — HaveIBeenPwned (Day 3)
# ══════════════════════════════════════════════════════════════════════════════

def hibp_lookup(email):
    """
    Query HaveIBeenPwned for email breach history.

    Args:
        email: Email address to check.

    Returns:
        dict with breach data or error information.
    """
    if not HIBP_KEY:
        return {
            "source": "haveibeenpwned",
            "error": "no_api_key",
            "email": email,
            "is_breached": None,
        }

    endpoint = (f"https://haveibeenpwned.com/api/v3/"
                f"breachedaccount/{email}")
    headers = {
        "hibp-api-key": HIBP_KEY,
        "User-Agent": "CASE-Kerala-Cyber-Cell",
    }
    params = {"truncateResponse": "false"}

    try:
        resp = requests.get(
            endpoint, headers=headers, params=params,
            timeout=REQUEST_TIMEOUT)

        # 404 means NOT breached — this is success, not error
        if resp.status_code == 404:
            return {
                "source": "haveibeenpwned",
                "email": email,
                "breach_count": 0,
                "breaches": [],
                "breach_details": [],
                "is_breached": False,
                "error": None,
            }

        if resp.status_code == 401:
            return {
                "source": "haveibeenpwned",
                "error": "invalid_api_key",
                "email": email,
                "is_breached": None,
            }

        if resp.status_code == 429:
            return {
                "source": "haveibeenpwned",
                "error": "rate_limited",
                "email": email,
                "is_breached": None,
            }

        resp.raise_for_status()
        data = resp.json()

        breach_names = [b.get("Name", "") for b in data]
        breach_details = [
            {
                "name": b.get("Name", ""),
                "date": b.get("BreachDate", ""),
                "data_classes": b.get("DataClasses", []),
            }
            for b in data
        ]

        return {
            "source": "haveibeenpwned",
            "email": email,
            "breach_count": len(data),
            "breaches": breach_names,
            "breach_details": breach_details,
            "is_breached": len(data) > 0,
            "error": None,
        }

    except requests.exceptions.Timeout:
        return _make_error_result("haveibeenpwned", email, "timeout")
    except requests.exceptions.RequestException as e:
        return _make_error_result("haveibeenpwned", email, str(e))
    except Exception as e:
        return _make_error_result("haveibeenpwned", email, str(e))


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 7 — Email Domain Age / Disposable Check (Day 3)
# ══════════════════════════════════════════════════════════════════════════════

# Known disposable email domains used in fraud
DISPOSABLE_DOMAINS = [
    "tempmail.com", "guerrillamail.com", "mailinator.com",
    "10minutemail.com", "throwawaymail.com", "yopmail.com",
    "trashmail.com", "getnada.com", "fakeinbox.com",
    "guerrillamail.info", "grr.la", "sharklasers.com",
    "guerrillamail.net", "tempail.com", "dispostable.com",
]


def analyze_email_domain(email):
    """
    Analyse the domain part of an email address for fraud signals.

    Checks domain age via RDAP and flags disposable email providers.

    Args:
        email: Email address to analyse.

    Returns:
        dict with domain analysis data.
    """
    domain = ""
    if "@" in email:
        domain = email.split("@", 1)[1].lower().strip()

    if not domain:
        return {
            "source": "domain_age_check",
            "email": email,
            "domain": "",
            "error": "invalid_email_no_domain",
        }

    # Check disposable domain list
    is_disposable = domain in DISPOSABLE_DOMAINS

    # Query RDAP for domain registration date
    domain_created = None
    domain_age_days = None
    is_newly_registered = False
    registrar = None

    try:
        resp = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=8)

        if resp.status_code == 200:
            data = resp.json()
            events = data.get("events", [])
            for event in events:
                if event.get("eventAction") == "registration":
                    domain_created = event.get("eventDate", "")
                    break

            # Parse date and calculate age
            if domain_created:
                # Handle ISO format dates
                date_str = domain_created.split("T")[0]
                try:
                    created_dt = datetime.strptime(
                        date_str, "%Y-%m-%d")
                    domain_age_days = (
                        datetime.now() - created_dt).days
                    is_newly_registered = domain_age_days < 30
                except ValueError:
                    pass

            # Extract registrar
            entities = data.get("entities", [])
            for entity in entities:
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) > 1:
                        for field in vcard[1]:
                            if field[0] == "fn":
                                registrar = field[3]
                                break
                    if not registrar:
                        registrar = entity.get("handle", "")
                    break

    except Exception:
        pass  # RDAP lookup is best-effort

    return {
        "source": "domain_age_check",
        "email": email,
        "domain": domain,
        "domain_created_date": domain_created,
        "domain_age_days": domain_age_days,
        "is_newly_registered": is_newly_registered,
        "is_disposable_domain": is_disposable,
        "registrar": registrar,
        "error": None,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 8 — Username Platform Presence Check (Day 3)
# ══════════════════════════════════════════════════════════════════════════════

PLATFORMS_TO_CHECK = {
    "Instagram": "https://www.instagram.com/{username}/",
    "Twitter/X": "https://x.com/{username}",
    "Telegram": "https://t.me/{username}",
    "GitHub": "https://github.com/{username}",
    "Facebook": "https://www.facebook.com/{username}",
}

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/120.0.0.0 Safari/537.36")


def username_presence_check(username):
    """
    Check if a username exists on major social platforms.

    Best-effort heuristic check using HTTP status codes.

    Args:
        username: Username string to check.

    Returns:
        dict with presence indicators per platform.
    """
    results = {}
    platforms_found = []
    platforms_checked = list(PLATFORMS_TO_CHECK.keys())
    headers = {"User-Agent": BROWSER_UA}

    for platform, url_template in PLATFORMS_TO_CHECK.items():
        url = url_template.format(username=username)
        try:
            resp = requests.get(
                url, headers=headers, timeout=8,
                allow_redirects=True)

            if resp.status_code == 200:
                results[platform] = "found"
                platforms_found.append(platform)
            elif resp.status_code == 404:
                results[platform] = "not_found"
            else:
                results[platform] = "uncertain"

        except Exception:
            results[platform] = "uncertain"

        time.sleep(1)  # avoid rate limiting

    return {
        "source": "username_presence",
        "username": username,
        "platforms_found": platforms_found,
        "platforms_checked": platforms_checked,
        "results": results,
        "error": None,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 9 — Phone Number OSINT + Cross-Case Linking (Day 3)
# ══════════════════════════════════════════════════════════════════════════════

def phone_lookup(phone_number, current_case_id=None):
    """
    Validate Indian phone number format and check for cross-case
    linkage in the local cases.db database.

    Args:
        phone_number:    Phone number string.
        current_case_id: Integer ID of the current case (to exclude
                         from cross-case results).

    Returns:
        dict with validation and cross-case linking data.
    """
    # Clean the number
    cleaned = re.sub(r"[\s\-\(\)]", "", str(phone_number))
    cleaned = re.sub(r"^(\+91|91|0)", "", cleaned)

    # Validate format
    is_valid = bool(re.fullmatch(r"[6-9]\d{9}", cleaned))

    # Cross-case linking — the killer feature
    linked_cases = []
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = """
            SELECT cases.case_number, cases.crime_name,
                   cases.date_filed
            FROM iocs
            JOIN cases ON iocs.case_id = cases.id
            WHERE iocs.ioc_type = 'phone'
              AND iocs.ioc_value = ?
        """
        params = [cleaned]

        if current_case_id is not None:
            query += " AND iocs.case_id != ?"
            params.append(current_case_id)

        cursor.execute(query, params)
        for row in cursor.fetchall():
            linked_cases.append({
                "case_number": row["case_number"],
                "crime_name": row["crime_name"],
                "date_filed": row["date_filed"],
            })
        conn.close()

    except Exception as e:
        print(f"  [DEBUG] Cross-case phone query error: {e}")

    return {
        "source": "phone_osint",
        "phone": cleaned,
        "is_valid_format": is_valid,
        "linked_cases": linked_cases,
        "is_repeat_offender_number": len(linked_cases) > 0,
        "error": None,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 10 — UPI ID / Wallet Cross-Case Linking (Day 3)
# ══════════════════════════════════════════════════════════════════════════════

def upi_wallet_lookup(value, ioc_type, current_case_id=None):
    """
    Check for cross-case pattern linking of UPI IDs or
    crypto wallet addresses in the local cases.db.

    Args:
        value:           The UPI ID or wallet address string.
        ioc_type:        "upi_id" or "wallet".
        current_case_id: Integer ID of the current case.

    Returns:
        dict with cross-case linking data.
    """
    linked_cases = []
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = """
            SELECT cases.case_number, cases.crime_name,
                   cases.date_filed
            FROM iocs
            JOIN cases ON iocs.case_id = cases.id
            WHERE iocs.ioc_type = ?
              AND iocs.ioc_value = ?
        """
        params = [ioc_type, value]

        if current_case_id is not None:
            query += " AND iocs.case_id != ?"
            params.append(current_case_id)

        cursor.execute(query, params)
        for row in cursor.fetchall():
            linked_cases.append({
                "case_number": row["case_number"],
                "crime_name": row["crime_name"],
                "date_filed": row["date_filed"],
            })
        conn.close()

    except Exception as e:
        print(f"  [DEBUG] Cross-case {ioc_type} query error: {e}")

    type_label = "NPCI" if ioc_type == "upi_id" else "blockchain"

    return {
        "source": "cross_case_linker",
        "ioc_type": ioc_type,
        "value": value,
        "linked_cases": linked_cases,
        "is_repeat_pattern": len(linked_cases) > 0,
        "note": (f"Live {type_label} trace requires LEA legal "
                 f"request \u2014 not available via public API"),
        "error": None,
    }


# ══════════════════════════════════════════════════════════════════════════════
#  ORCHESTRATOR — run_osint()
# ══════════════════════════════════════════════════════════════════════════════

def run_osint(ioc_type, ioc_value, current_case_id=None):
    """
    Main OSINT dispatcher. Routes an IOC to the correct module(s)
    and returns aggregated results.

    Args:
        ioc_type:       One of "ip", "url", "domain", "hash",
                        "phone", "email", "upi_id", "wallet".
        ioc_value:      The IOC value string.
        current_case_id: Integer case ID for cross-case linking.

    Returns:
        dict with keys: ioc_type, ioc_value, results (list),
        is_malicious (bool), and optional notes.
    """
    # ── IP addresses ──────────────────────────────────────────────────────
    if ioc_type == "ip":
        if is_private_ip(ioc_value):
            return {
                "ioc_type": "ip",
                "ioc_value": ioc_value,
                "results": [],
                "is_malicious": False,
                "note": "private_ip_skipped",
            }

        results = []
        results.append(vt_lookup(ioc_value, "ip"))
        results.append(abuseipdb_lookup(ioc_value))
        results.append(ipinfo_lookup(ioc_value))

        flagged = any(
            r.get("is_malicious", False) for r in results
            if "error" not in r
        )

        return {
            "ioc_type": "ip",
            "ioc_value": ioc_value,
            "results": results,
            "is_malicious": flagged,
        }

    # ── URLs ──────────────────────────────────────────────────────────────
    if ioc_type == "url":
        domain = extract_domain(ioc_value)
        results = []
        results.append(vt_lookup(ioc_value, "url"))
        if domain:
            results.append(vt_lookup(domain, "domain"))
        results.append(phishtank_lookup(ioc_value))
        results.append(urlscan_lookup(ioc_value))

        flagged = any(
            r.get("is_malicious", False) or r.get("is_phishing", False)
            or r.get("verdict_malicious", False)
            for r in results if "error" not in r
        )

        return {
            "ioc_type": "url",
            "ioc_value": ioc_value,
            "domain": domain,
            "results": results,
            "is_malicious": flagged,
        }

    # ── Domains ───────────────────────────────────────────────────────────
    if ioc_type == "domain":
        results = []
        results.append(vt_lookup(ioc_value, "domain"))

        flagged = any(
            r.get("is_malicious", False) for r in results
            if "error" not in r
        )

        return {
            "ioc_type": "domain",
            "ioc_value": ioc_value,
            "results": results,
            "is_malicious": flagged,
        }

    # ── File hashes ───────────────────────────────────────────────────────
    if ioc_type == "hash":
        results = []
        results.append(vt_lookup(ioc_value, "hash"))

        flagged = any(
            r.get("is_malicious", False) for r in results
            if "error" not in r
        )

        return {
            "ioc_type": "hash",
            "ioc_value": ioc_value,
            "results": results,
            "is_malicious": flagged,
        }

    # ── Phone numbers (Day 3) ─────────────────────────────────────────────
    if ioc_type == "phone":
        result = phone_lookup(ioc_value, current_case_id)
        return {
            "ioc_type": "phone",
            "ioc_value": ioc_value,
            "results": [result],
            "is_malicious": result.get(
                "is_repeat_offender_number", False),
        }

    # ── Email addresses (Day 3) ───────────────────────────────────────────
    if ioc_type == "email":
        results = []
        results.append(hibp_lookup(ioc_value))
        results.append(analyze_email_domain(ioc_value))
        # Extract username from email for presence check
        username = ioc_value.split("@")[0] if "@" in ioc_value else ""
        if username and len(username) >= 3:
            results.append(username_presence_check(username))
        is_flag = any([
            results[0].get("is_breached"),
            results[1].get("is_disposable_domain"),
            results[1].get("is_newly_registered"),
        ])
        return {
            "ioc_type": "email",
            "ioc_value": ioc_value,
            "results": results,
            "is_malicious": bool(is_flag),
        }

    # ── UPI IDs (Day 3) ───────────────────────────────────────────────────
    if ioc_type == "upi_id":
        result = upi_wallet_lookup(
            ioc_value, "upi_id", current_case_id)
        return {
            "ioc_type": "upi_id",
            "ioc_value": ioc_value,
            "results": [result],
            "is_malicious": result.get("is_repeat_pattern", False),
        }

    # ── Crypto wallets (Day 3) ────────────────────────────────────────────
    if ioc_type == "wallet":
        result = upi_wallet_lookup(
            ioc_value, "wallet", current_case_id)
        return {
            "ioc_type": "wallet",
            "ioc_value": ioc_value,
            "results": [result],
            "is_malicious": result.get("is_repeat_pattern", False),
        }

    # ── Unknown IOC type ──────────────────────────────────────────────────
    return {
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "results": [],
        "is_malicious": False,
        "note": f"Unknown IOC type: {ioc_type}",
    }
