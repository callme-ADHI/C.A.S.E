"""
C.A.S.E. — Cyber Attack Scene Examiner
OSINT Engine — Day 2

Unified OSINT module containing:
  1. VirusTotal     — IP, URL, domain, hash lookups
  2. AbuseIPDB      — IP abuse scoring
  3. IPInfo         — IP geolocation + ASN
  4. PhishTank      — URL phishing check (no key needed)
  5. URLScan.io     — URL scanning + screenshot capture

Orchestrator function run_osint() dispatches IOCs to the correct
module(s) and returns structured, aggregated results.
"""

import base64
import ipaddress
import json
import time
from urllib.parse import urlparse

import requests

from config.config import VT_KEY, ABUSEIPDB_KEY, IPINFO_KEY, URLSCAN_KEY

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
#  ORCHESTRATOR — run_osint()
# ══════════════════════════════════════════════════════════════════════════════

def run_osint(ioc_type, ioc_value):
    """
    Main OSINT dispatcher. Routes an IOC to the correct module(s)
    and returns aggregated results.

    Args:
        ioc_type:  One of "ip", "url", "domain", "hash",
                   "phone", "email", "upi_id", "wallet".
        ioc_value: The IOC value string.

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

    # ── Day 3 IOCs (phone, email, upi_id, wallet) ────────────────────────
    if ioc_type in ("phone", "email", "upi_id", "wallet"):
        day3_notes = {
            "phone": "Phone OSINT queued for Day 3 (Truecaller + DOT FRI)",
            "email": "Email OSINT queued for Day 3 (HIBP + Holehe + Sherlock)",
            "upi_id": "UPI OSINT queued for Day 3 (NPCI trace)",
            "wallet": "Wallet tracing queued for Day 3 (blockchain explorer)",
        }
        return {
            "ioc_type": ioc_type,
            "ioc_value": ioc_value,
            "results": [],
            "is_malicious": False,
            "note": day3_notes.get(ioc_type, "Handled in Day 3"),
        }

    # ── Unknown IOC type ──────────────────────────────────────────────────
    return {
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "results": [],
        "is_malicious": False,
        "note": f"Unknown IOC type: {ioc_type}",
    }
