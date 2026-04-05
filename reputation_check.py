"""
reputation_check.py — Threat Intelligence Aggregator
Queries VirusTotal, AbuseIPDB, and WHOIS for a given IP / domain.
"""

import os
import time
import json
import socket
import logging
import requests
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger("SOC-Reputation")

# ── API Keys (set via environment variables) ──────────────────────────────────
VT_API_KEY      = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_VT_KEY_HERE")
ABUSEIPDB_KEY   = os.getenv("ABUSEIPDB_API_KEY",  "YOUR_ABUSE_KEY_HERE")

VT_BASE         = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE  = "https://api.abuseipdb.com/api/v2"


class ReputationChecker:
    """Aggregates threat-intel from multiple sources into one reputation dict."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SOC-Automation-Lab/1.0"})

    # ── Public entry point ────────────────────────────────────────────────────
    def investigate(self, ip: Optional[str], domain: Optional[str] = None) -> dict:
        rep = {
            "ip":           ip,
            "domain":       domain,
            "virustotal":   self._check_virustotal(ip),
            "abuseipdb":    self._check_abuseipdb(ip),
            "whois":        self._check_whois(ip),
            "geo":          self._geolocate(ip),
            "checked_at":   datetime.now(timezone.utc).isoformat(),
        }
        if domain:
            rep["domain_vt"] = self._check_virustotal_domain(domain)
        return rep

    # ── VirusTotal ─────────────────────────────────────────────────────────────
    def _check_virustotal(self, ip: Optional[str]) -> dict:
        if not ip or VT_API_KEY == "YOUR_VT_KEY_HERE":
            return self._mock_vt(ip)
        try:
            r = self.session.get(
                f"{VT_BASE}/ip_addresses/{ip}",
                headers={"x-apikey": VT_API_KEY},
                timeout=self.timeout,
            )
            r.raise_for_status()
            data  = r.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious":    stats.get("malicious", 0),
                "suspicious":   stats.get("suspicious", 0),
                "harmless":     stats.get("harmless", 0),
                "undetected":   stats.get("undetected", 0),
                "reputation":   data.get("reputation", 0),
                "country":      data.get("country", "N/A"),
                "as_owner":     data.get("as_owner", "N/A"),
            }
        except Exception as e:
            log.warning(f"VirusTotal error for {ip}: {e}")
            return {"error": str(e)}

    def _check_virustotal_domain(self, domain: str) -> dict:
        if VT_API_KEY == "YOUR_VT_KEY_HERE":
            return {"note": "API key not configured"}
        try:
            r = self.session.get(
                f"{VT_BASE}/domains/{domain}",
                headers={"x-apikey": VT_API_KEY},
                timeout=self.timeout,
            )
            r.raise_for_status()
            data  = r.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "categories": data.get("categories", {}),
                "reputation": data.get("reputation", 0),
            }
        except Exception as e:
            log.warning(f"VT domain error for {domain}: {e}")
            return {"error": str(e)}

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────
    def _check_abuseipdb(self, ip: Optional[str]) -> dict:
        if not ip or ABUSEIPDB_KEY == "YOUR_ABUSE_KEY_HERE":
            return self._mock_abuse(ip)
        try:
            r = self.session.get(
                f"{ABUSEIPDB_BASE}/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                timeout=self.timeout,
            )
            r.raise_for_status()
            d = r.json()["data"]
            return {
                "abuse_score":    d.get("abuseConfidenceScore", 0),
                "total_reports":  d.get("totalReports", 0),
                "distinct_users": d.get("numDistinctUsers", 0),
                "last_reported":  d.get("lastReportedAt"),
                "isp":            d.get("isp", "N/A"),
                "usage_type":     d.get("usageType", "N/A"),
                "country":        d.get("countryCode", "N/A"),
                "is_tor":         d.get("isTor", False),
                "is_public":      d.get("isPublic", True),
            }
        except Exception as e:
            log.warning(f"AbuseIPDB error for {ip}: {e}")
            return {"error": str(e)}

    # ── WHOIS (socket-based lightweight lookup) ───────────────────────────────
    def _check_whois(self, ip: Optional[str]) -> dict:
        if not ip:
            return {}
        try:
            # Use ARIN RDAP (no auth needed)
            r = requests.get(
                f"https://rdap.arin.net/registry/ip/{ip}",
                timeout=self.timeout,
            )
            if r.status_code == 200:
                data = r.json()
                org  = "N/A"
                for entity in data.get("entities", []):
                    vcards = entity.get("vcardArray", [])
                    if vcards and len(vcards) > 1:
                        for prop in vcards[1]:
                            if prop[0] == "fn":
                                org = prop[3]
                                break
                return {
                    "network_name": data.get("name", "N/A"),
                    "organization": org,
                    "start_address": data.get("startAddress", "N/A"),
                    "end_address":   data.get("endAddress", "N/A"),
                    "type":          data.get("type", "N/A"),
                }
        except Exception as e:
            log.warning(f"WHOIS error for {ip}: {e}")
        return {"error": "WHOIS lookup failed"}

    # ── Geo (ip-api.com — free, no key needed) ────────────────────────────────
    def _geolocate(self, ip: Optional[str]) -> dict:
        if not ip:
            return {}
        try:
            r = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as",
                timeout=self.timeout,
            )
            data = r.json()
            if data.get("status") == "success":
                return {
                    "country":     data.get("country"),
                    "region":      data.get("regionName"),
                    "city":        data.get("city"),
                    "isp":         data.get("isp"),
                    "org":         data.get("org"),
                    "asn":         data.get("as"),
                }
        except Exception as e:
            log.warning(f"Geo error for {ip}: {e}")
        return {}

    # ── Mock data (when API keys not configured) ──────────────────────────────
    @staticmethod
    def _mock_vt(ip):
        return {
            "note":       "Demo mode — configure VIRUSTOTAL_API_KEY",
            "malicious":  7,
            "suspicious": 2,
            "harmless":   50,
            "undetected": 15,
            "reputation": -15,
            "country":    "RU",
            "as_owner":   "DigitalOcean",
        }

    @staticmethod
    def _mock_abuse(ip):
        return {
            "note":           "Demo mode — configure ABUSEIPDB_API_KEY",
            "abuse_score":    87,
            "total_reports":  245,
            "distinct_users": 38,
            "last_reported":  "2025-01-14T09:12:00+00:00",
            "isp":            "DigitalOcean LLC",
            "usage_type":     "Data Center/Web Hosting/Transit",
            "country":        "RU",
            "is_tor":         False,
            "is_public":      True,
        }


# ── CLI test ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    checker = ReputationChecker()
    result  = checker.investigate("45.33.32.156")
    print(json.dumps(result, indent=2, default=str))
