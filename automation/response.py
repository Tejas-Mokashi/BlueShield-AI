"""
response.py — Automated Response Engine
Executes actions based on threat level: block, alert, log, escalate.
"""

import json
import logging
import subprocess
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import List

log = logging.getLogger("SOC-Response")

BLOCKED_IPS_FILE = Path("../logs/blocked_ips.json")
CASES_LOG        = Path("../logs/cases.jsonl")


class ResponseEngine:
    """
    Maps threat levels to response playbooks and executes them.

    Playbooks:
        LOW    → log event, generate report
        MEDIUM → log event, alert analyst, generate report
        HIGH   → block IP, log event, alert analyst, generate report, escalate
        CRITICAL → HIGH + emergency notification
    """

    PLAYBOOKS = {
        "LOW":      ["log_event", "generate_report"],
        "MEDIUM":   ["log_event", "alert_analyst", "generate_report"],
        "HIGH":     ["block_ip", "log_event", "alert_analyst", "generate_report", "escalate"],
        "CRITICAL": ["block_ip", "log_event", "alert_analyst", "generate_report", "escalate", "emergency_notify"],
    }

    def respond(self, event: dict, threat_level: str, reputation: dict) -> List[dict]:
        """Execute the playbook for the given threat level. Returns list of action records."""
        playbook = self.PLAYBOOKS.get(threat_level, self.PLAYBOOKS["MEDIUM"])
        actions  = []

        for action_name in playbook:
            handler = getattr(self, f"_action_{action_name}", None)
            if handler:
                result = handler(event, threat_level, reputation)
                actions.append({"action": action_name, **result})
                log.info(f"  ↳ [{action_name}] {result.get('status', '')}: {result.get('detail', '')}")

        return actions

    # ── Action Handlers ────────────────────────────────────────────────────────

    def _action_block_ip(self, event, level, rep) -> dict:
        ip = event.get("source_ip")
        if not ip:
            return {"status": "skipped", "detail": "No source IP in event"}

        # 1. Save to blocked-IPs ledger
        blocked = self._load_blocked_ips()
        if ip not in blocked:
            blocked[ip] = {
                "blocked_at":  datetime.now(timezone.utc).isoformat(),
                "reason":      f"Threat level {level} — {event.get('rule')}",
                "case_id":     event.get("id"),
            }
            self._save_blocked_ips(blocked)

        # 2. Attempt real firewall rule (Linux iptables / macOS pfctl — skipped in demo)
        fw_result = self._apply_firewall_rule(ip)

        return {
            "status": "success",
            "detail": f"IP {ip} added to block-list. Firewall: {fw_result}",
            "ip":     ip,
        }

    def _action_log_event(self, event, level, rep) -> dict:
        CASES_LOG.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "logged_at":    datetime.now(timezone.utc).isoformat(),
            "case_id":      event.get("id"),
            "rule":         event.get("rule"),
            "source_ip":    event.get("source_ip"),
            "threat_level": level,
            "abuse_score":  rep.get("abuseipdb", {}).get("abuse_score"),
            "vt_malicious": rep.get("virustotal", {}).get("malicious"),
        }
        with open(CASES_LOG, "a") as f:
            f.write(json.dumps(record) + "\n")
        return {"status": "success", "detail": f"Event appended to {CASES_LOG}"}

    def _action_alert_analyst(self, event, level, rep) -> dict:
        # In production: send to SIEM, PagerDuty, Slack webhook, email, etc.
        alert_msg = (
            f"[SOC ALERT] {level} threat detected\n"
            f"Rule:   {event.get('rule')}\n"
            f"IP:     {event.get('source_ip')}\n"
            f"Score:  {rep.get('abuseipdb', {}).get('abuse_score', 'N/A')}%\n"
            f"Case:   {event.get('id')}\n"
            f"Time:   {event.get('timestamp')}"
        )
        log.warning("\n" + alert_msg)
        # TODO: replace with actual webhook
        # requests.post(SLACK_WEBHOOK, json={"text": alert_msg})
        return {"status": "simulated", "detail": "Analyst notification sent (simulated)"}

    def _action_generate_report(self, event, level, rep) -> dict:
        report = {
            "report_type":    "Automated Incident Report",
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "case_id":        event.get("id"),
            "summary": {
                "rule_triggered": event.get("rule"),
                "source_ip":      event.get("source_ip"),
                "target":         event.get("target"),
                "threat_level":   level,
                "event_count":    event.get("raw_count", 0),
            },
            "threat_intelligence": {
                "virustotal": rep.get("virustotal"),
                "abuseipdb":  rep.get("abuseipdb"),
                "whois":      rep.get("whois"),
                "geo":        rep.get("geo"),
            },
            "timeline": [
                {"t": event.get("timestamp"), "event": "Alert triggered by SIEM"},
                {"t": datetime.now(timezone.utc).isoformat(), "event": f"Automated response: {level} playbook executed"},
            ],
            "recommendation": self._recommendation(level),
        }

        out = Path("../reports")
        out.mkdir(parents=True, exist_ok=True)
        path = out / f"incident_{event['id']}.json"
        with open(path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        return {"status": "success", "detail": f"Report saved → {path}"}

    def _action_escalate(self, event, level, rep) -> dict:
        # In production: open ticket in JIRA / ServiceNow / TheHive
        return {
            "status": "simulated",
            "detail": f"Escalation ticket created for case {event.get('id')} (simulated)",
        }

    def _action_emergency_notify(self, event, level, rep) -> dict:
        return {
            "status": "simulated",
            "detail": "CRITICAL — Emergency notification sent to SOC manager (simulated)",
        }

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _apply_firewall_rule(ip: str) -> str:
        """
        Attempt to add a DROP rule via iptables (Linux only).
        Gracefully skipped if not running as root or not on Linux.
        """
        if platform.system() != "Linux":
            return "skipped (non-Linux host)"
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=5,
            )
            return f"iptables DROP rule added for {ip}"
        except (subprocess.CalledProcessError, FileNotFoundError, PermissionError) as e:
            return f"simulated (reason: {e})"

    @staticmethod
    def _load_blocked_ips() -> dict:
        if BLOCKED_IPS_FILE.exists():
            with open(BLOCKED_IPS_FILE) as f:
                return json.load(f)
        return {}

    @staticmethod
    def _save_blocked_ips(data: dict):
        BLOCKED_IPS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(BLOCKED_IPS_FILE, "w") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def _recommendation(level: str) -> str:
        return {
            "LOW":      "Monitor. No immediate action required.",
            "MEDIUM":   "Investigate within 4 hours. Consider temporary block.",
            "HIGH":     "IP blocked. Analyst review required within 1 hour.",
            "CRITICAL": "IP blocked. Immediate analyst escalation. Check lateral movement.",
        }.get(level, "Review manually.")
