"""
analyzer.py — Core SOC Automation Engine
Orchestrates detection → investigation → AI decision → response pipeline
"""

import json
import time
import logging
from datetime import datetime
from pathlib import Path

from reputation_check import ReputationChecker
from response import ResponseEngine

# ── Ensure logs directory exists ─────────────────────────────────────────────
Path("../logs").mkdir(parents=True, exist_ok=True)

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("../logs/soc_pipeline.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("SOC-Analyzer")


# ── Alert Parser ──────────────────────────────────────────────────────────────
def parse_alert(alert: dict) -> dict:
    """
    Normalize an incoming SIEM alert into a standard event object.

    Expected SIEM alert format (ELK / Splunk / custom):
    {
        "timestamp": "2025-01-15T14:23:00Z",
        "rule":      "Brute Force Detected",
        "source_ip": "45.33.32.156",
        "target":    "10.0.0.5",
        "count":     312,
        "severity":  "medium",
        "tags":      ["authentication", "brute_force"]
    }
    """
    return {
        "id":         f"EVT-{int(time.time())}",
        "timestamp":  alert.get("timestamp", datetime.utcnow().isoformat()),
        "rule":       alert.get("rule", "Unknown Rule"),
        "source_ip":  alert.get("source_ip"),
        "domain":     alert.get("domain"),
        "target":     alert.get("target", "unknown"),
        "raw_count":  alert.get("count", 0),
        "siem_sev":   alert.get("severity", "medium"),
        "tags":       alert.get("tags", []),
    }


# ── Pipeline ──────────────────────────────────────────────────────────────────
def run_pipeline(alert: dict) -> dict:
    """
    Full SOC automation pipeline for a single alert.
    Returns a completed incident case dict.
    """
    event   = parse_alert(alert)
    checker = ReputationChecker()
    engine  = ResponseEngine()

    log.info(f"[{event['id']}] Pipeline started — Rule: {event['rule']}")

    # Step 1 — Reputation Investigation
    log.info(f"[{event['id']}] Investigating source: {event['source_ip']}")
    rep = checker.investigate(event["source_ip"], event.get("domain"))

    # Step 2 — AI / Rule-based Classification
    from classifier import ThreatClassifier
    clf   = ThreatClassifier()
    score = clf.score(event, rep)
    level = clf.classify(score)
    log.info(f"[{event['id']}] Threat level: {level} (score={score})")

    # Step 3 — Automated Response
    actions = engine.respond(event, level, rep)
    log.info(f"[{event['id']}] Response actions: {actions}")

    # Step 4 — Build case record
    case = {
        "case_id":          event["id"],
        "timestamp":        event["timestamp"],
        "rule_triggered":   event["rule"],
        "source_ip":        event["source_ip"],
        "target":           event["target"],
        "reputation":       rep,
        "threat_score":     score,
        "threat_level":     level,
        "response_actions": actions,
        "status":           "closed",
    }

    # Step 5 — Persist report
    _save_report(case)
    log.info(f"[{event['id']}] Case closed → reports/incident_{event['id']}.json")
    return case


# ── Report Writer ─────────────────────────────────────────────────────────────
def _save_report(case: dict):
    out_dir = Path("../reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"incident_{case['case_id']}.json"
    with open(path, "w") as f:
        json.dump(case, f, indent=2, default=str)


# ── Demo / Manual Trigger ─────────────────────────────────────────────────────
if __name__ == "__main__":
    sample_alert = {
        "timestamp":  "2025-01-15T14:23:00Z",
        "rule":       "Brute Force — SSH",
        "source_ip":  "45.33.32.156",
        "target":     "10.0.0.5",
        "count":      312,
        "severity":   "high",
        "tags":       ["authentication", "brute_force", "ssh"],
    }

    result = run_pipeline(sample_alert)
    print("\n" + "="*60)
    print("INCIDENT REPORT")
    print("="*60)
    print(json.dumps(result, indent=2, default=str))
