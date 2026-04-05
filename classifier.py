"""
classifier.py — Threat Classification Engine
Rule-based scoring + optional ML model for threat level classification.
"""

import logging
from typing import Tuple

log = logging.getLogger("SOC-Classifier")


class ThreatClassifier:
    """
    Scores an event + reputation bundle and returns a threat level.

    Scoring bands:
        0  – 25  → LOW
        26 – 55  → MEDIUM
        56 – 80  → HIGH
        81 – 100 → CRITICAL
    """

    # Scoring weights (sum of all max weights = ~100)
    W = {
        "abuse_score":       0.35,   # AbuseIPDB confidence (0-100) × 0.35  → max 35
        "vt_malicious":      2.0,    # each malicious VT engine       → max ~20
        "vt_suspicious":     1.0,    # each suspicious VT engine
        "vt_reputation":    -0.1,    # VT reputation (can be negative) → penalty/bonus
        "event_count":       0.03,   # raw event count (brute force hits)
        "is_tor":            15,     # flat bonus if TOR exit node
        "is_datacenter":     5,      # flat bonus if datacenter IP
        "siem_severity": {           # SIEM's own severity label
            "critical": 20,
            "high":     15,
            "medium":    8,
            "low":       2,
            "info":      0,
        },
    }

    BANDS = [
        (81, "CRITICAL"),
        (56, "HIGH"),
        (26, "MEDIUM"),
        (0,  "LOW"),
    ]

    # ── Public API ────────────────────────────────────────────────────────────

    def score(self, event: dict, reputation: dict) -> float:
        """Return a float threat score in [0, 100]."""
        s = 0.0
        vt    = reputation.get("virustotal",  {})
        abuse = reputation.get("abuseipdb",   {})

        # AbuseIPDB confidence
        s += abuse.get("abuse_score", 0) * self.W["abuse_score"]

        # VirusTotal detections
        s += min(vt.get("malicious",  0), 10) * self.W["vt_malicious"]
        s += min(vt.get("suspicious", 0), 10) * self.W["vt_suspicious"]
        s += vt.get("reputation", 0)          * self.W["vt_reputation"]

        # Raw event count (capped at 500 to avoid domination)
        s += min(event.get("raw_count", 0), 500) * self.W["event_count"]

        # TOR exit node bonus
        if abuse.get("is_tor", False):
            s += self.W["is_tor"]

        # Data-center hosting bonus
        if "data center" in abuse.get("usage_type", "").lower():
            s += self.W["is_datacenter"]

        # SIEM severity label
        siem_sev = event.get("siem_sev", "medium").lower()
        s += self.W["siem_severity"].get(siem_sev, 8)

        return round(min(max(s, 0), 100), 2)

    def classify(self, score: float) -> str:
        """Map numeric score to named threat level."""
        for threshold, label in self.BANDS:
            if score >= threshold:
                return label
        return "LOW"

    def explain(self, event: dict, reputation: dict) -> dict:
        """Return a human-readable score breakdown."""
        vt    = reputation.get("virustotal", {})
        abuse = reputation.get("abuseipdb",  {})
        siem_sev = event.get("siem_sev", "medium").lower()

        breakdown = {
            "abuse_contribution":  round(abuse.get("abuse_score", 0) * self.W["abuse_score"], 2),
            "vt_malicious_contrib": round(min(vt.get("malicious", 0), 10) * self.W["vt_malicious"], 2),
            "vt_suspicious_contrib": round(min(vt.get("suspicious", 0), 10) * self.W["vt_suspicious"], 2),
            "vt_reputation_contrib": round(vt.get("reputation", 0) * self.W["vt_reputation"], 2),
            "event_count_contrib":  round(min(event.get("raw_count", 0), 500) * self.W["event_count"], 2),
            "tor_bonus":            self.W["is_tor"] if abuse.get("is_tor") else 0,
            "datacenter_bonus":     self.W["is_datacenter"] if "data center" in abuse.get("usage_type", "").lower() else 0,
            "siem_sev_contrib":     self.W["siem_severity"].get(siem_sev, 8),
        }

        total = round(sum(breakdown.values()), 2)
        level = self.classify(total)

        return {
            "score":     min(total, 100),
            "level":     level,
            "breakdown": breakdown,
        }


# ── ML Extension Point ────────────────────────────────────────────────────────
class MLThreatClassifier(ThreatClassifier):
    """
    Drop-in replacement that uses a trained sklearn model when available,
    falling back to the rule-based scorer if the model isn't loaded.

    Train with:  python train_model.py
    """

    def __init__(self, model_path: str = "../ai_model/threat_model.pkl"):
        super().__init__()
        self._model = None
        self._scaler = None
        try:
            import pickle
            with open(model_path, "rb") as f:
                bundle = pickle.load(f)
                self._model  = bundle["model"]
                self._scaler = bundle["scaler"]
            log.info("ML model loaded successfully.")
        except FileNotFoundError:
            log.info("No ML model found — using rule-based classifier.")
        except Exception as e:
            log.warning(f"ML model load failed: {e} — using rule-based classifier.")

    def score(self, event: dict, reputation: dict) -> float:
        if self._model is None:
            return super().score(event, reputation)

        features = self._extract_features(event, reputation)
        try:
            scaled = self._scaler.transform([features])
            proba  = self._model.predict_proba(scaled)[0]
            # Map probability of "malicious" class to 0-100 score
            return round(float(proba[1]) * 100, 2)
        except Exception as e:
            log.warning(f"ML inference error: {e} — falling back to rules.")
            return super().score(event, reputation)

    @staticmethod
    def _extract_features(event: dict, reputation: dict) -> list:
        vt    = reputation.get("virustotal", {})
        abuse = reputation.get("abuseipdb",  {})
        return [
            abuse.get("abuse_score",    0),
            vt.get("malicious",         0),
            vt.get("suspicious",        0),
            vt.get("reputation",        0),
            event.get("raw_count",      0),
            int(abuse.get("is_tor",     False)),
            abuse.get("total_reports",  0),
            abuse.get("distinct_users", 0),
        ]


# ── CLI test ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json
    clf = ThreatClassifier()

    mock_event = {"raw_count": 312, "siem_sev": "high"}
    mock_rep   = {
        "virustotal": {"malicious": 7, "suspicious": 2, "reputation": -15},
        "abuseipdb":  {"abuse_score": 87, "is_tor": False, "usage_type": "Data Center/Web Hosting"},
    }

    explanation = clf.explain(mock_event, mock_rep)
    print(json.dumps(explanation, indent=2))
