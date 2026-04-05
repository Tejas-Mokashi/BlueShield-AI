# 🛡️ BlueShield-AI

> **End-to-End AI-Powered Security Operations Center Automation**  
> Detect → Investigate → Classify → Respond — fully automated.

---

## 🧠 Architecture

```
SIEM (ELK / Splunk)
        │
        ▼  alert (JSON)
 siem_listener.py          ← listens for alerts (file / ELK / Splunk webhook)
        │
        ▼
   analyzer.py             ← orchestrates the full pipeline
        │
        ├─► reputation_check.py    → VirusTotal + AbuseIPDB + WHOIS + Geo
        │
        ├─► classifier.py          → rule-based scoring + optional ML model
        │
        └─► response.py            → block IP | alert | report | escalate
                │
                └─► reports/incident_*.json
```

---

## 🚀 Quick Start

### 1. Clone & install dependencies

```bash
git clone https://github.com/yourname/BlueShield-AI
cd BlueShield-AI
pip install -r requirements.txt
```

### 2. Set API keys

```bash
export VIRUSTOTAL_API_KEY="your_key_here"
export ABUSEIPDB_API_KEY="your_key_here"
```

> **Free tiers:**  
> - VirusTotal: https://www.virustotal.com/gui/join-us  
> - AbuseIPDB: https://www.abuseipdb.com/register

### 3. Run in demo mode (no API keys needed)

```bash
cd automation
python analyzer.py
```

### 4. Start the real-time listener

```bash
# File mode (simplest)
python detection/siem_listener.py --mode file --file logs/alerts.jsonl

# ELK mode
python detection/siem_listener.py --mode elk --elk http://localhost:9200

# Splunk webhook mode
python detection/siem_listener.py --mode splunk --port 8888
```

---

## 📁 Project Structure

```
BlueShield-AI/
│
├── logs/
│   ├── soc_pipeline.log        # pipeline execution log
│   ├── blocked_ips.json        # blocked IP ledger
│   └── cases.jsonl             # all cases (append-only)
│
├── detection/
│   ├── siem_listener.py        # real-time alert watcher (ELK/Splunk/file)
│   └── siem_rules.txt          # KQL / SPL / Sigma rule templates
│
├── automation/
│   ├── analyzer.py             # main pipeline orchestrator
│   ├── reputation_check.py     # VirusTotal + AbuseIPDB + WHOIS
│   └── response.py             # automated response playbooks
│
├── ai_model/
│   └── classifier.py           # rule-based + ML threat classifier
│
├── reports/
│   └── incident_*.json         # auto-generated incident reports
│
└── README.md
```

---

## 🔬 Pipeline Steps

| Step | Component | What it does |
|------|-----------|--------------|
| 1 | SIEM | Detects anomaly (brute force, scan, C2, etc.) |
| 2 | `siem_listener.py` | Listens for alert, normalizes it |
| 3 | `reputation_check.py` | Checks VirusTotal, AbuseIPDB, WHOIS, Geo |
| 4 | `classifier.py` | Scores threat (0–100), classifies: LOW/MEDIUM/HIGH/CRITICAL |
| 5 | `response.py` | Executes playbook: block, alert, report, escalate |

---

## 🎭 Threat Level Playbooks

| Level    | Score  | Actions |
|----------|--------|---------|
| LOW      | 0–25   | log + report |
| MEDIUM   | 26–55  | log + alert analyst + report |
| HIGH     | 56–80  | **block IP** + log + alert + report + escalate |
| CRITICAL | 81–100 | **block IP** + log + alert + report + escalate + emergency notify |

---

## 🔌 Integrations

### SIEM Support
- ✅ **ELK / Elastic SIEM** — direct Elasticsearch polling
- ✅ **Splunk** — webhook receiver (HTTP listener)
- ✅ **Any SIEM** — file-based (write alerts to `logs/alerts.jsonl`)

### Threat Intelligence
- ✅ **VirusTotal** — IP/domain analysis (free tier: 500 req/day)
- ✅ **AbuseIPDB** — IP reputation (free tier: 1000 req/day)
- ✅ **RDAP/WHOIS** — network ownership (no key needed)
- ✅ **ip-api.com** — geolocation (no key needed, 45 req/min)

### Response Actions
- ✅ Linux `iptables` — live IP blocking (requires root)
- ✅ Block-list ledger (`logs/blocked_ips.json`)
- ✅ Analyst alert (console / extend to Slack / PagerDuty)
- ✅ Automated incident report (JSON)
- ✅ Case logging (`logs/cases.jsonl`)
- 🔌 Ticketing (TheHive / JIRA / ServiceNow — extend `response.py`)

---

## 🤖 AI / ML Classifier

BlueShield-AI's `ThreatClassifier` uses a weighted rule-based scoring model by default. To train and use the optional ML model:

```bash
# 1. Generate training data (run some alerts through the pipeline)
# 2. Train the model
python ai_model/train_model.py   # coming soon

# 3. Use it automatically (drop-in replacement)
from ai_model.classifier import MLThreatClassifier
clf = MLThreatClassifier()
```

The ML classifier uses these features:
- AbuseIPDB confidence score
- VirusTotal malicious/suspicious engine counts
- VT reputation score
- Raw event count
- TOR exit node flag
- Total prior abuse reports
- Distinct reporting users

---

## 🧪 Example Scenario

```
[14:23:00] SSH brute force — 312 failed logins from 45.33.32.156
[14:24:01] BlueShield-AI pipeline triggered
[14:24:03] VirusTotal: 7 malicious engines, reputation -15
[14:24:04] AbuseIPDB: 87% confidence, 245 reports from 38 users
[14:24:05] Classifier: score=79.45 → HIGH
[14:24:05] Playbook: block_ip + alert_analyst + generate_report + escalate
[14:25:03] Case closed → reports/incident_EVT-1736951100.json
```

---

## 📋 Requirements

```
requests>=2.31
elasticsearch>=8.0      # optional: ELK mode
flask>=3.0              # optional: Splunk webhook mode
scikit-learn>=1.4       # optional: ML classifier
```

---

## 🛡️ MITRE ATT&CK Coverage

Detection rules cover: T1110 (Brute Force), T1046 (Network Scan),
T1071 (C2 Beaconing), T1550.002 (Pass-the-Hash), T1548 (Privilege Escalation),
T1204 (Malware Execution), T1071.004 (DNS Tunneling).

---

*BlueShield-AI — Built as an educational SOC automation project. Response actions are simulated by default.*
