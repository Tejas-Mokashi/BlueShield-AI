"""
siem_listener.py — Real-time SIEM Alert Listener
Watches for alerts from ELK (Elasticsearch), Splunk webhook, or a log file.
Triggers the SOC pipeline for each new alert.
"""

import os
import sys
import json
import time
import logging
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Iterator

# Add automation dir to path
sys.path.insert(0, str(Path(__file__).parent / "automation"))

log = logging.getLogger("SOC-Listener")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


# ══════════════════════════════════════════════════════════════════════════════
# Mode 1 — File Watcher (simplest, works with any log shipper)
# ══════════════════════════════════════════════════════════════════════════════

class FileWatcher:
    """
    Tail a JSONL alerts file (one alert JSON per line).
    Compatible with Filebeat, Logstash, or any tool that appends to a file.
    """

    def __init__(self, path: str, poll_interval: float = 1.0):
        self.path = Path(path)
        self.interval = poll_interval
        self._pos = 0

    def alerts(self) -> Iterator[dict]:
        log.info(f"Watching {self.path} for new alerts...")
        while True:
            try:
                if self.path.exists():
                    with open(self.path) as f:
                        f.seek(self._pos)
                        for line in f:
                            line = line.strip()
                            if line:
                                try:
                                    yield json.loads(line)
                                except json.JSONDecodeError as e:
                                    log.warning(f"Bad JSON line: {e}")
                        self._pos = f.tell()
            except Exception as e:
                log.error(f"File watcher error: {e}")
            time.sleep(self.interval)


# ══════════════════════════════════════════════════════════════════════════════
# Mode 2 — Elasticsearch / ELK Watcher
# ══════════════════════════════════════════════════════════════════════════════

class ElasticsearchWatcher:
    """
    Polls an Elasticsearch index for new alerts (e.g. .siem-signals-*).
    Requires: pip install elasticsearch
    """

    def __init__(
        self,
        host: str = "http://localhost:9200",
        index: str = ".siem-signals-default",
        poll_interval: float = 5.0,
        username: str = None,
        password: str = None,
    ):
        try:
            from elasticsearch import Elasticsearch
            kwargs = {"hosts": [host]}
            if username:
                kwargs["basic_auth"] = (username, password)
            self.es = Elasticsearch(**kwargs)
            log.info(f"Connected to Elasticsearch at {host}")
        except ImportError:
            raise RuntimeError("Install elasticsearch: pip install elasticsearch")

        self.index    = index
        self.interval = poll_interval
        self._last_ts = datetime.now(timezone.utc).isoformat()

    def alerts(self) -> Iterator[dict]:
        log.info(f"Polling Elasticsearch index: {self.index}")
        while True:
            try:
                result = self.es.search(
                    index=self.index,
                    body={
                        "query": {
                            "range": {
                                "@timestamp": {"gt": self._last_ts}
                            }
                        },
                        "sort": [{"@timestamp": "asc"}],
                        "size": 100,
                    },
                )
                hits = result["hits"]["hits"]
                for hit in hits:
                    src = hit["_source"]
                    self._last_ts = src.get("@timestamp", self._last_ts)
                    yield self._normalize(src)

            except Exception as e:
                log.error(f"Elasticsearch error: {e}")

            time.sleep(self.interval)

    @staticmethod
    def _normalize(src: dict) -> dict:
        """Map ELK SIEM signal format to our standard alert schema."""
        signal = src.get("signal", {})
        rule   = signal.get("rule", {})
        return {
            "timestamp":  src.get("@timestamp"),
            "rule":       rule.get("name", "Unknown"),
            "source_ip":  src.get("source", {}).get("ip"),
            "target":     src.get("destination", {}).get("ip"),
            "count":      signal.get("original_event", {}).get("count", 1),
            "severity":   rule.get("severity", "medium"),
            "tags":       rule.get("tags", []),
        }


# ══════════════════════════════════════════════════════════════════════════════
# Mode 3 — Splunk Webhook Receiver
# ══════════════════════════════════════════════════════════════════════════════

class SplunkWebhookServer:
    """
    Minimal HTTP server that receives Splunk Alert Action webhooks.
    Configure in Splunk: Alert → Add Actions → Webhook → URL: http://host:8888/alert
    Requires: pip install flask
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 8888):
        try:
            from flask import Flask, request, jsonify
        except ImportError:
            raise RuntimeError("Install flask: pip install flask")

        self.app  = Flask("SOC-Webhook")
        self._q   = []

        @self.app.route("/alert", methods=["POST"])
        def receive_alert():
            data = request.get_json(force=True) or {}
            alert = self._normalize(data)
            self._q.append(alert)
            log.info(f"Received Splunk alert: {alert.get('rule')}")
            return jsonify({"status": "queued"}), 200

        import threading
        t = threading.Thread(
            target=self.app.run,
            kwargs={"host": host, "port": port, "use_reloader": False},
            daemon=True,
        )
        t.start()
        log.info(f"Splunk webhook listener on http://{host}:{port}/alert")

    def alerts(self) -> Iterator[dict]:
        while True:
            if self._q:
                yield self._q.pop(0)
            else:
                time.sleep(0.5)

    @staticmethod
    def _normalize(data: dict) -> dict:
        result = data.get("result", {})
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule":      data.get("search_name", "Splunk Alert"),
            "source_ip": result.get("src_ip") or result.get("src"),
            "target":    result.get("dest_ip") or result.get("dest"),
            "count":     int(result.get("count", 1)),
            "severity":  data.get("alert_severity", "medium"),
            "tags":      [],
        }


# ══════════════════════════════════════════════════════════════════════════════
# Main dispatcher
# ══════════════════════════════════════════════════════════════════════════════

def main():
    from analyzer import run_pipeline  # imported here to keep CLI fast

    parser = argparse.ArgumentParser(description="SOC Automation — Alert Listener")
    parser.add_argument("--mode",  choices=["file", "elk", "splunk"], default="file")
    parser.add_argument("--file",  default="logs/alerts.jsonl", help="Alert file (file mode)")
    parser.add_argument("--elk",   default="http://localhost:9200", help="ELK host")
    parser.add_argument("--index", default=".siem-signals-default", help="ELK index")
    parser.add_argument("--port",  type=int, default=8888, help="Splunk webhook port")
    args = parser.parse_args()

    if args.mode == "file":
        watcher = FileWatcher(args.file)
    elif args.mode == "elk":
        watcher = ElasticsearchWatcher(host=args.elk, index=args.index)
    elif args.mode == "splunk":
        watcher = SplunkWebhookServer(port=args.port)
    else:
        parser.print_help(); sys.exit(1)

    log.info(f"SOC Automation Pipeline ACTIVE — mode={args.mode}")

    for alert in watcher.alerts():
        try:
            case = run_pipeline(alert)
            log.info(
                f"[{case['case_id']}] COMPLETE — "
                f"Level: {case['threat_level']} | "
                f"Score: {case['threat_score']} | "
                f"Actions: {len(case['response_actions'])}"
            )
        except Exception as e:
            log.error(f"Pipeline error for alert {alert}: {e}", exc_info=True)


if __name__ == "__main__":
    main()
