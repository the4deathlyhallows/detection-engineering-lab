import json
import os
from pathlib import Path
from typing import Dict, Any
import requests

SPLUNK_URL = os.environ["SPLUNK_URL"].rstrip("/")
SPLUNK_USERNAME = os.environ["SPLUNK_USERNAME"]
SPLUNK_PASSWORD = os.environ["SPLUNK_PASSWORD"]
SPLUNK_APP = os.environ.get("SPLUNK_APP", "search")

RULES_DIR = Path("detections/splunk")


def load_rule(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def get_saved_search_url(name: str) -> str:
    return f"{SPLUNK_URL}/servicesNS/nobody/{SPLUNK_APP}/saved/searches/{name}"


def get_collection_url() -> str:
    return f"{SPLUNK_URL}/servicesNS/nobody/{SPLUNK_APP}/saved/searches"


def upsert_rule(rule: Dict[str, Any]) -> None:
    name = rule["name"]
    params = {
        "name": name,
        "search": rule["search"],
        "description": rule.get("description", ""),
        "cron_schedule": rule.get("cron_schedule", "*/15 * * * *"),
        "disabled": "1" if rule.get("disabled", False) else "0",
        "is_scheduled": "1" if rule.get("is_scheduled", True) else "0",
        "alert_type": rule.get("alert_type", "always"),
        "alert_comparator": rule.get("alert_comparator", "greater than"),
        "alert_threshold": rule.get("alert_threshold", "0"),
        "actions": rule.get("actions", "")
    }

    session = requests.Session()
    session.auth = (SPLUNK_USERNAME, SPLUNK_PASSWORD)
    session.verify = False  # change to True if your Splunk cert is trusted
    session.headers.update({"Accept": "application/json"})

    check = session.get(get_saved_search_url(name))
    if check.status_code == 200:
        resp = session.post(get_saved_search_url(name), data=params)
        resp.raise_for_status()
        print(f"[UPDATED] {name}")
    elif check.status_code == 404:
        resp = session.post(get_collection_url(), data=params)
        resp.raise_for_status()
        print(f"[CREATED] {name}")
    else:
        raise RuntimeError(f"Unexpected status checking {name}: {check.status_code} {check.text}")


def main() -> None:
    if not RULES_DIR.exists():
        print("No Splunk detections directory found.")
        return

    for path in RULES_DIR.glob("*.json"):
        rule = load_rule(path)
        upsert_rule(rule)


if __name__ == "__main__":
    main()
