import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
import requests
from google.oauth2 import service_account
from google.auth.transport.requests import Request

RULES_DIR = Path("detections/yara")
SCOPE = "https://www.googleapis.com/auth/chronicle-backstory"


def get_token() -> str:
    creds_file = os.environ["GOOGLE_APPLICATION_CREDENTIALS"]
    credentials = service_account.Credentials.from_service_account_file(
        creds_file,
        scopes=[SCOPE],
    )
    credentials.refresh(Request())
    return credentials.token


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_meta(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def write_meta(path: Path, data: Dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def chronicle_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }


def create_rule(base_url: str, token: str, rule_text: str) -> Dict[str, Any]:
    url = f"{base_url}/v2/detect/rules"
    resp = requests.post(url, headers=chronicle_headers(token), json={"ruleText": rule_text}, timeout=60)
    resp.raise_for_status()
    return resp.json()


def create_rule_version(base_url: str, token: str, rule_id: str, rule_text: str) -> Dict[str, Any]:
    url = f"{base_url}/v2/detect/rules/{rule_id}:createVersion"
    resp = requests.post(url, headers=chronicle_headers(token), json={"ruleText": rule_text}, timeout=60)
    resp.raise_for_status()
    return resp.json()


def enable_live_rule(base_url: str, token: str, rule_id: str) -> None:
    url = f"{base_url}/v2/detect/rules/{rule_id}:enableLiveRule"
    resp = requests.post(url, headers=chronicle_headers(token), timeout=60)
    resp.raise_for_status()


def main() -> None:
    base_url = os.environ["CHRONICLE_BASE_URL"].rstrip("/")
    token = get_token()

    for yaral_path in RULES_DIR.glob("*.yaral"):
        meta_path = yaral_path.with_suffix(".meta.json")
        meta = read_meta(meta_path)
        rule_text = read_text(yaral_path)
        rule_id: Optional[str] = meta.get("rule_id") or None

        if rule_id:
            result = create_rule_version(base_url, token, rule_id, rule_text)
            enable_live_rule(base_url, token, rule_id)
            print(f"[UPDATED] {yaral_path.name} -> {rule_id} version {result.get('versionId')}")
        else:
            result = create_rule(base_url, token, rule_text)
            new_rule_id = result["ruleId"]
            enable_live_rule(base_url, token, new_rule_id)
            meta["rule_id"] = new_rule_id
            write_meta(meta_path, meta)
            print(f"[CREATED] {yaral_path.name} -> {new_rule_id}")


if __name__ == "__main__":
    main()
