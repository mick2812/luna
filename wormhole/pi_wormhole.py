#!/usr/bin/env python3
"""Luna Wormhole - Raspberry Pi polling bridge.

First protocol operation: ping.

The Pi polls GitHub for inbox messages and writes responses to outbox.
No inbound port is required on the Pi.
"""

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = os.environ.get("LUNA_REPO", "mick2812/luna")
BRANCH = os.environ.get("LUNA_BRANCH", "main")
POLL_SECONDS = int(os.environ.get("LUNA_POLL_SECONDS", "10"))
STATE_FILE = Path(os.environ.get("LUNA_STATE_FILE", "wormhole_state.json"))

API = f"https://api.github.com/repos/{REPO}"
TOKEN = os.environ.get("GITHUB_TOKEN")

if not TOKEN:
    print("ERROR: GITHUB_TOKEN is not set.", file=sys.stderr)
    sys.exit(1)


def request(method, url, data=None):
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Luna-Wormhole-Pi/0.1",
    }
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def load_state():
    if not STATE_FILE.exists():
        return set()
    try:
        return set(json.loads(STATE_FILE.read_text()))
    except Exception:
        return set()


def save_state(processed):
    STATE_FILE.write_text(json.dumps(sorted(processed), indent=2))


def list_inbox():
    url = f"{API}/contents/wormhole/inbox?ref={BRANCH}"
    result = request("GET", url)
    return [x for x in result if x.get("type") == "file" and x["name"].endswith(".json")]


def read_json_file(path):
    result = request("GET", f"{API}/contents/{path}?ref={BRANCH}")
    raw = base64.b64decode(result["content"]).decode("utf-8")
    return json.loads(raw)


def write_json_file(path, document, message):
    # The contents API accepts base64 content.
    encoded = base64.b64encode(
        (json.dumps(document, indent=2) + "\n").encode("utf-8")
    ).decode("ascii")

    payload = {
        "message": message,
        "content": encoded,
        "branch": BRANCH,
    }
    return request("PUT", f"{API}/contents/{path}", payload)


def process(command):
    command_id = command.get("id")
    op = command.get("op")

    if not command_id or not isinstance(command_id, str):
        return None, "invalid command id"

    if op == "ping":
        return {
            "id": command_id,
            "ok": True,
            "op": "ping",
            "result": "PONG FROM RASPBERRY PI",
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }, None

    return {
        "id": command_id,
        "ok": False,
        "op": op,
        "error": "operation not allowed",
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }, None


def main():
    processed = load_state()
    print(f"Luna Wormhole online: {REPO}@{BRANCH}")
    print(f"Polling every {POLL_SECONDS}s")

    while True:
        try:
            for item in list_inbox():
                path = item["path"]
                if path in processed:
                    continue

                print(f"Received {path}")
                command = read_json_file(path)
                response, error = process(command)

                if response is None:
                    print(f"Rejected {path}: {error}", file=sys.stderr)
                    processed.add(path)
                    save_state(processed)
                    continue

                command_id = response["id"]
                outbox_path = f"wormhole/outbox/{command_id}.json"

                # Avoid overwriting an existing response.
                try:
                    request("GET", f"{API}/contents/{outbox_path}?ref={BRANCH}")
                    print(f"Response already exists: {outbox_path}")
                except urllib.error.HTTPError as exc:
                    if exc.code != 404:
                        raise
                    write_json_file(
                        outbox_path,
                        response,
                        f"Wormhole response: {command_id}",
                    )
                    print(f"Wrote {outbox_path}")

                processed.add(path)
                save_state(processed)

        except Exception as exc:
            print(f"Wormhole error: {exc}", file=sys.stderr)

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
