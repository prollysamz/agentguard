import hashlib
import json

GENESIS = "0" * 64


def event_hash(event: dict) -> str:
    body = {k: v for k, v in event.items() if k != "event_hash"}
    return hashlib.sha256(
        json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode()
    ).hexdigest()


def verify_events(events: list[dict]) -> str:
    previous = GENESIS
    for index, event in enumerate(events, 1):
        if event.get("previous_hash") != previous or event.get("event_hash") != event_hash(event):
            raise ValueError(f"Invalid audit chain at event {index}")
        previous = event["event_hash"]
    return previous
