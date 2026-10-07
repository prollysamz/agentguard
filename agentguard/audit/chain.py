import hashlib
import hmac
import json

GENESIS = "0" * 64
# Fields outside the hashed body: the hash itself, and the signature over that hash.
UNHASHED = frozenset({"event_hash", "signature"})


def event_hash(event: dict) -> str:
    body = {k: v for k, v in event.items() if k not in UNHASHED}
    return hashlib.sha256(
        json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode()
    ).hexdigest()


def sign(key: bytes, digest: str) -> str:
    return "hmac-sha256:" + hmac.new(key, digest.encode(), hashlib.sha256).hexdigest()


def verify_event(event: dict, previous: str, index: int, key: bytes | None = None) -> str:
    if event.get("previous_hash") != previous or event.get("event_hash") != event_hash(event):
        raise ValueError(f"Invalid audit chain at event {index}")
    if key is not None and not hmac.compare_digest(
        str(event.get("signature", "")), sign(key, event["event_hash"])
    ):
        raise ValueError(f"Invalid or missing audit signature at event {index}")
    return event["event_hash"]


def verify_events(events: list[dict], previous: str = GENESIS, key: bytes | None = None) -> str:
    for index, event in enumerate(events, 1):
        previous = verify_event(event, previous, index, key)
    return previous
