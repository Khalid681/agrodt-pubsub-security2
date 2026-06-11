#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from common import ATTACK_LOG, LAST_MESSAGE_FILE, add_mqtt_args, ensure_dirs, log_json, mqtt_client, read_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay attack: republishes a previously transmitted message.")
    add_mqtt_args(parser)
    args = parser.parse_args()
    ensure_dirs()

    envelope = read_json(LAST_MESSAGE_FILE, default={})
    if not envelope:
        raise RuntimeError("No last message found. Run publisher first.")

    raw = json.dumps(envelope, sort_keys=True).encode("utf-8")

    client = mqtt_client("replay-attack", args)
    client.connect(args.host, args.port, keepalive=60)
    client.loop_start()
    # Publish twice to clearly trigger duplicate sequence detection.
    for _ in range(2):
        info = client.publish(args.topic, raw, qos=0)
        info.wait_for_publish()
    client.loop_stop()
    client.disconnect()

    log_json(ATTACK_LOG, {
        "event": "replay_attack_published",
        "mode": envelope.get("Header", {}).get("SecurityMode"),
        "sequence_number": envelope.get("Payload", {}).get("SequenceNumber") if envelope.get("Payload") else "encrypted",
        "message_size_bytes": len(raw),
    })
    print("Replay message published twice. Authorized Subscriber should reject duplicate/old SequenceNumber.")


if __name__ == "__main__":
    main()
