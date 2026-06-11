#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time

from common import ATTACK_LOG, LAST_MESSAGE_FILE, add_mqtt_args, ensure_dirs, log_json, mqtt_client, read_json, write_json


def tamper(envelope: dict) -> dict:
    e = json.loads(json.dumps(envelope))  # deep copy
    mode = str(e.get("Header", {}).get("SecurityMode", "")).lower()

    if mode in ["none", "sign"] and isinstance(e.get("Payload"), dict):
        e["Payload"]["SoilMoisture"] = 99.99
        e["Payload"]["Tampered"] = True
    elif mode == "signandencrypt":
        ct = e.get("EncryptedPayloadB64", "")
        if ct:
            # Change one base64 character. AES-GCM authentication should fail.
            e["EncryptedPayloadB64"] = ("A" if ct[0] != "A" else "B") + ct[1:]
        e.setdefault("Header", {})["TamperedCiphertext"] = True
    else:
        e.setdefault("Header", {})["TamperedUnknownMode"] = True

    e.setdefault("Header", {})["AttackType"] = "payload_tampering"
    return e


def main() -> None:
    parser = argparse.ArgumentParser(description="Payload tampering attack: modifies last message and republishes it.")
    add_mqtt_args(parser)
    args = parser.parse_args()
    ensure_dirs()

    envelope = read_json(LAST_MESSAGE_FILE, default={})
    if not envelope:
        raise RuntimeError("No last message found. Run publisher first.")

    attacked = tamper(envelope)
    raw = json.dumps(attacked, sort_keys=True).encode("utf-8")

    client = mqtt_client("tamper-attack", args)
    client.connect(args.host, args.port, keepalive=60)
    client.loop_start()
    info = client.publish(args.topic, raw, qos=0)
    info.wait_for_publish()
    client.loop_stop()
    client.disconnect()

    log_json(ATTACK_LOG, {
        "event": "tamper_attack_published",
        "mode": attacked.get("Header", {}).get("SecurityMode"),
        "topic": args.topic,
        "message_size_bytes": len(raw),
    })
    write_json(LAST_MESSAGE_FILE.with_name("tampered_message.json"), attacked)
    print("Tampered message published. Authorized Subscriber should reject it in Sign/SignAndEncrypt mode.")


if __name__ == "__main__":
    main()
