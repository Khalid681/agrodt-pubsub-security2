#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import signal
import time

from common import UNAUTH_SUB_LOG, add_mqtt_args, ensure_dirs, log_json, mqtt_client

running = True


def stop_handler(signum, frame):
    global running
    running = False


def main() -> None:
    parser = argparse.ArgumentParser(description="Unauthorized Subscriber: receives MQTT messages but does not have SKS keys.")
    parser.add_argument("--max", type=int, default=5)
    add_mqtt_args(parser)
    args = parser.parse_args()

    ensure_dirs()
    received = {"count": 0}

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print(f"Unauthorized Subscriber connected. Subscribing to {args.topic}")
            client.subscribe(args.topic, qos=0)
        else:
            print(f"MQTT connection failed rc={rc}")

    def on_message(client, userdata, msg):
        received["count"] += 1
        raw = msg.payload
        readable = False
        visible_payload = None
        mode = ""
        reason = ""

        try:
            envelope = json.loads(raw.decode("utf-8"))
            mode = str(envelope.get("Header", {}).get("SecurityMode", "unknown")).lower()
            if mode in ["none", "sign"]:
                readable = True
                visible_payload = envelope.get("Payload")
                reason = "payload_visible_without_decryption"
            elif mode == "signandencrypt":
                readable = False
                visible_payload = envelope.get("EncryptedPayloadB64", "")[:80] + "..."
                reason = "encrypted_payload_visible_but_not_decryptable_without_key"
            else:
                reason = "unknown_mode"
        except Exception as exc:
            reason = f"parse_failed:{exc}"

        event = {
            "event": "unauthorized_subscriber_observed",
            "mode": mode,
            "readable": readable,
            "reason": reason,
            "visible_payload_preview": visible_payload,
            "message_size_bytes": len(raw),
        }
        log_json(UNAUTH_SUB_LOG, event)

        print(f"UNAUTHORIZED_SUB mode={mode} readable={readable} reason={reason}")

        if args.max and received["count"] >= args.max:
            global running
            running = False

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    client = mqtt_client("unauthorized-subscriber", args)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(args.host, args.port, keepalive=60)
    client.loop_start()

    try:
        while running:
            time.sleep(0.2)
    finally:
        client.loop_stop()
        client.disconnect()
        print("Unauthorized Subscriber stopped.")


if __name__ == "__main__":
    main()
