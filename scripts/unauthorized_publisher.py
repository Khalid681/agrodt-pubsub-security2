#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from common import ATTACK_LOG, add_mqtt_args, canonical_json, ensure_dirs, log_json, mqtt_client


def fake_payload() -> dict:
    return {
        "SensorId": "fake_sensor_999",
        "Timestamp": "2026-06-11T10:30:00Z",
        "SequenceNumber": 9999,
        "SoilMoisture": 0.01,
        "SoilTemperature": 99.99,
        "SoilPH": 14.0,
        "Alert": "FAKE_ATTACK_MESSAGE",
    }


def build_fake(mode: str) -> dict:
    payload = fake_payload()
    header = {
        "UADPVersion": "PoC-UADP-1.0",
        "MessageType": "DataSetMessage",
        "SecurityMode": mode,
        "PublisherId": "unauthorized_attacker_publisher",
        "SecurityGroupId": "agrodt_soil_security_group",
        "TimestampSentNs": time.time_ns(),
        "KeyId": "attacker-key-not-in-sks",
        "AttackType": "unauthorized_publisher",
    }

    if mode == "none":
        return {
            "Header": header,
            "Payload": payload,
            "Security": {"KeyId": None, "Signature": None, "Nonce": None, "Algorithm": "None"},
        }

    if mode == "sign":
        wrong_key = b"wrong-attacker-signing-key-000000"
        sig = hmac.new(wrong_key, canonical_json(payload), hashlib.sha256).hexdigest()
        return {
            "Header": header,
            "Payload": payload,
            "Security": {"KeyId": "attacker-key-not-in-sks", "Signature": sig, "Nonce": None, "Algorithm": "HMAC-SHA256"},
        }

    if mode == "signandencrypt":
        wrong_key = os.urandom(32)
        nonce = os.urandom(12)
        aesgcm = AESGCM(wrong_key)
        ct = aesgcm.encrypt(nonce, canonical_json(payload), canonical_json(header))
        return {
            "Header": header,
            "Payload": None,
            "EncryptedPayloadB64": base64.b64encode(ct).decode("ascii"),
            "Security": {
                "KeyId": "attacker-key-not-in-sks",
                "Signature": "AES-GCM-TAG-IN-CIPHERTEXT",
                "Nonce": base64.b64encode(nonce).decode("ascii"),
                "Algorithm": "AES-256-GCM",
            },
        }

    raise ValueError(mode)


def main() -> None:
    parser = argparse.ArgumentParser(description="Unauthorized Publisher attack.")
    parser.add_argument("--mode", choices=["none", "sign", "signandencrypt"], default="signandencrypt")
    add_mqtt_args(parser)
    args = parser.parse_args()

    ensure_dirs()
    envelope = build_fake(args.mode)
    raw = json.dumps(envelope, sort_keys=True).encode("utf-8")

    client = mqtt_client("unauthorized-publisher", args)
    client.connect(args.host, args.port, keepalive=60)
    client.loop_start()
    info = client.publish(args.topic, raw, qos=0)
    info.wait_for_publish()
    client.loop_stop()
    client.disconnect()

    log_json(ATTACK_LOG, {
        "event": "unauthorized_publisher_sent",
        "mode": args.mode,
        "topic": args.topic,
        "message_size_bytes": len(raw),
    })
    print(f"Unauthorized publisher message sent in mode={args.mode}. Authorized Subscriber should reject Sign/SignAndEncrypt.")


if __name__ == "__main__":
    main()
