#!/usr/bin/env python3
"""
Common utilities for AgroDT OPC UA PubSub-style UADP over MQTT security PoC.

This is a Phase-1 proof of concept:
- MQTT is the transport layer.
- The message envelope follows a simplified UADP-style structure.
- End-to-end payload protection is implemented in Python for None, Sign, SignAndEncrypt.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import psutil
except Exception:
    psutil = None

try:
    import paho.mqtt.client as mqtt
except Exception:
    mqtt = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception:
    AESGCM = None


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_TOPIC = "agrodt/soil/uadp"
CONTROL_TOPIC = "agrodt/control"
KEYS_FILE = PROJECT_ROOT / "keys" / "security_keys.json"
DT_STATE_FILE = PROJECT_ROOT / "results" / "digital_twin_state.json"
LAST_MESSAGE_FILE = PROJECT_ROOT / "results" / "last_message.json"
PUBLISHER_LOG = PROJECT_ROOT / "logs" / "publisher.jsonl"
SUBSCRIBER_LOG = PROJECT_ROOT / "logs" / "authorized_subscriber.jsonl"
UNAUTH_SUB_LOG = PROJECT_ROOT / "logs" / "unauthorized_subscriber.jsonl"
ATTACK_LOG = PROJECT_ROOT / "logs" / "attacks.jsonl"
METRICS_FILE = PROJECT_ROOT / "results" / "subscriber_metrics.csv"

SECURITY_GROUP_ID = "agrodt_soil_security_group"
PUBLISHER_ID = "authorized_agrodt_soil_publisher"
AUTHORIZED_SUBSCRIBER_ID = "authorized_agrodt_dt_subscriber"

VALID_MODES = ["none", "sign", "signandencrypt", "all"]


def ensure_dirs() -> None:
    for p in ["logs", "results", "keys", "captures", "data"]:
        (PROJECT_ROOT / p).mkdir(exist_ok=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def log_json(path: Path, event: Dict[str, Any]) -> None:
    ensure_dirs()
    event.setdefault("event_time", now_iso())
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, sort_keys=True) + "\n")


def write_json(path: Path, data: Dict[str, Any]) -> None:
    ensure_dirs()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def current_resource_usage() -> Dict[str, float]:
    if psutil is None:
        return {"cpu_percent": 0.0, "memory_mb": 0.0}
    proc = psutil.Process(os.getpid())
    return {
        "cpu_percent": proc.cpu_percent(interval=None),
        "memory_mb": round(proc.memory_info().rss / (1024 * 1024), 3),
    }


def load_soil_csv(csv_path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with csv_path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        required = {"SensorId", "Timestamp", "SoilMoisture", "SoilTemperature", "SoilPH"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV missing required columns: {sorted(missing)}")
        for i, row in enumerate(reader, start=1):
            payload = {
                "SensorId": str(row.get("SensorId", "soil_001")).strip() or "soil_001",
                "Timestamp": str(row.get("Timestamp", now_iso())).strip() or now_iso(),
                "SequenceNumber": int(float(row.get("SequenceNumber", i) or i)),
                "SoilMoisture": float(row["SoilMoisture"]),
                "SoilTemperature": float(row["SoilTemperature"]),
                "SoilPH": float(row["SoilPH"]),
            }
            if "Alert" in row and row.get("Alert"):
                payload["Alert"] = str(row["Alert"])
            rows.append(payload)
    return rows


def mqtt_client(client_id: str, args: argparse.Namespace):
    if mqtt is None:
        raise RuntimeError("paho-mqtt is not installed. Run: pip install paho-mqtt")
    client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv311)
    if getattr(args, "username", None):
        client.username_pw_set(args.username, getattr(args, "password", None))
    if getattr(args, "tls", False):
        cafile = getattr(args, "cafile", None)
        client.tls_set(ca_certs=cafile)
    return client


def add_mqtt_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default="127.0.0.1", help="MQTT broker host")
    parser.add_argument("--port", type=int, default=1883, help="MQTT broker port")
    parser.add_argument("--topic", default=DATA_TOPIC, help="MQTT data topic")
    parser.add_argument("--tls", action="store_true", help="Use MQTT over TLS")
    parser.add_argument("--cafile", default=None, help="CA certificate for MQTT TLS")
    parser.add_argument("--username", default=None, help="MQTT username")
    parser.add_argument("--password", default=None, help="MQTT password")


def load_keys() -> Dict[str, Any]:
    data = read_json(KEYS_FILE, default={})
    if not data:
        raise RuntimeError("No SKS keys found. Run: python3 scripts/sks.py --init")
    return data


def get_active_key() -> Dict[str, Any]:
    data = load_keys()
    active = data.get("active_key_id")
    if not active or active not in data.get("keys", {}):
        raise RuntimeError("Invalid SKS state: active_key_id missing")
    return data["keys"][active]


def get_key_by_id(key_id: str) -> Optional[Dict[str, Any]]:
    data = read_json(KEYS_FILE, default={})
    return data.get("keys", {}).get(key_id)


def make_hmac(payload: Dict[str, Any], signing_key_b64: str) -> str:
    key = b64d(signing_key_b64)
    return hmac.new(key, canonical_json(payload), hashlib.sha256).hexdigest()


def verify_hmac(payload: Dict[str, Any], signature_hex: str, signing_key_b64: str) -> bool:
    expected = make_hmac(payload, signing_key_b64)
    return hmac.compare_digest(expected, signature_hex)


def build_envelope(payload: Dict[str, Any], mode: str) -> Dict[str, Any]:
    mode = mode.lower()
    timestamp_sent_ns = time.time_ns()

    header = {
        "UADPVersion": "PoC-UADP-1.0",
        "MessageType": "DataSetMessage",
        "SecurityMode": mode,
        "PublisherId": PUBLISHER_ID,
        "SecurityGroupId": SECURITY_GROUP_ID,
        "TimestampSentNs": timestamp_sent_ns,
        "PayloadFields": ["SensorId", "Timestamp", "SequenceNumber", "SoilMoisture", "SoilTemperature", "SoilPH"],
    }

    if mode == "none":
        return {
            "Header": header,
            "Payload": payload,
            "Security": {
                "KeyId": None,
                "Signature": None,
                "Nonce": None,
                "Algorithm": "None",
            },
        }

    active_key = get_active_key()
    key_id = active_key["key_id"]
    header["KeyId"] = key_id

    if mode == "sign":
        sig = make_hmac(payload, active_key["signing_key_b64"])
        return {
            "Header": header,
            "Payload": payload,
            "Security": {
                "KeyId": key_id,
                "Signature": sig,
                "Nonce": None,
                "Algorithm": "HMAC-SHA256",
            },
        }

    if mode == "signandencrypt":
        if AESGCM is None:
            raise RuntimeError("cryptography is not installed. Run: pip install cryptography")
        enc_key = b64d(active_key["encryption_key_b64"])
        aesgcm = AESGCM(enc_key)
        nonce = os.urandom(12)
        aad = canonical_json(header)
        plaintext = canonical_json(payload)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        return {
            "Header": header,
            "Payload": None,
            "EncryptedPayloadB64": b64e(ciphertext),
            "Security": {
                "KeyId": key_id,
                "Signature": "AES-GCM-TAG-IN-CIPHERTEXT",
                "Nonce": b64e(nonce),
                "Algorithm": "AES-256-GCM",
            },
        }

    raise ValueError(f"Unsupported mode: {mode}")


def decode_envelope(envelope: Dict[str, Any]) -> Dict[str, Any]:
    header = envelope.get("Header", {})
    mode = str(header.get("SecurityMode", "")).lower()
    key_id = envelope.get("Security", {}).get("KeyId") or header.get("KeyId")

    if mode == "none":
        payload = envelope.get("Payload")
        if not isinstance(payload, dict):
            raise ValueError("missing_plain_payload")
        return payload

    key = get_key_by_id(str(key_id))
    if not key:
        raise PermissionError("unknown_key_id")

    if mode == "sign":
        payload = envelope.get("Payload")
        if not isinstance(payload, dict):
            raise ValueError("missing_signed_payload")
        signature = envelope.get("Security", {}).get("Signature", "")
        if not verify_hmac(payload, signature, key["signing_key_b64"]):
            raise PermissionError("signature_verification_failed")
        return payload

    if mode == "signandencrypt":
        if AESGCM is None:
            raise RuntimeError("cryptography is not installed. Run: pip install cryptography")
        nonce_b64 = envelope.get("Security", {}).get("Nonce")
        ct_b64 = envelope.get("EncryptedPayloadB64")
        if not nonce_b64 or not ct_b64:
            raise ValueError("missing_encrypted_payload_or_nonce")
        enc_key = b64d(key["encryption_key_b64"])
        aesgcm = AESGCM(enc_key)
        aad = canonical_json(header)
        plaintext = aesgcm.decrypt(b64d(nonce_b64), b64d(ct_b64), aad)
        return json.loads(plaintext.decode("utf-8"))

    raise ValueError(f"unsupported_security_mode:{mode}")


def message_size_bytes(envelope: Dict[str, Any]) -> int:
    return len(canonical_json(envelope))


def append_metric(row: Dict[str, Any]) -> None:
    ensure_dirs()
    exists = METRICS_FILE.exists()
    fieldnames = [
        "EventTime", "Mode", "SensorId", "SequenceNumber", "Status", "Reason",
        "LatencyMs", "MessageSizeBytes", "CPUPercent", "MemoryMB", "KeyId"
    ]
    with METRICS_FILE.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not exists:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in fieldnames})


def load_dt_state() -> Dict[str, Any]:
    return read_json(DT_STATE_FILE, default={"sensors": {}, "accepted_messages": 0, "rejected_messages": 0})


def update_dt_state(payload: Dict[str, Any], envelope: Dict[str, Any]) -> Dict[str, Any]:
    state = load_dt_state()
    sensor_id = str(payload["SensorId"])
    sensors = state.setdefault("sensors", {})
    sensors[sensor_id] = {
        "SensorId": sensor_id,
        "LastTimestamp": payload.get("Timestamp"),
        "LastSequenceNumber": payload.get("SequenceNumber"),
        "SoilMoisture": payload.get("SoilMoisture"),
        "SoilTemperature": payload.get("SoilTemperature"),
        "SoilPH": payload.get("SoilPH"),
        "Alert": payload.get("Alert", ""),
        "LastSecurityMode": envelope.get("Header", {}).get("SecurityMode"),
        "LastKeyId": envelope.get("Security", {}).get("KeyId"),
        "UpdatedAt": now_iso(),
    }
    state["accepted_messages"] = int(state.get("accepted_messages", 0)) + 1
    write_json(DT_STATE_FILE, state)
    return state


def reject_dt_state() -> None:
    state = load_dt_state()
    state["rejected_messages"] = int(state.get("rejected_messages", 0)) + 1
    write_json(DT_STATE_FILE, state)


def replay_check(payload: Dict[str, Any]) -> Optional[str]:
    state = load_dt_state()
    sensor_id = str(payload.get("SensorId", ""))
    seq = int(payload.get("SequenceNumber", -1))
    sensor_state = state.get("sensors", {}).get(sensor_id)
    if sensor_state:
        last_seq = int(sensor_state.get("LastSequenceNumber", -1))
        if seq <= last_seq:
            return f"replay_detected_sequence_{seq}_not_greater_than_last_{last_seq}"
    return None


def reset_runtime_outputs() -> None:
    for p in [PUBLISHER_LOG, SUBSCRIBER_LOG, UNAUTH_SUB_LOG, ATTACK_LOG, METRICS_FILE, DT_STATE_FILE, LAST_MESSAGE_FILE]:
        if p.exists():
            p.unlink()
