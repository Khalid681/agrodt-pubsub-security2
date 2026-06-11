#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import signal
import time

from common import (
    SUBSCRIBER_LOG, add_mqtt_args, append_metric, current_resource_usage, decode_envelope,
    ensure_dirs, log_json, message_size_bytes, mqtt_client, reject_dt_state, replay_check, update_dt_state
)

running = True


def stop_handler(signum, frame):
    global running
    running = False


def main() -> None:
    parser = argparse.ArgumentParser(description="Authorized Subscriber: verifies/decrypts messages and updates Digital Twin state.")
    parser.add_argument("--mode", choices=["none", "sign", "signandencrypt", "all"], default="all")
    parser.add_argument("--max", type=int, default=0, help="Stop after N messages. 0 means keep running.")
    add_mqtt_args(parser)
    args = parser.parse_args()

    ensure_dirs()
    received = {"count": 0}

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print(f"Authorized Subscriber connected. Subscribing to {args.topic}")
            client.subscribe(args.topic, qos=0)
        else:
            print(f"MQTT connection failed rc={rc}")

    def on_message(client, userdata, msg):
        received["count"] += 1
        raw = msg.payload
        receive_ns = time.time_ns()
        status = "REJECTED"
        reason = ""
        payload = {}
        envelope = {}
        mode = ""
        key_id = ""
        seq = ""
        sensor_id = ""

        try:
            envelope = json.loads(raw.decode("utf-8"))
            mode = str(envelope.get("Header", {}).get("SecurityMode", "")).lower()
            key_id = str(envelope.get("Security", {}).get("KeyId", ""))
            if args.mode != "all" and mode != args.mode:
                raise PermissionError(f"mode_mismatch_expected_{args.mode}_got_{mode}")

            payload = decode_envelope(envelope)
            sensor_id = payload.get("SensorId", "")
            seq = payload.get("SequenceNumber", "")

            replay_reason = replay_check(payload)
            if replay_reason:
                raise PermissionError(replay_reason)

            update_dt_state(payload, envelope)
            status = "ACCEPTED"
            reason = "dt_state_updated"

        except Exception as exc:
            reject_dt_state()
            reason = str(exc)

        latency_ms = ""
        try:
            sent_ns = int(envelope.get("Header", {}).get("TimestampSentNs", 0))
            if sent_ns:
                latency_ms = round((receive_ns - sent_ns) / 1_000_000, 3)
        except Exception:
            pass

        usage = current_resource_usage()
        size = len(raw)

        log_event = {
            "event": "subscriber_received",
            "status": status,
            "reason": reason,
            "mode": mode,
            "sensor_id": sensor_id,
            "sequence_number": seq,
            "topic": msg.topic,
            "key_id": key_id,
            "latency_ms": latency_ms,
            "message_size_bytes": size,
            "cpu_percent": usage["cpu_percent"],
            "memory_mb": usage["memory_mb"],
        }
        log_json(SUBSCRIBER_LOG, log_event)
        append_metric({
            "EventTime": log_event["event_time"],
            "Mode": mode,
            "SensorId": sensor_id,
            "SequenceNumber": seq,
            "Status": status,
            "Reason": reason,
            "LatencyMs": latency_ms,
            "MessageSizeBytes": size,
            "CPUPercent": usage["cpu_percent"],
            "MemoryMB": usage["memory_mb"],
            "KeyId": key_id,
        })

        print(f"{status} mode={mode} seq={seq} reason={reason} size={size}B latency={latency_ms}ms")

        if args.max and received["count"] >= args.max:
            global running
            running = False

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    client = mqtt_client(f"authorized-subscriber-{args.mode}", args)
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(args.host, args.port, keepalive=60)
    client.loop_start()

    print(f"Authorized Subscriber started | accepted mode={args.mode}")
    try:
        while running:
            time.sleep(0.2)
    finally:
        client.loop_stop()
        client.disconnect()
        print("Authorized Subscriber stopped.")


if __name__ == "__main__":
    main()
