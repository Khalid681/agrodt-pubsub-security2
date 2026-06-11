#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from common import (
    LAST_MESSAGE_FILE, PUBLISHER_LOG, add_mqtt_args, build_envelope, current_resource_usage,
    ensure_dirs, load_soil_csv, log_json, message_size_bytes, mqtt_client, write_json
)


def main() -> None:
    parser = argparse.ArgumentParser(description="AgroDT Publisher: reads soil CSV and publishes UADP-style messages over MQTT.")
    parser.add_argument("--mode", choices=["none", "sign", "signandencrypt"], required=True)
    parser.add_argument("--csv", default="data/soil_data.csv", help="CSV file path")
    parser.add_argument("--count", type=int, default=10, help="Number of messages to publish")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between messages")
    add_mqtt_args(parser)
    args = parser.parse_args()

    ensure_dirs()
    csv_path = Path(args.csv)
    if not csv_path.is_absolute():
        csv_path = Path(__file__).resolve().parents[1] / csv_path

    rows = load_soil_csv(csv_path)
    if not rows:
        raise RuntimeError("No rows found in CSV")

    client = mqtt_client(f"publisher-{args.mode}", args)
    client.connect(args.host, args.port, keepalive=60)
    client.loop_start()

    print(f"Publisher started | mode={args.mode} | topic={args.topic} | count={args.count}")

    for i in range(args.count):
        payload = dict(rows[i % len(rows)])
        # Ensure sequence number is monotonic in long benchmark runs.
        payload["SequenceNumber"] = i + 1

        start_ns = time.time_ns()
        envelope = build_envelope(payload, args.mode)
        raw = json.dumps(envelope, sort_keys=True).encode("utf-8")
        info = client.publish(args.topic, raw, qos=0)
        info.wait_for_publish()
        end_ns = time.time_ns()

        size = len(raw)
        usage = current_resource_usage()
        event = {
            "event": "published",
            "mode": args.mode,
            "topic": args.topic,
            "sensor_id": payload["SensorId"],
            "sequence_number": payload["SequenceNumber"],
            "key_id": envelope.get("Security", {}).get("KeyId"),
            "message_size_bytes": size,
            "publish_duration_ms": round((end_ns - start_ns) / 1_000_000, 3),
            "cpu_percent": usage["cpu_percent"],
            "memory_mb": usage["memory_mb"],
        }
        log_json(PUBLISHER_LOG, event)
        write_json(LAST_MESSAGE_FILE, envelope)
        print(f"PUBLISHED mode={args.mode} seq={payload['SequenceNumber']} size={size}B key={event['key_id']}")
        time.sleep(args.interval)

    client.loop_stop()
    client.disconnect()
    print("Publisher finished.")


if __name__ == "__main__":
    main()
