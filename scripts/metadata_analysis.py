#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from common import LAST_MESSAGE_FILE, read_json


def main():
    parser = argparse.ArgumentParser(description="Analyze visible metadata in the last transmitted message.")
    args = parser.parse_args()
    msg = read_json(LAST_MESSAGE_FILE, default={})
    if not msg:
        print("No last message found.")
        return

    header = msg.get("Header", {})
    security = msg.get("Security", {})
    print("Visible metadata in message envelope:")
    for key in ["UADPVersion", "MessageType", "SecurityMode", "PublisherId", "SecurityGroupId", "TimestampSentNs", "PayloadFields", "KeyId"]:
        print(f"- {key}: {header.get(key)}")
    print(f"- Security.Algorithm: {security.get('Algorithm')}")
    print(f"- Security.KeyId: {security.get('KeyId')}")
    print(f"- Security.Nonce visible: {bool(security.get('Nonce'))}")
    print(f"- Message size can be observed from MQTT packet length.")
    print(f"- MQTT topic and broker IP/port remain visible at transport/network level.")
    if header.get("SecurityMode") == "signandencrypt":
        print("Payload values are encrypted, but routing and timing metadata remain visible.")
    else:
        print("Payload values are visible in this mode.")


if __name__ == "__main__":
    main()
