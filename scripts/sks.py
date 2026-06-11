#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import os
import secrets
import time
from datetime import datetime, timezone

from common import KEYS_FILE, ensure_dirs, read_json, write_json, now_iso


def new_key(version: int) -> dict:
    key_id = f"key-v{version}-{secrets.token_hex(4)}"
    return {
        "key_id": key_id,
        "version": version,
        "created_at": now_iso(),
        "signing_key_b64": base64.b64encode(os.urandom(32)).decode("ascii"),
        "encryption_key_b64": base64.b64encode(os.urandom(32)).decode("ascii"),
        "status": "active",
        "algorithm_sign": "HMAC-SHA256",
        "algorithm_encrypt": "AES-256-GCM",
    }


def init_keys(force: bool = False) -> None:
    ensure_dirs()
    if KEYS_FILE.exists() and not force:
        print(f"SKS already exists: {KEYS_FILE}")
        print("Use --force to overwrite.")
        return
    k = new_key(1)
    state = {
        "sks_name": "AgroDT Local SKS Prototype",
        "created_at": now_iso(),
        "active_key_id": k["key_id"],
        "keys": {k["key_id"]: k},
        "rotation_history": [{"event": "init", "key_id": k["key_id"], "time": now_iso()}],
    }
    write_json(KEYS_FILE, state)
    print(f"SKS initialized. Active key: {k['key_id']}")


def rotate_key() -> None:
    ensure_dirs()
    state = read_json(KEYS_FILE, default={})
    if not state:
        init_keys(force=True)
        return
    keys = state.setdefault("keys", {})
    for key in keys.values():
        if key.get("status") == "active":
            key["status"] = "retired"
            key["retired_at"] = now_iso()

    version = len(keys) + 1
    k = new_key(version)
    keys[k["key_id"]] = k
    state["active_key_id"] = k["key_id"]
    state.setdefault("rotation_history", []).append({"event": "rotate", "key_id": k["key_id"], "time": now_iso()})
    write_json(KEYS_FILE, state)
    print(f"Key rotated. Active key: {k['key_id']}")


def show_keys() -> None:
    state = read_json(KEYS_FILE, default={})
    if not state:
        print("No SKS state found. Run --init first.")
        return
    print(f"SKS: {state.get('sks_name')}")
    print(f"Active key: {state.get('active_key_id')}")
    print("Keys:")
    for key_id, key in state.get("keys", {}).items():
        print(f"  - {key_id} | version={key.get('version')} | status={key.get('status')} | created={key.get('created_at')}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Simplified Security Key Service/SKS prototype.")
    parser.add_argument("--init", action="store_true", help="Initialize SKS keys")
    parser.add_argument("--force", action="store_true", help="Overwrite existing SKS during --init")
    parser.add_argument("--rotate", action="store_true", help="Rotate key once")
    parser.add_argument("--rotate-every", type=int, default=0, help="Rotate key every N seconds")
    parser.add_argument("--show", action="store_true", help="Show active keys")
    args = parser.parse_args()

    if args.init:
        init_keys(force=args.force)
    elif args.rotate:
        rotate_key()
    elif args.rotate_every:
        init_keys(force=False)
        print(f"SKS key rotation loop started. Rotation interval: {args.rotate_every}s")
        try:
            while True:
                time.sleep(args.rotate_every)
                rotate_key()
        except KeyboardInterrupt:
            print("\nSKS rotation stopped.")
    elif args.show:
        show_keys()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
