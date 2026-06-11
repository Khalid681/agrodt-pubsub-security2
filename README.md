# AgroDT OPC UA PubSub-style UADP over MQTT Security

This project implements a clean Phase-1 proof of concept for end-to-end payload protection of agricultural sensor data.

## Important scope note

This project uses a simplified **UADP-style message envelope** transported over MQTT. It is designed to validate the security workflow before migrating to a strict OPC UA PubSub implementation such as open62541.

## Required fields

The dataset uses:

- SensorId
- Timestamp
- SequenceNumber
- SoilMoisture
- SoilTemperature
- SoilPH

## Architecture

CSV soil data -> Publisher -> UADP-style protected message -> MQTT broker -> Authorized Subscriber -> Digital Twin state.

The project also includes:

- Unauthorized Subscriber
- Unauthorized Publisher
- Payload tampering
- Replay attack
- SKS prototype
- Key rotation
- Packet capture commands
- Benchmark summary

## Install

```bash
cd "/mnt/c/Users/khalid usman/OneDrive/Desktop"
cd agrodt_pubsub_security_clean

sudo apt update
sudo apt install mosquitto mosquitto-clients tcpdump tshark python3-venv unzip -y

python3 -m venv pubsub-env
source pubsub-env/bin/activate
pip install -r requirements.txt
```

## Start MQTT broker

Terminal 1:

```bash
cd "/mnt/c/Users/khalid usman/OneDrive/Desktop/agrodt_pubsub_security_clean"
mosquitto -c conf/mosquitto_plain.conf -v
```

## Initialize SKS

Terminal 2:

```bash
source pubsub-env/bin/activate
python3 scripts/sks.py --init
python3 scripts/sks.py --show
```

## Run None mode

Terminal 2:

```bash
python3 scripts/authorized_subscriber.py --mode none
```

Terminal 3:

```bash
source pubsub-env/bin/activate
python3 scripts/publisher.py --mode none --csv data/soil_data.csv --count 5 --interval 0.5
```

Expected: messages accepted, payload visible, no integrity protection.

## Run Sign mode

Terminal 2:

```bash
python3 scripts/authorized_subscriber.py --mode sign 
```

Terminal 3:

```bash
python3 scripts/publisher.py --mode sign --csv data/soil_data.csv --count 5 --interval 0.5
```

Expected: messages accepted, payload visible, signature verified.

## Run SignAndEncrypt mode

Terminal 2:

```bash
python3 scripts/authorized_subscriber.py --mode signandencrypt 
```

Terminal 3:

```bash
python3 scripts/publisher.py --mode signandencrypt --csv data/soil_data.csv --count 5 --interval 0.5
```

Expected: messages accepted, payload encrypted.

## Payload tampering test

First publish one signed message while subscriber is running:

```bash
python3 scripts/authorized_subscriber.py --mode sign --max 2
```

In another terminal:

```bash
python3 scripts/publisher.py --mode sign --csv data/soil_data.csv --count 1
python3 scripts/tamper_attack.py
```

Expected: the original message is accepted; the tampered message is rejected.

## Unauthorized Subscriber test

Terminal 2:

```bash
python3 scripts/unauthorized_subscriber.py --max 3
```

Terminal 3:

```bash
python3 scripts/publisher.py --mode signandencrypt --csv data/soil_data.csv --count 3
```

Expected: unauthorized subscriber can see MQTT envelope metadata but cannot decrypt payload.

## Unauthorized Publisher test

Terminal 2:

```bash
python3 scripts/authorized_subscriber.py --mode signandencrypt --max 1
```

Terminal 3:

```bash
python3 scripts/unauthorized_publisher.py --mode signandencrypt
```

Expected: message rejected because key id is unknown or authentication fails.

## Replay attack test

Terminal 2:

```bash
python3 scripts/authorized_subscriber.py --mode signandencrypt --max 3
```

Terminal 3:

```bash
python3 scripts/publisher.py --mode signandencrypt --csv data/soil_data.csv --count 1
python3 scripts/replay_attack.py
```

Expected: original message accepted; replayed duplicate messages rejected.

## Key rotation test

Terminal 2:

```bash
python3 scripts/sks.py --rotate-every 30
```

In parallel, keep publishing/subscribing:

```bash
python3 scripts/authorized_subscriber.py --mode signandencrypt
python3 scripts/publisher.py --mode signandencrypt --csv data/soil_data.csv --count 100 --interval 1
```

Expected: the publisher reads the active SKS key for each new message, and the subscriber validates messages with the current/known keys.

## Packet capture

Run before each mode:

```bash
sudo tcpdump -i lo -w captures/none_mode.pcap port 1883
sudo tcpdump -i lo -w captures/sign_mode.pcap port 1883
sudo tcpdump -i lo -w captures/signandencrypt_mode.pcap port 1883
```

Analyze:

```bash
tshark -r captures/none_mode.pcap
tshark -r captures/sign_mode.pcap
tshark -r captures/signandencrypt_mode.pcap
```

## MQTT TLS transport demo

Create TLS certs:

```bash
bash scripts/generate_mqtt_tls_certs.sh
```

Start TLS broker:

```bash
mosquitto -c conf/mosquitto_tls.conf -v
```

Run subscriber and publisher using TLS:

```bash
python3 scripts/authorized_subscriber.py --mode none --port 8883 --tls --cafile keys/broker_ca.crt
python3 scripts/publisher.py --mode none --csv data/soil_data.csv --count 5 --port 8883 --tls --cafile keys/broker_ca.crt
```

Meaning:
- MQTT TLS protects the transport channel.
- UADP-style SignAndEncrypt protects the payload end-to-end.
- Even with TLS, the broker terminates TLS and can see plaintext payload unless end-to-end payload encryption is used.

## Generate benchmark summary

```bash
python3 scripts/benchmark_summary.py
```

Outputs:

- `results/subscriber_metrics.csv`
- `results/benchmark_summary.csv`
- `results/digital_twin_state.json`
- `logs/publisher.jsonl`
- `logs/authorized_subscriber.jsonl`
- `logs/unauthorized_subscriber.jsonl`
- `logs/attacks.jsonl`

## Visible metadata analysis

```bash
python3 scripts/metadata_analysis.py
```

Even with encrypted payload, these remain visible:
- MQTT topic
- Broker IP/port
- Message timing
- Packet size
- Security mode
- Key ID
- Publisher ID
- Security group ID

