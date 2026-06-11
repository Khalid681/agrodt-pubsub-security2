# Technical Report: End-to-End Payload Protection for AgroDT Sensor Data

## 1. Objective

The objective is to validate end-to-end payload protection for agricultural sensor data using OPC UA PubSub-style UADP messages transported through MQTT.

The proof of concept includes:

- Publisher
- MQTT broker
- Authorized Subscriber
- Unauthorized Subscriber
- Simplified Digital Twin state
- SKS/key-management prototype
- Security modes: None, Sign, SignAndEncrypt

## 2. Dataset Fields

| Field | Purpose |
|---|---|
| SensorId | Identifies the soil sensor |
| Timestamp | Time of sensor measurement |
| SequenceNumber | Used for ordering and replay detection |
| SoilMoisture | Soil moisture value |
| SoilTemperature | Soil temperature value |
| SoilPH | Soil pH value |

## 3. Security Modes

| Mode | Confidentiality | Integrity | Authenticity | Payload visible? |
|---|---:|---:|---:|---:|
| None | No | No | No | Yes |
| Sign | No | Yes | Yes | Yes |
| SignAndEncrypt | Yes | Yes | Yes | No |

## 4. Cryptographic Design

This project does not develop a new encryption algorithm. It uses standard cryptographic mechanisms:

| Function | Method |
|---|---|
| Signature / message authentication | HMAC-SHA256 |
| Encryption and authentication | AES-256-GCM |
| Key generation | Local SKS prototype |
| Key rotation | Active key update in SKS file |

## 5. MQTT Transport Security vs End-to-End Payload Security

MQTT TLS protects communication links:

Publisher -> Broker  
Subscriber -> Broker

However, the broker terminates TLS and can see the MQTT payload after decryption.

End-to-end UADP-style payload security protects the message content:

Publisher -> Subscriber

Therefore, even the MQTT broker cannot read encrypted payload data in SignAndEncrypt mode.

## 6. Attack Tests

| Test | Expected Result |
|---|---|
| Payload tampering | Rejected in Sign and SignAndEncrypt modes |
| Unauthorized Subscriber | Cannot decrypt SignAndEncrypt payload |
| Unauthorized Publisher | Rejected because key/signature is invalid |
| Replay attack | Rejected using SequenceNumber check |
| Key rotation | Valid Publisher/Subscriber continue with new keys |

## 7. Packet Capture Analysis

Expected observations:

| Mode | PCAP Observation |
|---|---|
| None | Soil values visible in MQTT payload |
| Sign | Soil values visible, signature also visible |
| SignAndEncrypt | Soil values hidden, only ciphertext visible |

## 8. Visible Metadata Under Encryption

Even when payload is encrypted, some metadata remains visible:

| Metadata | Reason |
|---|---|
| MQTT topic | Required for routing |
| Broker IP and port | Network routing |
| Packet size | Observable from traffic |
| Publish frequency | Observable from timing |
| Security mode | Present in message header |
| PublisherId | Routing/identification metadata |
| SecurityGroupId | Needed for key selection |
| KeyId | Needed for key lookup |

## 9. Performance Metrics

The system records:

- Latency
- Message size
- CPU usage
- Memory usage
- Status accepted/rejected

Raw data is saved in:

`results/subscriber_metrics.csv`

Summary is saved in:

`results/benchmark_summary.csv`

## 10. Limitations

This is a Phase-1 proof of concept. It uses a simplified UADP-style message envelope in Python. It is not a strict official OPC UA PubSub binary UADP stack. For industrial compliance, a Phase-2 implementation should be developed with open62541 or another OPC UA PubSub-compliant stack.

The SKS is also simplified and runs locally. In real deployments, the SKS should be hosted in a trusted edge gateway, institutional server, or cloud security service.
