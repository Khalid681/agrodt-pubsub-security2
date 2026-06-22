## Results

This project evaluates security mechanisms for MQTT-based OPC UA PubSub-style communication in an Agro Digital Twin scenario. The experiments compare three payload security modes: `none`, `sign`, and `signandencrypt`.

### Test 1: None Mode Baseline

In `none` mode, the publisher successfully transmitted sensor messages to the authorized subscriber. The subscriber accepted the messages and updated the Digital Twin state.

Result:

* Messages were accepted successfully.
* Payload was visible in plain text.
* No encryption was applied.
* No signature or integrity protection was applied.
* Sensor values such as `SoilMoisture`, `SoilTemperature`, and `SoilPH` were readable in `last_message.json`.

Conclusion: `none` mode confirms that the communication pipeline works, but it provides no confidentiality, integrity, or authenticity.

### Test 2: Sign Mode

In `sign` mode, the payload remained visible, but each message included an HMAC-SHA256 signature and a key identifier.

Result:

* Messages were accepted by the authorized subscriber.
* Payload was still readable in plain text.
* HMAC-SHA256 signature was attached to the message.
* Payload tampering was detected and rejected.

Conclusion: `sign` mode does not hide the sensor data, but it protects message integrity and authenticity. If an attacker modifies the payload, the signature no longer matches and the subscriber rejects the message.

### Test 3: SignAndEncrypt Mode

In `signandencrypt` mode, the payload was encrypted using AES-256-GCM. The `Payload` field became `null`, and the encrypted content was stored as `EncryptedPayloadB64`.

Result:

* Authorized subscriber accepted and decrypted the messages.
* Payload was not visible in plain text.
* Sensor values were protected from unauthorized readers.
* AES-256-GCM provided confidentiality and integrity protection.

Conclusion: `signandencrypt` mode provides confidentiality, integrity, and authenticity for the sensor payload.

### Test 4: Payload Tampering Attack

A valid signed message was modified by changing the sensor payload value. The original message was accepted, while the tampered message was rejected.

Result:

* Original message accepted.
* Modified payload rejected.
* Subscriber detected that the HMAC-SHA256 signature did not match the changed payload.

Conclusion: The system successfully detected payload tampering in `sign` mode.

### Test 5: Unauthorized Subscriber

An unauthorized subscriber connected to the MQTT topic while messages were transmitted in `signandencrypt` mode.

Result:

* Unauthorized subscriber could observe encrypted messages.
* Payload was not readable.
* Subscriber reported: `encrypted_payload_visible_but_not_decryptable_without_key`.

Conclusion: Unauthorized subscribers can see that traffic exists, but they cannot decrypt or read protected sensor data without the correct key.

### Test 6: Unauthorized Publisher

A fake publisher attempted to send a protected message in `signandencrypt` mode.

Result:

* Authorized subscriber rejected the message.
* Rejection reason: `unknown_key_id`.

Conclusion: The system prevents unauthorized publishers from injecting fake protected messages.

### Test 7: Replay Attack

A previously valid encrypted message was published again to simulate a replay attack.

Result:

* First message was accepted.
* Repeated message was rejected.
* Rejection reason: sequence number was not greater than the last accepted sequence number.

Conclusion: Replay protection works using sequence-number validation.

### Test 8: SKS Key Rotation

The Security Key Service rotated keys during message transmission.

Result:

* Messages continued to be accepted after key rotation.
* Digital Twin state showed the updated key ID.
* Encrypted communication continued without failure.

Conclusion: The system supports dynamic key rotation while maintaining secure communication.

### Test 9: MQTT over TLS

MQTT over TLS was tested on port `8883`.

Result:

* Subscriber successfully connected through the TLS broker.
* Messages were accepted.
* TLS protected the transport channel.
* Payload-level protection still depended on the selected mode: `none`, `sign`, or `signandencrypt`.

Conclusion: MQTT TLS protects the communication channel, while application-level payload security provides end-to-end protection of sensor data.

## Summary

| Security Mode    | Payload Visible | Tamper Detection | Encryption | Authentication | Main Result                                  |
| ---------------- | --------------: | ---------------: | ---------: | -------------: | -------------------------------------------- |
| `none`           |             Yes |               No |         No |             No | Baseline only                                |
| `sign`           |             Yes |              Yes |         No |            Yes | Integrity and authenticity                   |
| `signandencrypt` |              No |              Yes |        Yes |            Yes | Confidentiality, integrity, and authenticity |

Overall, the experiments confirm that `none` mode is useful only as a baseline, `sign` mode protects against tampering, and `signandencrypt` provides the strongest protection by encrypting and authenticating sensor payloads. MQTT over TLS adds transport-level protection, while UADP-style payload security protects the data itself.
