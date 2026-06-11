#!/usr/bin/env bash
set -e
mkdir -p keys
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout keys/broker_ca.key -out keys/broker_ca.crt \
  -subj "/CN=AgroDT-MQTT-CA"
openssl req -newkey rsa:2048 -nodes \
  -keyout keys/broker.key -out keys/broker.csr \
  -subj "/CN=localhost"
openssl x509 -req -in keys/broker.csr -CA keys/broker_ca.crt -CAkey keys/broker_ca.key \
  -CAcreateserial -out keys/broker.crt -days 365
echo "TLS certificates created in keys/"
echo "Start broker with: mosquitto -c conf/mosquitto_tls.conf -v"
