#!/usr/bin/env bash
set -e
source pubsub-env/bin/activate
python3 scripts/authorized_subscriber.py --mode none --max 5 &
SUB_PID=$!
sleep 1
python3 scripts/publisher.py --mode none --csv data/soil_data.csv --count 5 --interval 0.5
wait $SUB_PID || true
