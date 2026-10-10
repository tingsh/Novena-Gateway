#!/usr/bin/env python3
"""Probe plain-LAN MQTT authentication using a private saved Gateway config."""
import argparse
import json
from pathlib import Path
import threading

import paho.mqtt.client as mqtt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--expect', choices=('accepted', 'rejected'), required=True)
    parser.add_argument('--bootstrap', action='store_true')
    args = parser.parse_args()
    if args.config.stat().st_mode & 0o077:
        parser.error('saved credential config must have mode 0600')
    config = json.loads(args.config.read_text())
    connection = config['mqtt']
    if connection.get('tls'):
        parser.error('this probe is for the plain-MQTT local replay only')
    credentials = config.get('bootstrap_mqtt', {}) if args.bootstrap else connection
    if not credentials.get('username') or not credentials.get('password'):
        parser.error('saved config does not contain the requested credentials')
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.username_pw_set(credentials['username'], credentials['password'])
    event = threading.Event()
    codes = []

    def connected(client, userdata, flags, code, properties):
        codes.append(code.value)
        event.set()

    client.on_connect = connected
    try:
        client.connect(connection['host'], int(connection.get('port', 1883)))
        client.loop_start()
        if not event.wait(5):
            print('INCONCLUSIVE: no authentication CONNACK received')
            return 2
        expected = codes[0] == 0 if args.expect == 'accepted' else codes[0] in (134, 135)
        print(f'{"PASS" if expected else "FAIL"}: CONNACK={codes[0]}, expected {args.expect}')
        return 0 if expected else 1
    except OSError:
        print('INCONCLUSIVE: broker unreachable; this does not prove revocation')
        return 2
    finally:
        client.disconnect()
        client.loop_stop()


if __name__ == '__main__':
    raise SystemExit(main())
