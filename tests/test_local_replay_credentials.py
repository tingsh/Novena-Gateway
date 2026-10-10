"""Private credentials and isolated identity rendering for real-broker replays."""
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from novena_gateway.gateway.novena_gateway import NovenaGateway

SCRIPT = Path(__file__).resolve().parents[1] / 'install/hardware-test/render_local_replay_config.py'


class ReplayCredentialsTest(unittest.TestCase):
    def test_dedicated_identity_private_input_and_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = root / 'claim-code'
            secret.write_text('test-only-claim-code')
            secret.chmod(0o600)
            output = root / 'config.json'
            output.write_text('{"preserve": "factory config"}')
            args = [sys.executable, str(SCRIPT), '--mqtt-host', '192.168.0.16',
                    '--mqtt-password-file', str(secret), '--serial', 'NOV-DYNSEC-TEST',
                    '--runtime-dir', '/var/lib/novena-gateway/dynsec-test', '--output', str(output),
                    '--public-key-id', 'test', '--public-key-b64', base64.b64encode(b'0'*32).decode(),
                    '--modbus-host', '192.168.0.20']
            result = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('test-only-claim-code', result.stdout + result.stderr)
            config = json.loads(output.read_text())
            self.assertEqual(config['gateway']['serial_number'], 'NOV-DYNSEC-TEST')
            self.assertEqual(config['mqtt']['username'], 'NOV-DYNSEC-TEST')
            self.assertEqual(config['bootstrap_mqtt']['username'], 'bootstrap:NOV-DYNSEC-TEST')
            self.assertNotIn('tls', config['mqtt'])
            self.assertEqual(config['storage']['sqlite']['data_file_path'], '/var/lib/novena-gateway/dynsec-test/sqlite/')
            self.assertEqual(NovenaGateway.validate_config(config), [])
            self.assertEqual(json.loads(next(root.glob('config.json.bak.*')).read_text()), {'preserve': 'factory config'})
            secret.chmod(0o644)
            refused = subprocess.run(args, capture_output=True, text=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertNotIn('test-only-claim-code', refused.stdout + refused.stderr)
            secret.chmod(0o600)
            for invalid_path in ('/tmp/dynsec-test', '/var/lib/novena-gateway', '/var/lib/novena-gateway-dynsec-test'):
                invalid_args = list(args)
                invalid_args[invalid_args.index('--runtime-dir') + 1] = invalid_path
                refused = subprocess.run(invalid_args, capture_output=True, text=True)
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn('absolute subdirectory', refused.stderr)
