"""
Integration test: Modbus TCP simulator → Novena Gateway → Payload verification

Starts a local pymodbus TCP server with known register values, then
verifies that the PayloadFormatter produces correct Novena Hub payloads
from ConvertedData objects matching what the Modbus connector would produce.

This test validates the data pipeline WITHOUT requiring a live MQTT broker.
"""

import sys
import os
import struct
import asyncio
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymodbus.datastore import (
    ModbusSlaveContext,
    ModbusServerContext,
    ModbusSequentialDataBlock,
)
from pymodbus.server import StartTcpServer

from novena_gateway.gateway.payload_formatter import PayloadFormatter
from novena_gateway.gateway.entities.converted_data import ConvertedData
from novena_gateway.gateway.entities.datapoint_key import DatapointKey
from novena_gateway.gateway.entities.telemetry_entry import TelemetryEntry


# ─── Helpers ──────────────────────────────────────────────────────────

def float32_to_registers(value: float):
    """Convert a float to two 16-bit Modbus registers (big-endian)."""
    packed = struct.pack('>f', value)
    reg_hi = struct.unpack('>H', packed[0:2])[0]
    reg_lo = struct.unpack('>H', packed[2:4])[0]
    return [reg_hi, reg_lo]


def build_holding_registers(register_map: dict, total_count: int = 100):
    """
    Build a ModbusSequentialDataBlock from a {address: float_value} map.
    ModbusSlaveContext internally offsets addresses by +1, so the block
    starts at address 0 but the slave maps client address 0 → index 1.
    We pre-shift values to account for this.
    """
    values = [0] * (total_count + 1)
    for addr, fval in register_map.items():
        regs = float32_to_registers(fval)
        values[addr] = regs[0]
        values[addr + 1] = regs[1]
    return ModbusSequentialDataBlock(1, values)


# ─── Test class ───────────────────────────────────────────────────────

class TestModbusIntegration(unittest.TestCase):
    """Validate the Modbus data → Novena payload pipeline."""

    SERVER_HOST = "127.0.0.1"
    SERVER_PORT = 15502  # non-standard port to avoid conflicts

    # Known register values that our simulated PLC will serve
    REGISTER_MAP = {
        0: 450.2,   # active_power  (address 0, 2 registers)
        2: 230.1,   # voltage       (address 2, 2 registers)
        4: 12.5,    # current       (address 4, 2 registers)
    }

    @classmethod
    def setUpClass(cls):
        """Start a local Modbus TCP server in a background thread."""
        hr_block = build_holding_registers(cls.REGISTER_MAP, total_count=100)
        store = ModbusSlaveContext(hr=hr_block, ir=hr_block)
        cls.context = ModbusServerContext(slaves=store, single=True)

        cls._server_thread = threading.Thread(
            target=cls._run_server, daemon=True
        )
        cls._server_thread.start()
        time.sleep(1)  # Give server time to start

    @classmethod
    def _run_server(cls):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(
            StartTcpServer(
                context=cls.context,
                address=(cls.SERVER_HOST, cls.SERVER_PORT),
            )
        )

    def test_read_modbus_and_format_payload(self):
        """
        Read registers from the simulator using pymodbus client,
        then verify the PayloadFormatter produces the correct output.
        """
        from pymodbus.client import ModbusTcpClient

        client = ModbusTcpClient(self.SERVER_HOST, port=self.SERVER_PORT)
        self.assertTrue(client.connect(), "Failed to connect to Modbus simulator")

        try:
            # Read active_power (address 0, 2 registers)
            result = client.read_holding_registers(0, count=2, slave=1)
            self.assertFalse(result.isError(), f"Modbus read error: {result}")
            active_power = struct.unpack('>f', struct.pack('>HH', *result.registers))[0]

            # Read voltage (address 2, 2 registers)
            result = client.read_holding_registers(2, count=2, slave=1)
            self.assertFalse(result.isError())
            voltage = struct.unpack('>f', struct.pack('>HH', *result.registers))[0]

            # Read current (address 4, 2 registers)
            result = client.read_holding_registers(4, count=2, slave=1)
            self.assertFalse(result.isError())
            current = struct.unpack('>f', struct.pack('>HH', *result.registers))[0]
        finally:
            client.close()

        # Verify raw values match what the simulator was configured with
        self.assertAlmostEqual(active_power, 450.2, places=1)
        self.assertAlmostEqual(voltage, 230.1, places=1)
        self.assertAlmostEqual(current, 12.5, places=1)

        # Now simulate what the Modbus connector would do: build ConvertedData
        cd = ConvertedData("Power Meter 1", "default")
        cd.add_to_telemetry(TelemetryEntry({
            DatapointKey("active_power"): round(active_power, 2),
            DatapointKey("voltage"): round(voltage, 2),
            DatapointKey("current"): round(current, 2),
        }))

        # Format into Novena Hub payload
        formatter = PayloadFormatter("NF-EDGE-001")
        payloads = formatter.format(cd)

        self.assertEqual(len(payloads), 1)
        payload = payloads[0]

        # Validate schema compliance
        self.assertEqual(payload["serial_number"], "NF-EDGE-001")
        self.assertIn("ts", payload)
        self.assertIn("values", payload)
        self.assertEqual(payload["values"]["device_name"], "Power Meter 1")
        self.assertAlmostEqual(payload["values"]["active_power"], 450.2, places=1)
        self.assertAlmostEqual(payload["values"]["voltage"], 230.1, places=1)
        self.assertAlmostEqual(payload["values"]["current"], 12.5, places=1)

        print("\n[SUCCESS] Integration test passed!")
        print(f"   Modbus simulator -> ConvertedData -> Novena payload")
        print(f"   Payload: {payload}")


if __name__ == "__main__":
    unittest.main()
