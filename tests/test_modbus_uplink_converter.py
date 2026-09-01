"""Compatibility coverage for the pymodbus 3.8 register conversion API."""

import logging
import struct
import unittest
from types import SimpleNamespace

from pymodbus.constants import Endian

from novena_gateway.connectors.modbus.bytes_modbus_uplink_converter import BytesModbusUplinkConverter
from novena_gateway.connectors.modbus.entities.bytes_uplink_converter_config import BytesUplinkConverterConfig
from novena_gateway.gateway.payload_formatter import PayloadFormatter


class CaptureHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(record)


class ModbusUplinkDecoderTest(unittest.TestCase):
    def setUp(self):
        self.converter = object.__new__(BytesModbusUplinkConverter)
        self.converter._log = logging.getLogger("test.modbus.converter")

    def decode(self, registers, type_name, *, byte_order=Endian.BIG,
               word_order=Endian.BIG, **extra):
        config = {
            "functionCode": 3,
            "type": type_name,
            "objectsCount": len(registers),
            **extra,
        }
        return self.converter.decode_data(registers, config, byte_order, word_order)

    def test_signed_unsigned_integer_and_float_widths(self):
        cases = (
            ([0xFF80], "8int", -1),
            ([0x12FF], "8uint", 18),
            ([0xFF80], "16int", -128),
            ([0xFEDC], "16uint", 65244),
            ([0x3E00], "16float", 1.5),
            ([0xFFFF, 0xFF80], "32int", -128),
            ([0x1234, 0x5678], "32uint", 0x12345678),
            (list(struct.unpack(">HH", struct.pack(">f", 230.5))), "32float", 230.5),
            (list(struct.unpack(">HHHH", struct.pack(">q", -1234567890123))),
             "64int", -1234567890123),
            (list(struct.unpack(">HHHH", struct.pack(">Q", 123456789012345))),
             "64uint", 123456789012345),
            (list(struct.unpack(">HHHH", struct.pack(">d", 12345.625))),
             "64float", 12345.625),
        )
        for registers, type_name, expected in cases:
            with self.subTest(type_name=type_name):
                self.assertEqual(self.decode(registers, type_name), expected)

    def test_byte_and_word_order_match_legacy_contract(self):
        registers = [0x1234, 0x5678]
        expected = {
            (Endian.BIG, Endian.BIG): 0x12345678,
            (Endian.BIG, Endian.LITTLE): 0x56781234,
            (Endian.LITTLE, Endian.BIG): 0x34127856,
            (Endian.LITTLE, Endian.LITTLE): 0x78563412,
        }
        for (byte_order, word_order), value in expected.items():
            with self.subTest(byte_order=byte_order, word_order=word_order):
                self.assertEqual(
                    self.decode(registers, "32uint", byte_order=byte_order,
                                word_order=word_order),
                    value,
                )

    def test_strings_bytes_register_bits_and_coils(self):
        self.assertEqual(self.decode([0x4142, 0x4344], "string"), "ABCD")
        self.assertEqual(self.decode([0x00FF, 0x10A0], "bytes"), "00ff10a0")
        self.assertEqual(
            self.decode([0x0102], "bits", objectsCount=8, bitTargetType="int"),
            [0, 1, 0, 0, 0, 0, 0, 0],
        )

        coils = [True, False, False, False, False, False, False, False]
        coil_config = {
            "functionCode": 1,
            "type": "bits",
            "objectsCount": 1,
            "bitTargetType": "bool",
        }
        self.assertIs(
            self.converter.decode_data(coils, coil_config, Endian.LITTLE, Endian.BIG),
            True,
        )

    def test_alias_scaling_offset_and_enum_conversion(self):
        self.assertEqual(self.decode([0xFFFF, 0xFF80], "int"), -128)
        self.assertEqual(self.decode([0x1234, 0x5678], "uint"), 0x12345678)
        self.assertEqual(self.decode([0x3F80, 0x0000], "float"), 1.0)
        self.assertEqual(
            self.decode([100], "16uint", multiplier=0.1, offset=-5),
            5,
        )
        self.assertEqual(
            self.decode([100], "16uint", divider=4, multiplier=100, offset=1),
            26,
        )
        self.assertEqual(
            self.decode([2], "16uint", variants={"2": "running"}),
            "running",
        )

    def test_normal_register_decoding_emits_no_pymodbus_warning(self):
        capture = CaptureHandler()
        pymodbus_logger = logging.getLogger("pymodbus")
        pymodbus_logger.addHandler(capture)
        try:
            for _ in range(42):
                self.decode([100], "16uint")
                self.decode([200], "16uint")
        finally:
            pymodbus_logger.removeHandler(capture)

        self.assertEqual(capture.records, [])

    def test_convert_preserves_keys_values_device_identity_and_timestamp(self):
        point = {
            "tag": "active_power",
            "type": "32float",
            "functionCode": 3,
            "objectsCount": 2,
            "address": 3060,
            "multiplier": 0.1,
            "offset": 2,
        }
        config = BytesUplinkConverterConfig(
            deviceName="Power Meter 1",
            deviceId=123,
            unitId=1,
            byteOrder="BIG",
            wordOrder="BIG",
            timeseries=[point],
            attributes=[],
        )
        converter = BytesModbusUplinkConverter(config, logging.getLogger("test.modbus.convert"))
        registers = list(struct.unpack(">HH", struct.pack(">f", 450.0)))
        response = SimpleNamespace(registers=registers)

        converted = converter.convert(None, [{
            "telemetry": {"active_power": [response]},
            "attributes": {},
        }])
        payload = PayloadFormatter("NF-TEST-001").format(converted)[0]

        self.assertEqual(payload["serial_number"], "NF-TEST-001")
        self.assertEqual(payload["device_id"], 123)
        self.assertEqual(payload["device_name"], "Power Meter 1")
        self.assertEqual(payload["values"]["device_name"], "Power Meter 1")
        self.assertEqual(payload["values"]["active_power"], 47.0)
        self.assertIsInstance(payload["ts"], int)
        self.assertGreater(payload["ts"], 0)

    def test_wide_range_register_keys_and_values_remain_compatible(self):
        point = {
            "tag": "register_${address}",
            "type": "16uint",
            "functionCode": 3,
            "objectsCount": 1,
            "address": "10-12",
        }
        config = BytesUplinkConverterConfig(
            deviceName="Wide Range Device",
            unitId=1,
            byteOrder="BIG",
            wordOrder="BIG",
            timeseries=[point],
            attributes=[],
        )
        converter = BytesModbusUplinkConverter(config, logging.getLogger("test.modbus.wide"))
        response = SimpleNamespace(registers=[11, 22, 33])

        converted = converter.convert(None, [{
            "telemetry": {"register_${address}": [response]},
            "attributes": {},
        }])
        values = PayloadFormatter("NF-TEST-WIDE").format(converted)[0]["values"]

        self.assertEqual(values["register_10"], 11)
        self.assertEqual(values["register_11"], 22)
        self.assertEqual(values["register_12"], 33)

    def test_tcp_and_rtu_slave_configs_use_the_same_conversion_contract(self):
        registers = list(struct.unpack(">HH", struct.pack(">f", 230.5)))
        for transport in (
            {"type": "tcp", "host": "127.0.0.1", "port": 502},
            {"type": "serial", "port": "/dev/ttyUSB0", "baudrate": 19200,
             "parity": "N", "stopbits": 1, "bytesize": 8},
        ):
            with self.subTest(transport=transport["type"]):
                config = BytesUplinkConverterConfig(
                    deviceName="Compatible Meter",
                    unitId=1,
                    byteOrder="BIG",
                    wordOrder="BIG",
                    timeseries=[],
                    attributes=[],
                    **transport,
                )
                converter = BytesModbusUplinkConverter(
                    config, logging.getLogger(f"test.modbus.{transport['type']}")
                )
                self.assertEqual(
                    converter.decode_data(
                        registers,
                        {"functionCode": 3, "type": "32float", "objectsCount": 2},
                        config.byte_order,
                        config.word_order,
                    ),
                    230.5,
                )


if __name__ == "__main__":
    unittest.main()
