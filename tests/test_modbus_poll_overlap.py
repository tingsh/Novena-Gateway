"""Modbus polling must not overlap requests to one field device."""

import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock

from pymodbus.exceptions import ModbusIOException

from novena_gateway.connectors.modbus.modbus_connector import AsyncModbusConnector


class TestModbusPollOverlap(unittest.IsolatedAsyncioTestCase):
    async def test_slow_poll_does_not_start_a_second_poll_for_same_slave(self):
        connector = object.__new__(AsyncModbusConnector)
        connector.loop = asyncio.get_running_loop()
        connector.process_device_requests = asyncio.Queue()
        connector._active_polls = set()
        connector._AsyncModbusConnector__stopped = False
        connector._AsyncModbusConnector__log = MagicMock()
        slave = MagicMock(type="tcp")
        started = asyncio.Event()
        release = asyncio.Event()
        calls = 0

        async def slow_poll(_slave):
            nonlocal calls
            calls += 1
            started.set()
            await release.wait()

        connector._AsyncModbusConnector__poll_device = slow_poll
        processor = asyncio.create_task(connector._AsyncModbusConnector__process_requests())
        try:
            connector.process_device_requests.put_nowait(slave)
            await asyncio.wait_for(started.wait(), timeout=1)
            connector.process_device_requests.put_nowait(slave)
            await asyncio.sleep(0.2)
            self.assertEqual(calls, 1)
        finally:
            release.set()
            connector._AsyncModbusConnector__stopped = True
            processor.cancel()
            await asyncio.gather(processor, return_exceptions=True)

    async def test_tcp_no_response_closes_stale_client_for_next_poll(self):
        connector = object.__new__(AsyncModbusConnector)
        connector._AsyncModbusConnector__log = MagicMock()
        connector._AsyncModbusConnector__gateway = MagicMock()
        connector._AsyncModbusConnector__gateway.get_devices.return_value = {"Main Gateway"}
        connector._AsyncModbusConnector__read_slave_data = AsyncMock(
            side_effect=ModbusIOException("No response received after 3 retries")
        )
        slave = MagicMock(type="tcp", device_name="Main Gateway")
        slave.uplink_converter_config.attributes = []
        slave.uplink_converter_config.telemetry = [{"tag": "temperature"}]
        slave.connect = AsyncMock(return_value=True)
        slave.disconnect = AsyncMock()
        slave.master.connected.return_value = True

        await connector._AsyncModbusConnector__poll_device(slave)

        slave.disconnect.assert_awaited_once()
        connector._AsyncModbusConnector__gateway.del_device.assert_called_once_with("Main Gateway")
        connector._AsyncModbusConnector__gateway.record_device_failure.assert_called_once()

    async def test_two_slaves_on_one_master_do_not_poll_concurrently(self):
        connector = object.__new__(AsyncModbusConnector)
        connector.loop = asyncio.get_running_loop()
        connector.process_device_requests = asyncio.Queue()
        connector._active_polls = set()
        connector._AsyncModbusConnector__stopped = False
        connector._AsyncModbusConnector__log = MagicMock()
        shared_master = object()
        first = MagicMock(type="tcp", master=shared_master)
        second = MagicMock(type="tcp", master=shared_master)
        started = asyncio.Event()
        release = asyncio.Event()
        calls = []

        async def slow_poll(slave):
            calls.append(slave)
            started.set()
            await release.wait()

        connector._AsyncModbusConnector__poll_device = slow_poll
        processor = asyncio.create_task(connector._AsyncModbusConnector__process_requests())
        try:
            connector.process_device_requests.put_nowait(first)
            await asyncio.wait_for(started.wait(), timeout=1)
            connector.process_device_requests.put_nowait(second)
            await asyncio.sleep(0.2)
            self.assertEqual(calls, [first])
        finally:
            release.set()
            connector._AsyncModbusConnector__stopped = True
            processor.cancel()
            await asyncio.gather(processor, return_exceptions=True)

    async def test_independent_masters_can_poll_concurrently(self):
        connector = object.__new__(AsyncModbusConnector)
        connector.loop = asyncio.get_running_loop()
        connector.process_device_requests = asyncio.Queue()
        connector._active_polls = set()
        connector._AsyncModbusConnector__stopped = False
        connector._AsyncModbusConnector__log = MagicMock()
        first = MagicMock(type="tcp", master=object())
        second = MagicMock(type="tcp", master=object())
        both_started = asyncio.Event()
        release = asyncio.Event()
        calls = []

        async def slow_poll(slave):
            calls.append(slave)
            if len(calls) == 2:
                both_started.set()
            await release.wait()

        connector._AsyncModbusConnector__poll_device = slow_poll
        processor = asyncio.create_task(connector._AsyncModbusConnector__process_requests())
        try:
            connector.process_device_requests.put_nowait(first)
            connector.process_device_requests.put_nowait(second)
            await asyncio.wait_for(both_started.wait(), timeout=1)
            self.assertCountEqual(calls, [first, second])
        finally:
            release.set()
            connector._AsyncModbusConnector__stopped = True
            processor.cancel()
            await asyncio.gather(processor, return_exceptions=True)


if __name__ == "__main__":
    unittest.main()
