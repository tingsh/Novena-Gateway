#     Copyright 2026. ThingsBoard
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.

from struct import pack, unpack
from time import time
from typing import List, Union

from pymodbus.client.mixin import ModbusClientMixin
from pymodbus.constants import Endian
from pymodbus.utilities import pack_bitstring, unpack_bitstring

from novena_gateway.connectors.modbus.entities.bytes_uplink_converter_config import BytesUplinkConverterConfig
from novena_gateway.connectors.modbus.modbus_converter import ModbusConverter
from novena_gateway.connectors.modbus.utils import Utils
from novena_gateway.connectors.modbus.constants import REQUIRED_KEYS_FOR_WIDE_RANGE_TAG_NAME
from novena_gateway.gateway.entities.converted_data import ConvertedData
from novena_gateway.gateway.entities.report_strategy_config import ReportStrategyConfig
from novena_gateway.gateway.statistics.decorators import CollectStatistics
from novena_gateway.gateway.statistics.statistics_service import StatisticsService
from novena_gateway.tb_utility.tb_utility import TBUtility


class BytesModbusUplinkConverter(ModbusConverter):
    def __init__(self, config: BytesUplinkConverterConfig, logger):
        self._log = logger
        self.__config = config

    @CollectStatistics(start_stat_type='receivedBytesFromDevices',
                       end_stat_type='convertedBytesFromDevice')
    def convert(self, _, data: List[dict]) -> Union[ConvertedData, None]:
        result = ConvertedData(self.__config.device_name, self.__config.device_type,
                               device_id=getattr(self.__config, 'device_id', None))
        device_report_strategy = self._get_device_report_strategy(self.__config.report_strategy,
                                                                  self.__config.device_name)

        converted_data_append_methods = {
            'attributes': result.add_to_attributes,
            'telemetry': result.add_to_telemetry
        }
        
        received_data_ts = int(time() * 1000)

        for device_data in data:
            StatisticsService.count_connector_message(self._log.name, 'convertersMsgProcessed')

            for config_section in converted_data_append_methods:
                for config in getattr(self.__config, config_section):
                    encoded_data = device_data[config_section].get(config['tag'])

                    try:
                        if Utils.is_wide_range_request(config['address']):
                            datapoints = self.__process_wide_range_response(config, encoded_data)
                        else:
                            datapoints = self.__process_single_address_response(config, encoded_data)
                    except (ValueError, IndexError, TypeError) as e:
                        self._log.error("Encoded data is invalid: %s, with config: %s, error: %s",
                                        encoded_data, config, e)
                        continue

                    for datapoint in datapoints:
                        for key_name, decoded_data in datapoint.items():
                            datapoint_key = TBUtility.convert_key_to_datapoint_key(key_name,
                                                                                   device_report_strategy,
                                                                                   config,
                                                                                   self._log)
                            payload = {datapoint_key: decoded_data}
                            if config_section == 'telemetry':
                                payload['ts'] = received_data_ts

                            converted_data_append_methods[config_section](payload)

        self._log.trace("Decoded data: %s", result)
        StatisticsService.count_connector_message(self._log.name, 'convertersAttrProduced',
                                                  count=result.attributes_datapoints_count)
        StatisticsService.count_connector_message(self._log.name, 'convertersTsProduced',
                                                  count=result.telemetry_datapoints_count)

        return result

    def __process_wide_range_response(self, config, encoded_data):
        encoded_data = self.__validate_wide_range_encoded_data(encoded_data)
        registers_data = self.__get_registers_from_wide_range_encoded_data(encoded_data,
                                                                           config['functionCode'])
        datapoints = self.__process_wide_range_response_encoded_data(config, registers_data)
        return datapoints

    def __validate_wide_range_encoded_data(self, encoded_data):
        invalid_chunks = []

        for chunk in encoded_data:
            if not Utils.is_encoded_data_valid(chunk):
                invalid_chunks.append(chunk)
                self._log.error("Encoded data chunk is invalid: %s. Skipping", chunk)

        if len(invalid_chunks) > 0:
            encoded_data = [chunk for chunk in encoded_data if chunk not in invalid_chunks]

        return encoded_data

    def __get_registers_from_wide_range_encoded_data(self, encoded_data, function_code):
        registers_data = []

        for chunk in encoded_data:
            registers_chunk = Utils.get_registers_from_encoded_data(chunk, function_code)
            registers_data.extend(registers_chunk)

        return registers_data

    def __process_single_address_response(self, config, encoded_data):
        encoded_data = encoded_data[0]

        if not Utils.is_encoded_data_valid(encoded_data):
            raise ValueError('Encoded data is invalid')

        registers_data = Utils.get_registers_from_encoded_data(encoded_data,
                                                               config['functionCode'])

        datapoints = self.__process_single_address_response_encoded_data(config, registers_data)

        return datapoints

    def __process_wide_range_response_encoded_data(self, config, encoded_data):
        result = []

        try:
            current_address = Utils.get_start_address(config['address'])
        except Exception as e:
            self._log.error("Error getting start address from config: %s, with config: %s",
                            e, config, exc_info=e)
            return []

        for i in range(0, len(encoded_data), config.get('objectsCount', 1)):
            chunk = encoded_data[i:i + config.get('objectsCount', 1)]
            decoded_data = self.decode_data(chunk, config,
                                            self.__config.byte_order,
                                            self.__config.word_order)

            if decoded_data is None:
                self._log.warning("Decoded data is empty, with config: %s", config)
                continue

            key_name = self.__get_key_name(config, current_address)
            result.append({key_name: decoded_data})

            current_address += config.get('objectsCount', 1)

        return result

    def __process_single_address_response_encoded_data(self, config, encoded_data):
        decoded_data = self.decode_data(encoded_data, config,
                                        self.__config.byte_order,
                                        self.__config.word_order)

        if decoded_data is None:
            self._log.warning("Decoded data is empty, with config: %s", config)
            return []

        key_name = self.__get_key_name(config)

        return [{key_name: decoded_data}]

    def __get_key_name(self, config, current_address=None):
        if Utils.is_wide_range_request(config['address']) and current_address is not None:
            key_name = self.__get_wide_range_key_name(config, current_address)
        else:
            key_name = config['tag']

        return key_name

    def __get_wide_range_key_name(self, config, current_address):
        key_name_info = self.__get_info_for_key_name(config)
        key_name_info['address'] = current_address
        config['tag'] = self.__validate_key_name_expression(config['tag'])
        result_tags = TBUtility.get_values(config['tag'], key_name_info, get_tag=True)
        result_values = TBUtility.get_values(config['tag'], key_name_info, expression_instead_none=True)

        result = config['tag']
        for (result_tag, result_value) in zip(result_tags, result_values):
            is_valid_key = "${" in config['tag'] and "}" in config['tag']
            result = result.replace('${' + str(result_tag) + '}',
                                    str(result_value)) if is_valid_key else result_tag

        return result

    def __get_info_for_key_name(self, config):
        return {
            'unitId': self.__config.unit_id,
            'address': config['address'],
            'functionCode': config['functionCode'],
            'type': config['type'],
            'objectsCount': config.get('objectsCount', 1),
        }

    def __validate_key_name_expression(self, key_name):
        for required_key in REQUIRED_KEYS_FOR_WIDE_RANGE_TAG_NAME:
            if required_key not in key_name:
                self._log.warning("Tag name '%s' does not contain required key '%s'. "
                                  "Appending it to the key name.", key_name, required_key)
                key_name += f"_${{{required_key}}}"

        return key_name

    def decode_data(self, encoded_data, config, endian_order, word_endian_order):
        decoded_data = None

        if config['functionCode'] in (1, 2):
            decoded_data = self.decode_from_coils(encoded_data, config, endian_order)
        elif config['functionCode'] in (3, 4):
            decoded_data = self.decode_from_registers(encoded_data, config,
                                                      endian_order, word_endian_order)

            if config.get('divider'):
                decoded_data = float(decoded_data) / float(config['divider'])
            elif config.get('multiplier'):
                decoded_data = decoded_data * config['multiplier']
            if config.get('offset') is not None:
                decoded_data = decoded_data + config['offset']

        if self._is_enum_value(config):
            decoded_data = self._process_enum_value(config, decoded_data)

        return decoded_data

    @staticmethod
    def _register_bytes(registers):
        return b''.join(pack('>H', register) for register in registers)

    @classmethod
    def _ordered_registers(cls, registers, byte_order, word_order):
        words = [cls._register_bytes([register]) for register in registers]
        if byte_order == Endian.LITTLE:
            words = [word[::-1] for word in words]
        if word_order == Endian.LITTLE:
            words.reverse()
        return [unpack('>H', word)[0] for word in words]

    @staticmethod
    def _coil_payload(coils):
        coils = list(coils)
        if padding := len(coils) % 8:
            coils = ([False] * padding) + coils
        return b''.join(pack_bitstring(chunk[::-1])
                        for chunk in (coils[index:index + 8]
                                      for index in range(0, len(coils), 8)))

    def decode_from_coils(self, coils, configuration, endian_order=Endian.LITTLE):
        payload = self._coil_payload(coils)
        lower_type = configuration['type'].lower()
        objects_count = self._objects_count(configuration)

        if lower_type in ('bit', 'bits'):
            decoded = unpack_bitstring(payload[:2])
            return self._format_decoded(decoded[-objects_count:], configuration, lower_type)

        if lower_type in ('string', 'bytes'):
            return self._format_decoded(
                payload[:objects_count * 2], configuration, lower_type
            )

        if lower_type in ('8int', '8uint'):
            decoded = unpack('>b' if lower_type == '8int' else '>B', payload[:1])[0]
            return self._format_decoded(decoded, configuration, lower_type)

        if len(payload) % 2:
            raise ValueError('Coil payload does not contain a complete register')
        registers = [unpack('>H', payload[index:index + 2])[0]
                     for index in range(0, len(payload), 2)]
        return self.decode_from_registers(registers, configuration, endian_order, Endian.BIG)

    @staticmethod
    def _objects_count(configuration):
        return configuration.get('objectsCount',
                                 configuration.get('registersCount',
                                                   configuration.get('registerCount', 1)))

    def decode_from_registers(self, registers, configuration,
                              endian_order=Endian.BIG, word_endian_order=Endian.BIG):
        objects_count = configuration.get("objectsCount",
                                          configuration.get("registersCount", configuration.get("registerCount", 1)))
        lower_type = configuration["type"].lower()
        raw_payload = self._register_bytes(registers)

        if lower_type in ('string', 'bytes'):
            decoded = raw_payload[:objects_count * 2]
        elif lower_type in ('bit', 'bits'):
            decoded = ModbusClientMixin.convert_from_registers(
                registers, ModbusClientMixin.DATATYPE.BITS
            )[-objects_count:]
        elif lower_type in ('8int', '8uint'):
            decoded = unpack('>b' if lower_type == '8int' else '>B', raw_payload[:1])[0]
        else:
            resolved_type = lower_type
            if lower_type in ('int', 'long', 'integer'):
                resolved_type = f'{objects_count * 16}int'
            elif lower_type in ('double', 'float'):
                resolved_type = f'{objects_count * 16}float'
            elif lower_type == 'uint':
                resolved_type = f'{objects_count * 16}uint'

            ordered_registers = self._ordered_registers(registers, endian_order,
                                                        word_endian_order)
            if resolved_type == '16float':
                decoded = unpack('>e', self._register_bytes(ordered_registers[:1]))[0]
            else:
                decoder_types = {
                    '16int': ModbusClientMixin.DATATYPE.INT16,
                    '16uint': ModbusClientMixin.DATATYPE.UINT16,
                    '32int': ModbusClientMixin.DATATYPE.INT32,
                    '32uint': ModbusClientMixin.DATATYPE.UINT32,
                    '32float': ModbusClientMixin.DATATYPE.FLOAT32,
                    '64int': ModbusClientMixin.DATATYPE.INT64,
                    '64uint': ModbusClientMixin.DATATYPE.UINT64,
                    '64float': ModbusClientMixin.DATATYPE.FLOAT64,
                }
                data_type = decoder_types.get(resolved_type)
                if data_type is None:
                    self._log.error("Unknown type: %s", lower_type)
                    decoded = None
                else:
                    required_registers = data_type.value[1]
                    decoded = ModbusClientMixin.convert_from_registers(
                        ordered_registers[:required_registers], data_type
                    )

        return self._format_decoded(decoded, configuration, lower_type)

    def _format_decoded(self, decoded, configuration, lower_type):
        objects_count = self._objects_count(configuration)

        if isinstance(decoded, int):
            result_data = decoded
        elif isinstance(decoded, bytes) and lower_type == "string":
            try:
                result_data = decoded.decode('UTF-8')
            except UnicodeDecodeError as e:
                self._log.error("Error decoding string from bytes, will be saved as hex: %s", decoded, exc_info=e)
                result_data = decoded.hex()
        elif isinstance(decoded, bytes) and lower_type == "bytes":
            result_data = decoded.hex()
        elif isinstance(decoded, list):
            if configuration.get('bit') is not None:
                result_data = int(decoded[configuration['bit'] if
                                          configuration['bit'] < len(decoded) else len(decoded) - 1])
            else:
                bitAsBoolean = configuration.get('bitTargetType', 'bool') == 'bool'
                if objects_count == 1:
                    result_data = bool(decoded[-1]) if bitAsBoolean else int(decoded[-1])
                else:
                    result_data = [bool(bit) if bitAsBoolean else int(bit) for bit in decoded]
        elif isinstance(decoded, float):
            result_data = float(round(decoded, configuration.get('round', 6)))
        elif decoded is not None:
            result_data = int(decoded, 16)
        else:
            result_data = decoded

        return result_data

    def _get_device_report_strategy(self, report_strategy, device_name):
        try:
            return ReportStrategyConfig(report_strategy)
        except ValueError as e:
            self._log.trace("Report strategy config is not specified for device %s: %s", device_name, e)

    @staticmethod
    def _is_enum_value(config):
        return 'variants' in config

    def _process_enum_value(self, config, decoded_data):
        try:
            enum_key = str(decoded_data)

            return config['variants'].get(enum_key, decoded_data)
        except Exception as e:
            self._log.exception(e)
            return decoded_data
