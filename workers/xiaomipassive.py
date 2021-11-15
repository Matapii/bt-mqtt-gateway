import time

from mqtt import MqttMessage

from workers.base import BaseWorker
from utils import booleanize
import logger
import struct

REQUIREMENTS = ["bluepy"]
_LOGGER = logger.get(__name__)

# Structured objects for data conversions
TH_STRUCT = struct.Struct("<hH")
H_STRUCT = struct.Struct("<H")
T_STRUCT = struct.Struct("<h")
CND_STRUCT = struct.Struct("<H")
ILL_STRUCT = struct.Struct("<I")
FMDH_STRUCT = struct.Struct("<H")

# Xiaomi sensor types dictionary for adv parser
#                              binary?
XIAOMI_TYPE_DICT = {
    b'\xAA\x01': ("LYWSDCGQ", False),
    b'\x47\x03': ("CGG1", False),
    b'\x48\x0B': ("CGG1-ENCRYPTED", False),
    b'\x5B\x04': ("LYWSD02", False),
    b'\x5B\x05': ("LYWSD03MMC", False),
    b'\x76\x05': ("CGD1", False),
    b'\xd3\x06': ("MHO-C303", False),
    b'\x87\x03': ("MHO-C401", False),
    b'\xDF\x02': ("JQJCY01YM", False),
    b'\x98\x00': ("HHCCJCY01", False),
    b'\xBC\x03': ("GCLS002", False),
    b'\x5D\x01': ("HHCCPOT002", False),
    b'\x0A\x04': ("WX08ZM", True),
    b'\x8B\x09': ("MCCGQ02HL", True),
    b'\x83\x00': ("YM-K1501", True),
    b'\x13\x01': ("YM-K1501EU", True),
    b'\x5C\x04': ("V-SK152", True),
}

class XiaomiStatus:
    monitoredAttrs = ['temperature', 'humidity', 'moisture', 'light', 'conductivity', 'battery', 'rssi']

    def __init__(
        self,
        worker,
        name: str,
        address: str,
        topic_prefix: str,
    ):
        self.worker = worker  # type: BlescanmultiWorker
        self.address = address.lower()
        self.name = name
        self.topic_prefix = topic_prefix

    def format_topic(self, *topic_args):
        return "/".join([self.topic_prefix, *topic_args])

    def generate_messages(self, result):
        messages = []
        for attr in XiaomiStatus.monitoredAttrs:
            if attr in result:
                messages.append(
                    MqttMessage(
                        topic=self.format_topic(self.name, attr),
                        payload=result[attr],
                    )
                )
                #_LOGGER.info(f"MQTT topic {self.format_topic(self.name, attr)} value {result[attr]}")
                _LOGGER.info(f"MQTT {messages[-1]}")
        return messages


class XiaomipassiveWorker(BaseWorker):
    # Default values
    devices = {}
    scan_timeout = 10.0  # type: float
    scan_passive = True  # type: str or bool

    def __init__(self, *args, **kwargs):
        from bluepy.btle import Scanner, DefaultDelegate

        class ScanDelegate(DefaultDelegate):
            def __init__(self, worker):
                DefaultDelegate.__init__(self)
                self.worker = worker

            def handleDiscovery(self, dev, isNewDev, isNewData):
                status = self.worker.device_map.get(dev.addr)
                if status is None:
                    _LOGGER.debug("Unknown device: %s" % dev.addr)
                    return

                if isNewDev:
                    _LOGGER.debug("Discovered new device: %s" % dev.addr)
                elif isNewData:
                    _LOGGER.debug("New data: %s" % dev.addr)
                else:
                    return # Old data

                servData = [val for (sdid, desc, val) in dev.getScanData() if sdid == 0x16]
                if len(servData) <= 0:
                    return
                servData = servData[0]

                _LOGGER.info(f"Device {dev.addr} RSSI {dev.rssi} data <{servData}>")
                servBytes = bytes.fromhex('16'+servData)

                result, _, _ = self.worker.parse_raw_message(servBytes, dev.addr, dev.rssi)
                _LOGGER.info(result)

                self.worker.messages += status.generate_messages(result)
                _LOGGER.info(f"MQTT message backlog {len(self.worker.messages)}")

        super(XiaomipassiveWorker, self).__init__(*args, **kwargs)
        
        self.messages = []
        self.scanner = Scanner().withDelegate(ScanDelegate(self))
        _LOGGER.info("Adding %d %s devices", len(self.devices), repr(self))

        self.device_map = {
            kwargs['address'].lower() : XiaomiStatus(self, name, **kwargs) for name, kwargs in self.devices.items()
        }

        def obj0d10(xobj):
            (temp, humi) = TH_STRUCT.unpack(xobj)
            return {"temperature": temp / 10, "humidity": humi / 10}

        def obj0610(xobj):
            (humi,) = H_STRUCT.unpack(xobj)
            return {"humidity": humi / 10}

        def obj0410(xobj):
            (temp,) = T_STRUCT.unpack(xobj)
            return {"temperature": temp / 10}

        def obj0910(xobj):
            (cond,) = CND_STRUCT.unpack(xobj)
            return {"conductivity": cond}

        def obj1010(xobj):
            (fmdh,) = FMDH_STRUCT.unpack(xobj)
            return {"formaldehyde": fmdh / 100}

        def obj0a10(xobj):
            return {"battery": xobj[0]}

        def obj0810(xobj):
            return {"moisture": xobj[0]}

        def obj1210(xobj):
            return {"switch": xobj[0]}

        def obj1810(xobj):
            return {"light": xobj[0]}

        def obj1910(xobj):
            return {"opening": xobj[0]}

        def obj1310(xobj):
            return {"consumable": xobj[0]}

        def obj0710(xobj):
            (illum,) = ILL_STRUCT.unpack(xobj + b'\x00')
            return {"light": illum}

        def obj0510(xobj):
            return {"switch": xobj[0], "temperature": xobj[1]}

        # dataobject dictionary to implement switch-case statement
        # dataObject id  (converter, binary, measuring)
        self._dataobject_dict = {
            b'\x0D\x10': (obj0d10, False, True),
            b'\x06\x10': (obj0610, False, True),
            b'\x04\x10': (obj0410, False, True),
            b'\x09\x10': (obj0910, False, True),
            b'\x10\x10': (obj1010, False, True),
            b'\x0A\x10': (obj0a10, True, True),
            b'\x08\x10': (obj0810, False, True),
            b'\x12\x10': (obj1210, True, False),
            b'\x18\x10': (obj1810, True, False),
            b'\x19\x10': (obj1910, True, False),
            b'\x13\x10': (obj1310, False, True),
            b'\x07\x10': (obj0710, False, True),
            b'\x05\x10': (obj0510, True, True),
        }

    def status_update(self):
        from bluepy import btle

        _LOGGER.info("Updating %d %s devices", len(self.devices), repr(self))
        self.messages = []

        try:
            devices = self.scanner.scan(
                float(self.scan_timeout), passive=booleanize(self.scan_passive)
            )

        except btle.BTLEException as e:
            logger.log_exception(
                _LOGGER,
                "Error during update (%s)",
                repr(self),
                type(e).__name__,
                suppress=True,
            )
        
        _LOGGER.info(f"MQTT messages {self.messages}")
        return self.messages

    # https://github.com/custom-components/ble_monitor/blob/master/custom_components/ble_monitor/__init__.py
    def parse_raw_message(self, data, addr, rssi):
        """Parse the raw data."""
        # # check if packet is Extended scan result
        # is_ext_packet = True if data[3] == 0x0d else False
        is_ext_packet = False
        # check for Xiaomi service data
        xiaomi_index = data.find(b'\x16\x95\xFE', 15 + 15 if is_ext_packet else 0)
        if xiaomi_index == -1:
            return None, None, None
        # # check for no BR/EDR + LE General discoverable mode flags
        # advert_start = 29 if is_ext_packet else 14
        # adv_index = data.find(b"\x02\x01\x06", advert_start, 3 + advert_start)
        # adv_index2 = data.find(b"\x15\x16\x95", advert_start, 3 + advert_start)
        # if adv_index == -1 and adv_index2 == -1:
        #     return None, None, None
        # if adv_index2 != -1:
        #     adv_index = adv_index2
        # check for BTLE msg size
        msg_length = len(data)
        # msg_length = data[2] + 3
        # if msg_length != len(data):
        #     return None, None, None
        # check for MAC presence in message and in service data
        xiaomi_mac_reversed = data[xiaomi_index + 8:xiaomi_index + 14]
        # mac_index = adv_index - 14 if is_ext_packet else adv_index
        # source_mac_reversed = data[mac_index - 7:mac_index - 1]
        # TODO
        # if xiaomi_mac_reversed != source_mac_reversed:
        #     return None, None, None
        # check for MAC presence in whitelist, if needed
        # if self.discovery is False:
        #     if xiaomi_mac_reversed not in self.whitelist:
        #         return None, None, None
        packet_id = data[xiaomi_index + 7]
        # try:
        #     prev_packet = self.lpacket_ids[xiaomi_mac_reversed]
        # except KeyError:
        #     prev_packet = None, None, None
        # if prev_packet == packet_id:
        #     return None, None, None
        # self.lpacket_ids[xiaomi_mac_reversed] = packet_id
        # extract RSSI byte
        # rssi_index = 18 if is_ext_packet else msg_length - 1
        # (rssi,) = struct.unpack("<b", data[rssi_index:rssi_index + 1])
        # strange positive RSSI workaround
        # if rssi > 0:
        #     rssi = -rssi
        try:
            sensor_type, binary_data = XIAOMI_TYPE_DICT[
                data[xiaomi_index + 5:xiaomi_index + 7]
            ]
        except KeyError:
            _LOGGER.info(
                "BLE ADV from UNKNOWN: RSSI: %s, MAC: %s, ADV: %s",
                rssi,
                addr,
                data.hex()
            )
            return None, None, None
        # frame control bits
        framectrl, = struct.unpack('>H', data[xiaomi_index + 3:xiaomi_index + 5])
        # check data is present
        if not (framectrl & 0x4000):
            return {
                "rssi": rssi,
                "mac": addr,
                "type": sensor_type,
                "packet": packet_id,
                "data": False,
            }, None, None
            # return None
        xdata_length = 0
        xdata_point = 0
        # check capability byte present
        if framectrl & 0x2000:
            xdata_length = -1
            xdata_point = 1
        # xiaomi data length = message length
        #     -all bytes before XiaomiUUID
        #     -3 bytes Xiaomi UUID + ADtype
        #     -1 byte rssi
        #     -3+1 bytes sensor type
        #     -1 byte packet_id
        #     -6 bytes MAC
        #     - capability byte offset
        xdata_length += msg_length - xiaomi_index - 15
        if xdata_length < 3:
            return None, None, None
        xdata_point += xiaomi_index + 14
        # check if xiaomi data start and length is valid
        if xdata_length != len(data[xdata_point:-1]):
            return None, None, None
        # check encrypted data flags
        if framectrl & 0x0800:
            raise Exception ('Payload encrypted')
            # # try to find encryption key for current device
            # try:
            #     key = self.aeskeys[xiaomi_mac_reversed]
            # except KeyError:
            #     # no encryption key found
            #     return None, None, None
            # nonce = b"".join(
            #     [
            #         xiaomi_mac_reversed,
            #         data[xiaomi_index + 5:xiaomi_index + 7],
            #         data[xiaomi_index + 7:xiaomi_index + 8]
            #     ]
            # )
            # endoffset = msg_length - int(not is_ext_packet)
            # encrypted_payload = data[xdata_point:endoffset]
            # aad = b"\x11"
            # token = encrypted_payload[-4:]
            # payload_counter = encrypted_payload[-7:-4]
            # nonce = b"".join([nonce, payload_counter])
            # cipherpayload = encrypted_payload[:-7]
            # cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
            # cipher.update(aad)
            # decrypted_payload = None
            # try:
            #     decrypted_payload = cipher.decrypt_and_verify(cipherpayload, token)
            # except ValueError as error:
            #     _LOGGER.error("Decryption failed: %s", error)
            #     _LOGGER.error("token: %s", token.hex())
            #     _LOGGER.error("nonce: %s", nonce.hex())
            #     _LOGGER.error("encrypted_payload: %s", encrypted_payload.hex())
            #     _LOGGER.error("cipherpayload: %s", cipherpayload.hex())
            #     return None, None, None
            # if decrypted_payload is None:
            #     _LOGGER.error(
            #         "Decryption failed for %s, decrypted payload is None",
            #         "".join("{:02X}".format(x) for x in xiaomi_mac_reversed[::-1]),
            #     )
            #     return None, None, None
            # # replace cipher with decrypted data
            # msg_length -= len(encrypted_payload)
            # if is_ext_packet:
            #     data = b"".join((data[:xdata_point], decrypted_payload))
            # else:
            #     data = b"".join((data[:xdata_point], decrypted_payload, data[-1:]))
            # msg_length += len(decrypted_payload)
        result = {
            "rssi": rssi,
            "mac": addr,
            "type": sensor_type,
            "packet": packet_id,
            "data": True,
        }
        binary = False
        measuring = False
        # loop through xiaomi payload
        # assume that the data may have several values of different types,
        # although I did not notice this behavior with my LYWSDCGQ sensors
        while True:
            xvalue_typecode = data[xdata_point:xdata_point + 2]
            try:
                xvalue_length = data[xdata_point + 2]
            except ValueError as error:
                _LOGGER.error("xvalue_length conv. error: %s", error)
                _LOGGER.error("xdata_point: %s", xdata_point)
                _LOGGER.error("data: %s", data.hex())
                result = {}
                break
            except IndexError as error:
                _LOGGER.error("Wrong xdata_point: %s", error)
                _LOGGER.error("xdata_point: %s", xdata_point)
                _LOGGER.error("data: %s", data.hex())
                result = {}
                break
            xnext_point = xdata_point + 3 + xvalue_length
            xvalue = data[xdata_point + 3:xnext_point]
            resfunc, tbinary, tmeasuring = self._dataobject_dict.get(xvalue_typecode, (None, None, None))
            if resfunc:
                binary = binary or tbinary
                measuring = measuring or tmeasuring
                result.update(resfunc(xvalue))
            else:
                _LOGGER.info(
                    "UNKNOWN dataobject from DEVICE: %s, MAC: %s, ADV: %s",
                    sensor_type,
                    addr,
                    data.hex()
                )
            if xnext_point > msg_length - 3:
                break
            xdata_point = xnext_point
        binary = binary and binary_data
        return result, binary, measuring