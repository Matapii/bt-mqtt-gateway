from const import DEFAULT_PER_DEVICE_TIMEOUT
from exceptions import DeviceTimeoutError
from mqtt import MqttMessage, MqttConfigMessage

from interruptingcow import timeout
from workers.base import BaseWorker, retry
import logger

REQUIREMENTS = [
    "bluepy",
    "miflora",
]

ATTR_BATTERY = "battery"
ATTR_LOW_BATTERY = 'low_battery'

monitoredAttrs = ["temperature", "moisture", "light", "conductivity", ATTR_BATTERY]
_LOGGER = logger.get(__name__)


class MifloraWorker(BaseWorker):
    per_device_timeout = DEFAULT_PER_DEVICE_TIMEOUT  # type: int
    low_battery_sensor = True

    def _setup(self):
        from miflora.miflora_poller import MiFloraPoller
        from btlewrap.bluepy import BluepyBackend

        _LOGGER.info("Adding %d %s devices", len(self.devices), repr(self))
        for name, mac in self.devices.items():
            _LOGGER.debug("Adding %s device '%s' (%s)", repr(self), name, mac)
            self.devices[name] = {
                "mac": mac,
                "poller": MiFloraPoller(
                    mac, BluepyBackend, adapter=getattr(self, 'adapter', 'hci0')),
            }

    def format_friendly_name(self, name):
        return name.replace('_', ' ').title()

    def config(self, availability_topic):
        ret = []
        for name, data in self.devices.items():
            ret += self.config_device(name, data["mac"])
        return ret

    def config_device(self, name, mac):
        ret = []
        device = {
            "identifiers": [mac, self.format_discovery_id(mac, name)],
            "manufacturer": "Xiaomi",
            "model": "MiFlora",
            "name": self.format_friendly_name(self.format_discovery_name(name)),
        }

        for attr in (monitoredAttrs + ['rssi']):
            payload = {
                "unique_id": self.format_discovery_id(mac, name, attr),
                "state_topic": self.format_prefixed_topic(name, attr),
                "name": self.format_friendly_name(attr),
                "device": device,
            }

            if attr == "light":
                payload.update(
                    {
                        "unique_id": self.format_discovery_id(mac, name, "illuminance"),
                        "device_class": "illuminance",
                        "unit_of_measurement": "lx",
                    }
                )
            elif attr == "moisture":
                payload.update({"icon": "mdi:water", "unit_of_measurement": "%"})
            elif attr == "conductivity":
                payload.update({"icon": "mdi:leaf", "unit_of_measurement": "µS/cm"})
            elif attr == "temperature":
                payload.update(
                    {"device_class": "temperature", "unit_of_measurement": "°C"}
                )
            elif attr == ATTR_BATTERY:
                payload.update({"device_class": "battery", "unit_of_measurement": "%"})
            elif attr == "rssi":
                payload.update({"device_class": "signal_strength", "unit_of_measurement": "dB"})

            ret.append(
                MqttConfigMessage(
                    MqttConfigMessage.SENSOR,
                    self.format_discovery_topic(mac, name, attr),
                    payload=payload,
                )
            )

        if self.low_battery_sensor:
            ret.append(
                MqttConfigMessage(
                    MqttConfigMessage.BINARY_SENSOR,
                    self.format_discovery_topic(mac, name, ATTR_LOW_BATTERY),
                    payload={
                        "unique_id": self.format_discovery_id(mac, name, ATTR_LOW_BATTERY),
                        "state_topic": self.format_prefixed_topic(name, ATTR_LOW_BATTERY),
                        "name": self.format_discovery_name(name, ATTR_LOW_BATTERY),
                        "device": device,
                        "device_class": "battery",
                    },
                )
            )

        return ret

    def status_update(self):
        _LOGGER.info("Updating %d %s devices", len(self.devices), repr(self))

        for name, data in self.devices.items():
            _LOGGER.debug("Updating %s device '%s' (%s)", repr(self), name, data["mac"])
            from btlewrap import BluetoothBackendException

            try:
                with timeout(self.per_device_timeout, exception=DeviceTimeoutError):
                    yield retry(self.update_device_state, retries=self.update_retries, exception_type=BluetoothBackendException)(name, data["poller"])
            except BluetoothBackendException as e:
                logger.log_exception(
                    _LOGGER,
                    "Error during update of %s device '%s' (%s): %s",
                    repr(self),
                    name,
                    data["mac"],
                    type(e).__name__,
                    suppress=True,
                )
            except DeviceTimeoutError:
                logger.log_exception(
                    _LOGGER,
                    "Time out during update of %s device '%s' (%s)",
                    repr(self),
                    name,
                    data["mac"],
                    suppress=True,
                )

    def update_device_state(self, name, poller):
        ret = []
        poller.clear_cache()
        for attr in monitoredAttrs:
            payload = poller.parameter_value(attr)

            # We sometimes see light values of over 400 million. This
            # probably comes from a sensor error or maybe the miflora
            # library not understanding the protocol completely.
            #
            # In any case, direct sunlight is up to 100 thousand lux,
            # so anything above that is suspicious. Lets cap our value
            # at 1 million lux, an order of magnitude more than we ever
            # expect.
            if (attr == "light") and (payload > 1_000_000):
                continue

            ret.append(
                MqttMessage(
                    topic=self.format_topic(name, attr),
                    payload=payload,
                )
            )

        # Low battery binary sensor
        if self.low_battery_sensor:
            ret.append(
                MqttMessage(
                    topic=self.format_topic(name, ATTR_LOW_BATTERY),
                    payload=self.true_false_to_ha_on_off(poller.parameter_value(ATTR_BATTERY) < 10),
                )
            )

        return ret
