""" A module for interacting with Bluetooth LE devices which support the Radar (RDR) service

Jason Sohn 2022

This service is tested on Garmin Varia RVR315.
Other models which are expected to support RDR service are:

* Garmin RTR515, RTR516 (German market version), and RCT715
* Bryton Gardia R300
* Magene L508

Example
=======
This example prints radar information broadcast from the Bluetooth device to the console. Please see also
information on :ref:`obtaining the Bluetooth address of your device <obtaining_device_address>`.

.. literalinclude:: ../examples/rear_view_radar_example.py
"""

from abc import ABC, abstractmethod
from collections import namedtuple

import struct

RadarMeasurement = namedtuple('RadarMeasurement', [
    'threat_id',
    'level',
    'speed',
    'distance',
])

class BaseRadar(ABC):
    @abstractmethod
    async def enable_radar_measurement_notifications(self):
        pass

    @abstractmethod
    async def disable_radar_measurement_notifications(self):
        pass

    @abstractmethod
    def _parse_radar_measurement(self, data: bytearray):
        pass

    @abstractmethod
    def set_radar_measurement_handler(self, callback):
        pass


class BrytonGardiaRadar(BaseRadar):
    RADAR_CHARACTERISTIC_ID = "f3641401-00b0-4240-ba50-05ca45bf8abc"

    def __init__(self, client):
        self._client = client
        self._radar_measurement_callback = None
    
    async def enable_radar_measurement_notifications(self):
        await self._client.start_notify(self.RADAR_CHARACTERISTIC_ID, self._radar_measurement_notification_handler)
    
    async def disable_radar_measurement_notifications(self):
        await self._client.stop_notify(self.RADAR_CHARACTERISTIC_ID)

    def set_radar_measurement_handler(self, callback):
        self._radar_measurement_callback = callback

    def _radar_measurement_notification_handler(self, sender, data): # pylint: disable=unused-argument
        if self._radar_measurement_callback is not None:
            self._radar_measurement_callback(self._parse_radar_measurement(data))
    
    def _parse_radar_measurement(self, data: bytearray):
        radar_measurements = []

        page, threat_level, threat_side, tmp_threat_distance_1, tmp_threat_distance_2, tmp_threat_distance_3, threat_speed_1, threat_speed_2 = struct.unpack_from("BBB3BBB", data)

        threat_1_level = (threat_level & 3)
        threat_2_level = (threat_level >> 2) & 3
        threat_3_level = (threat_level >> 4) & 3
        threat_4_level = (threat_level >> 6) & 3

        print(threat_1_level, threat_2_level, threat_3_level, threat_4_level)

        threat_1_distance = (tmp_threat_distance_1 >> 0) & 63
        threat_2_distance = ((tmp_threat_distance_1 >> 6) & 3) | (((tmp_threat_distance_2 >> 0) & 15) << 2)
        threat_3_distance = ((tmp_threat_distance_2 >> 4) & 15) | (((tmp_threat_distance_3 >> 0) & 3) << 4)
        threat_4_distance = (tmp_threat_distance_3 >> 2) & 63

        print(threat_1_distance * 3.125, threat_2_distance * 3.125, threat_3_distance * 3.125, threat_4_distance * 3.125)

        threat_1_speed = (threat_speed_1 >> 0) & 15
        threat_2_speed = (threat_speed_1 >> 4) & 15
        threat_3_speed = (threat_speed_2 >> 0) & 15
        threat_4_speed = (threat_speed_2 >> 4) & 15

        print(threat_1_speed * 3.04 * 3.6, threat_2_speed * 3.04 * 3.6, threat_3_speed * 3.04 * 3.6, threat_4_speed * 3.04 * 3.6)

        if threat_1_level > 0:
            radar_measurements.append(RadarMeasurement(None, threat_1_level, threat_1_speed, threat_1_distance))

        if threat_2_level > 0:
            radar_measurements.append(RadarMeasurement(None, threat_2_level, threat_2_speed, threat_2_distance))

        return radar_measurements


class GarminVariaRadar(BaseRadar):
    RADAR_CHARACTERISTIC_ID = "6a4e3203-667b-11e3-949a-0800200c9a66"

    def __init__(self, client):
        self._client = client
        self._radar_measurement_callback = None
    
    async def enable_radar_measurement_notifications(self):
        await self._client.start_notify(self.RADAR_CHARACTERISTIC_ID, self._radar_measurement_notification_handler)
    
    async def disable_radar_measurement_notifications(self):
        await self._client.stop_notify(self.RADAR_CHARACTERISTIC_ID)

    def set_radar_measurement_handler(self, callback):
        self._radar_measurement_callback = callback

    def _radar_measurement_notification_handler(self, sender, data): # pylint: disable=unused-argument
        if self._radar_measurement_callback is not None:
            self._radar_measurement_callback(self._parse_radar_measurement(data))

    def _parse_radar_measurement(data: bytearray) -> RadarMeasurement:
        """
        Characteristic payload in bytes: 1+3i where i is number of threats (cars)

        byte 0: probably some kind of packet identifier (can be used in case of multiple packets)
        byte 1: threat identifier
        byte 2 (5, 8, ...): distance to threat in meters
        byte 3 (6, 9, ...): speed of threat in km/h

        See source for this reverse-engineering in repo README
        """
        radar_measurements = []
        try:
            for i in range(1, len(data), 3):
                threat_id = int(data[i])
                distance = int(data[i+1])
                speed = int(data[i+2])
                radar_measurements.append(RadarMeasurement(threat_id, speed, distance))
        except IndexError:
            print('pycycling:rear_view_radar.py IndexError: probably starting up and not all data is available yet')
            return None
        return radar_measurements


class RearViewRadarService:
    def __init__(self, client, radar: BaseRadar = GarminVariaRadar):
        self._radar = radar(client)

    async def enable_radar_measurement_notifications(self):
        await self._radar.enable_radar_measurement_notifications()

    async def disable_radar_measurement_notifications(self):
        await self._radar.disable_radar_measurement_notifications()

    def set_radar_measurement_handler(self, callback):
        self._radar.set_radar_measurement_handler(callback)
