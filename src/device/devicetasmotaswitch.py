import logging
import traceback
import event
import time
import paho.mqtt.client as paho

from device import Device
from util import b2s, init_logger
from action import (ActionStateon, ActionStateoff, ActionStatechange, ActionNotifystate)

_LOGGER = init_logger(__name__, level=logging.DEBUG)


class DeviceTasmotaswitch(Device):

    def __init__(self, mac='', root=None, name='', **kw):
        Device.__init__(self, ('', 0), mac, root, name)
        self.state = ""

    def copy_extra_from(self, already_saved_device):
        Device.copy_extra_from(self, already_saved_device)
        self.state = already_saved_device.state

    def mqtt_inner_topic(self, prefix, suffix):
        return str(prefix + '/tasmota_switch/' + self.name + "/" + suffix)

    def mqtt_publish_onfinish(self, action, retval):
        if isinstance(action, (ActionNotifystate)):
            return self.mqtt_power_state()
        else:
            return Device.mqtt_publish_onfinish(self, action, retval)

    def mqtt_subscribe_topics(self):
        topic = Device.mqtt_subscribe_topics(self)
        topic.append((self.mqtt_inner_topic("stat", "POWER"), 0,))
        return topic

    def mqtt_on_message(self, client, userdata, msg):
        Device.mqtt_on_message(self, client, userdata, msg)
        sub = self.mqtt_sub(msg.topic)
        try:
            if sub == "state":
                i = int(msg.payload)
                if i == 0 or (i == -1 and self.state == "1"):
                    event.EventManager.fire(eventname='ExtInsertAction', hp=(
                        self.host, self.port), cmdline="", action=ActionStateoff(self))
                elif i == 1 or (i == -1 and self.state == "0"):
                    event.EventManager.fire(eventname='ExtInsertAction', hp=(
                        self.host, self.port), cmdline="", action=ActionStateon(self))
            elif msg.topic == self.mqtt_inner_topic("stat", "POWER"):
                event.EventManager.fire(eventname='ExtChangeState', hp=self.host, mac=self.mac, newstate="1" if msg.payload == b"ON" else "0")
                _LOGGER.info(f"payload = {b2s(msg.payload)} state = {self.state}")
        except:  # noqa: E722
            _LOGGER.warning(f"{traceback.format_exc()}")

    def to_json(self):
        rv = Device.to_json(self)
        rv.update({'state': self.state})
        return rv

    def state_value_conv(self, s):
        return "1" if s != "0" else "0"

    @staticmethod
    def mqtt_on_connect_discovery(client, userdata, flags, rc):
        _LOGGER.info("mqtt_on_connect_discovery connected")
        client.subscribe([("tele/tasmota_switch/+/LWT", 0,)])

    @staticmethod
    def mqtt_on_message_discovery(client, devices, msg):
        topic = b2s(msg.topic)
        devname = topic[len("tele/tasmota_switch/"):-4]
        _LOGGER.info(f"Found {devname}")
        devices["tasmota_switch_" + devname] = DeviceTasmotaswitch(mac="tasmota_switch_" + devname, name=devname)

    @staticmethod
    def discovery(mqtt_hp, timeout=5, **kwargs):
        _LOGGER.info("searching for devices tasmotaswitch")
        devices = dict()
        client = paho.Client(userdata=devices, protocol=paho.MQTTv31)
        client.on_connect = DeviceTasmotaswitch.mqtt_on_connect_discovery
        client.on_message = DeviceTasmotaswitch.mqtt_on_message_discovery
        _LOGGER.info("mqtt_start (%s:%d)" % mqtt_hp)
        client.connect_async(mqtt_hp[0], port=mqtt_hp[1])
        client.loop_start()
        time.sleep(timeout)
        client.loop_stop()
        client.disconnect()
        return devices

    def get_action_payload(self, action):
        if isinstance(action, ActionStatechange):
            return self.state_value_conv(action.newstate)
        else:
            return Device.get_action_payload(self, action)

    def send_action(self, actionexec, action, state):
        if isinstance(action, ActionStatechange):
            if (self.state == '0' and action.newstate != '0') or (self.state == '1' and action.newstate == '0'):
                self.mqtt_publish_all([dict(topic=self.mqtt_inner_topic("cmnd", "POWER"), msg="TOGGLE", options=dict())])
                rv = 1
            else:
                rv = None
            return action.exec_handler(rv, None)
        else:
            return Device.send_action(self, actionexec, action, state)

    def mqtt_power_state(self):
        return [dict(topic=self.mqtt_topic("stat", "power"), msg="-1" if self.state != "0" and self.state != "1" else str(self.state), options=dict(retain=True))]

    def mqtt_on_subscribe(self, client, userdata, mid, granted_qos):
        Device.mqtt_on_subscribe(self, client, userdata, mid, granted_qos)
        self.mqtt_publish_all([dict(topic=self.mqtt_inner_topic("cmnd", "POWER"), msg="", options=dict())])

    def process_asynch_state_change(self, state):
        self.state = b2s(state)
