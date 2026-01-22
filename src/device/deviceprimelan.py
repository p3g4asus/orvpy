import json
import logging
import struct
import sys
import time
import traceback
from typing import Dict, Optional
from xml.dom import minidom

import requests

import event
from action import ActionNotifystate, ActionStatechange
from Crypto.Cipher import AES
from device import Device
from transport import TCPClient
from util import b2s, init_logger, s2b, tohexs

if sys.version_info >= (3, 0):
    from functools import reduce


_LOGGER = init_logger(__name__, level=logging.DEBUG)


class CacheElement(object):
    def __init__(self, num: int, typeel: int, state0: Optional[int] = None, state1: Optional[int] = None) -> None:
        self.num = num
        self.type = typeel
        self.update(state0, state1)

    def update(self, state0: Optional[int] = None, state1: Optional[int] = None) -> None:
        self.state0 = state0
        self.state1 = state1
        if self.state0 is not None:
            self.time = time.time()
        else:
            self.time = 0

    def age(self) -> float:
        return time.time() - self.time


class DevicePrimelan(Device):
    # 0: doppio pulsante
    # 2: On off slider
    # 1: slider 0-100
    TIMEOUT = 7
    STATE_CACHE: Dict[str, Dict[int, CacheElement]] = dict()

    def process_asynch_state_change(self, state, device_connected=None):
        self.last_get = time.time()
        _LOGGER.info(f"{id(self)} {self.name} last_get = {self.last_get}")
        if self.state != state:
            self.oldstate = self.state
            self.state = state

    def state_value_conv(self, s):
        try:
            realv = int(s)
        except:  # noqa: E722
            realv = 0
        if realv == 0:
            return "0"
        elif realv >= 1000:
            if self.subtype == 1:
                try:
                    ost = int(self.oldstate)
                except:  # noqa: E722
                    ost = 0
                try:
                    st = int(self.state)
                except:  # noqa: E722
                    st = 0
                if st:
                    return str(st)
                elif ost:
                    return str(ost)
                else:
                    return "50"
            else:
                return "1"
        else:
            return s

    def do_presend_operations(self, action, actionexec):
        if isinstance(action, ActionStatechange) and action.newstate != DevicePrimelan.GET_STATE_ACTION and time.time() - self.last_get > 10:
            actionexec.insert_action(ActionStatechange(
                self, DevicePrimelan.GET_STATE_ACTION), 0)
            return 0
        else:
            return Device.do_presend_operations(self, action, actionexec)

    def do_postsend_operations(self, action, actionexec):
        if isinstance(action, ActionStatechange) and action.newstate != DevicePrimelan.GET_STATE_ACTION:
            actionexec.insert_action(ActionStatechange(
                self, DevicePrimelan.GET_STATE_ACTION), 1)
        else:
            Device.do_postsend_operations(self, action, actionexec)

    def mqtt_publish_onstart(self):
        out = {
            'subtype': self.subtype,
            'nick': self.nick,
            'state': self.state,
            'oldstate': self.oldstate}
        lst = [dict(topic=self.mqtt_topic("stat", "device"), msg=json.dumps(out), options=dict(retain=True))]
        if self.homeassistant:
            cmd = None
            if self.subtype == 1:
                topic = f'{self.homeassistant}/light/{self.name}/config'
                cmd = dict(
                    availability_topic=f'stat/{self.__class__.__name__[6:].lower()}/{self.name}/device',
                    availability_template='{{ "online" if (value_json.state | int) >= 0 else "offline" }}',
                    brightness_state_topic=f'stat/{self.__class__.__name__[6:].lower()}/{self.name}/device',
                    state_topic=f'stat/{self.__class__.__name__[6:].lower()}/{self.name}/device',
                    command_topic=f'cmnd/{self.__class__.__name__[6:].lower()}/{self.name}/state',
                    brightness_command_topic=f'cmnd/{self.__class__.__name__[6:].lower()}/{self.name}/state',
                    brightness_value_template='{{value_json.state | int}}',
                    brightness_command_template='{{value}}',
                    brightness_scale=100,
                    on_command_type='brightness',
                    payload_not_available='-1',
                    payload_off='0',
                    payload_on='1000',
                    name=self.name,
                    unique_id=tohexs(self.mac),
                    state_value_template='{{ "1000" if (value_json.state | int) > 0 else "0" }}'
                )
            elif self.subtype == 0:
                topic = f'{self.homeassistant}/switch/{self.name}/config'
                cmd = dict(
                    availability_topic=f'stat/{self.__class__.__name__[6:].lower()}/{self.name}/device',
                    availability_template='{{ "online" if (value_json.state | int) >= 0 else "offline" }}',
                    command_topic=f'cmnd/{self.__class__.__name__[6:].lower()}/{self.name}/state',
                    state_topic=f'stat/{self.__class__.__name__[6:].lower()}/{self.name}/device',
                    payload_off='0',
                    payload_on='1',
                    state_off='0',
                    state_on='1',
                    unique_id=tohexs(self.mac),
                    value_template='{{ "1" if (value_json.state | int) > 0 else "0" }}',
                    name=self.name
                )
            elif self.subtype == 2:
                topic = f'{self.homeassistant}/light/{self.name}/config'
                cmd = dict(
                    availability_topic=f'stat/{self.__class__.__name__[6:].lower()}/{self.name}/device',
                    command_topic=f'cmnd/{self.__class__.__name__[6:].lower()}/{self.name}/state',
                    state_topic=f'stat/{self.__class__.__name__[6:].lower()}/{self.name}/device',
                    availability_template='{{ "online" if (value_json.state | int) >= 0 else "offline" }}',
                    payload_off='0',
                    payload_on='1',
                    name=self.name,
                    unique_id=tohexs(self.mac),
                    state_value_template='{{ "1" if (value_json.state | int) > 0 else "0" }}'
                )
            if cmd:
                lst.append(dict(topic=topic, msg=json.dumps(cmd), options=dict(retain=True)))
        return lst

    def mqtt_on_message(self, client, userdata, msg):
        Device.mqtt_on_message(self, client, userdata, msg)
        sub = self.mqtt_sub(msg.topic)
        try:
            if sub == "state":
                event.EventManager.fire(eventname='ExtInsertAction', hp=(
                    self.host, self.port), cmdline="", action=ActionStatechange(self, b2s(msg.payload)))
        except:  # noqa: E722
            _LOGGER.warning(f"{traceback.format_exc()}")

    def mqtt_publish_onfinish(self, action, retval):
        if isinstance(action, ActionNotifystate) or\
            (isinstance(action, ActionStatechange) and
             action.newstate == DevicePrimelan.GET_STATE_ACTION):
            return self.mqtt_publish_onstart()
        else:
            return Device.mqtt_publish_onfinish(self, action, retval)

    def get_action_payload(self, action):
        if isinstance(action, ActionStatechange):
            return self.state_value_conv(action.newstate)
        else:
            return Device.get_action_payload(self, action)

    crc16_table = [
        0x0000, 0xc0c1, 0xc181, 0x0140, 0xc301, 0x03c0, 0x0280, 0xc241,
        0xc601, 0x06c0, 0x0780, 0xc741, 0x0500, 0xc5c1, 0xc481, 0x0440,
        0xcc01, 0x0cc0, 0x0d80, 0xcd41, 0x0f00, 0xcfc1, 0xce81, 0x0e40,
        0x0a00, 0xcac1, 0xcb81, 0x0b40, 0xc901, 0x09c0, 0x0880, 0xc841,
        0xd801, 0x18c0, 0x1980, 0xd941, 0x1b00, 0xdbc1, 0xda81, 0x1a40,
        0x1e00, 0xdec1, 0xdf81, 0x1f40, 0xdd01, 0x1dc0, 0x1c80, 0xdc41,
        0x1400, 0xd4c1, 0xd581, 0x1540, 0xd701, 0x17c0, 0x1680, 0xd641,
        0xd201, 0x12c0, 0x1380, 0xd341, 0x1100, 0xd1c1, 0xd081, 0x1040,
        0xf001, 0x30c0, 0x3180, 0xf141, 0x3300, 0xf3c1, 0xf281, 0x3240,
        0x3600, 0xf6c1, 0xf781, 0x3740, 0xf501, 0x35c0, 0x3480, 0xf441,
        0x3c00, 0xfcc1, 0xfd81, 0x3d40, 0xff01, 0x3fc0, 0x3e80, 0xfe41,
        0xfa01, 0x3ac0, 0x3b80, 0xfb41, 0x3900, 0xf9c1, 0xf881, 0x3840,
        0x2800, 0xe8c1, 0xe981, 0x2940, 0xEB01, 0x2bc0, 0x2a80, 0xea41,
        0xee01, 0x2ec0, 0x2f80, 0xef41, 0x2d00, 0xedc1, 0xec81, 0x2c40,
        0xe401, 0x24c0, 0x2580, 0xe541, 0x2700, 0xe7c1, 0xe681, 0x2640,
        0x2200, 0xe2c1, 0xe381, 0x2340, 0xe101, 0x21c0, 0x2080, 0xe041,
        0xa001, 0x60c0, 0x6180, 0xa141, 0x6300, 0xa3c1, 0xa281, 0x6240,
        0x6600, 0xa6c1, 0xa781, 0x6740, 0xa501, 0x65c0, 0x6480, 0xa441,
        0x6c00, 0xacc1, 0xad81, 0x6d40, 0xaf01, 0x6fc0, 0x6e80, 0xae41,
        0xaa01, 0x6ac0, 0x6b80, 0xab41, 0x6900, 0xa9c1, 0xa881, 0x6840,
        0x7800, 0xb8c1, 0xb981, 0x7940, 0xbb01, 0x7bc0, 0x7a80, 0xba41,
        0xbe01, 0x7ec0, 0x7f80, 0xbf41, 0x7d00, 0xbdc1, 0xbc81, 0x7c40,
        0xb401, 0x74c0, 0x7580, 0xb541, 0x7700, 0xb7c1, 0xb681, 0x7640,
        0x7200, 0xb2c1, 0xb381, 0x7340, 0xb101, 0x71c0, 0x7080, 0xb041,
        0x5000, 0x90c1, 0x9181, 0x5140, 0x9301, 0x53c0, 0x5280, 0x9241,
        0x9601, 0x56c0, 0x5780, 0x9741, 0x5500, 0x95c1, 0x9481, 0x5440,
        0x9c01, 0x5cc0, 0x5d80, 0x9d41, 0x5f00, 0x9fc1, 0x9e81, 0x5e40,
        0x5a00, 0x9ac1, 0x9b81, 0x5b40, 0x9901, 0x59c0, 0x5880, 0x9841,
        0x8801, 0x48c0, 0x4980, 0x8941, 0x4b00, 0x8bc1, 0x8a81, 0x4a40,
        0x4e00, 0x8ec1, 0x8f81, 0x4f40, 0x8d01, 0x4dc0, 0x4c80, 0x8c41,
        0x4400, 0x84c1, 0x8581, 0x4540, 0x8701, 0x47c0, 0x4680, 0x8641,
        0x8201, 0x42c0, 0x4380, 0x8341, 0x4100, 0x81c1, 0x8081, 0x4040
    ]

    @staticmethod
    def crc16(ba):
        return reduce(lambda x, y: ((x >> 8) & 0xff) ^ DevicePrimelan.crc16_table[(x ^ y) & 0xff], ba, 0)

    @staticmethod
    def tcp_type_to_subtype(typev):
        if typev == 0x01:
            return 0
        elif typev == 0x05:
            return 1
        elif typev == 0x06:
            return 2
        else:
            return 0

    @staticmethod
    def discovery_tcp(hp, passw, codu, port2, timeout=10):
        startidx = 0
        oldstartidx = startidx
        n = 20
        maxidx = 245
        out = {}
        key = DevicePrimelan.key_from_passw(passw)
        iv = DevicePrimelan.iv_from_key(key)
        t = TCPClient(timeout)
        while startidx < maxidx:
            try:
                oldstartidx = startidx
                n2 = n if startidx + n <= maxidx else maxidx - startidx
                byvals = DevicePrimelan.pkt_state_get_c(startidx, n2, key, iv)
                _LOGGER.info(f'Get state for id {startidx} -> {byvals.hex()}')
                if (rv := t.send_packet((hp[0], port2), byvals)) and (decrypted := DevicePrimelan.pkt_state_get_process_response(rv, key, iv)):
                    start = 18
                    while start < len(decrypted):
                        typeel = decrypted[start]
                        state0 = state1 = None
                        if typeel == 0x01 or typeel == 0x06:
                            state0 = int(decrypted[start + 1])
                            _LOGGER.info(f'Device {startidx} state: {state0}')
                        elif typeel == 0x05:
                            state0 = int(decrypted[start + 1])
                            state1 = int(decrypted[start + 2])
                            _LOGGER.info(f'Device {startidx} state: {state1}/{state0}')
                        if state0 is not None:
                            idv = f'{startidx}'
                            name = f'{hp[0]}_{idv}_{"switch" if typeel == 0x01 else "power_controlled_dimmer" if typeel == 0x05 else "power_controlled_switch"}'
                            _LOGGER.info(f'TCP Discovered device id {idv} name {name} type {typeel} state {state0}/{state1}')
                            dev = DevicePrimelan(
                                hp=hp,
                                mac=DevicePrimelan.generate_mac(hp[0], idv),
                                name=name,
                                idv=idv,
                                typev=DevicePrimelan.tcp_type_to_subtype(typeel),
                                tk=idv,
                                qindex=f'{idv}',
                                state=DevicePrimelan.states_to_real_state(state0, state1),
                                passw=passw,
                                port2=port2)
                            out['{}:{}'.format(*hp) + ':' + idv] = dev
                        start += 10
                        startidx += 1
            except Exception:  # noqa: E722
                startidx = oldstartidx + n
                _LOGGER.warning(f"Discovery error: {traceback.format_exc()}")
        return out

    @staticmethod
    def discovery(hp, passw, codu, port2, timeout=10):
        return DevicePrimelan.discovery_tcp(hp, passw, codu, port2, timeout)

    @staticmethod
    def discovery_http(hp, passw, codu, port2, timeout=10):
        try:
            r = requests.post('http://{}:{}/cgi-bin/web.cgi'.format(*hp),
                              data={'pass': passw, 'code': codu, 'mod': 'auth'}, timeout=timeout)
            txt = r.content.decode('utf-8')
            doc = minidom.parseString(txt)
            divs = doc.getElementsByTagName('div')
            tk = ''
            qindex = ''
            for div in divs:
                tk = div.attributes['tk'].value
                qindex = div.attributes['qindex'].value
            _LOGGER.info('received ' + txt + " tk = " +
                         tk + " qindex = " + qindex)
            r = requests.post('http://{}:{}/cgi-bin/web.cgi'.format(*hp),
                              data={'tk': tk, 'qindex': qindex, 'mod': 'cmd'}, timeout=timeout)
            lst = r.json()['cmd']
            out = {}
            _LOGGER.info(lst)
            for d in lst:
                idv = d['id']
                dev = DevicePrimelan(
                    hp=hp,
                    mac=DevicePrimelan.generate_mac(hp[0], idv),
                    name=d['lb'],
                    idv=idv,
                    typev=d['t'],
                    tk=tk,
                    qindex=qindex,
                    state=DevicePrimelan.http_state_to_real_state(d),
                    passw=passw,
                    port2=port2)
                out['{}:{}'.format(*hp) + ':' + idv] = dev
            return out
        except:  # noqa: E722
            _LOGGER.warning(f"{traceback.format_exc()}")
            return {}

    @staticmethod
    def generate_name_nick(nick):
        nick = nick.strip().lower()
        name = nick.replace(' ', '_')
        return (name, nick)

    @staticmethod
    def generate_mac(ip, idv):
        lst = ip.split('.')
        id2 = int(idv)
        lst.append((id2 >> 8) & 0xFF)
        lst.append(id2 & 0xFF)
        o = []
        for x in lst:
            try:
                o.append(chr(int(x)))
            except Exception:
                o.extend([s for s in x])
        return ''.join(o)

    @staticmethod
    def pad(byte_array: bytearray, byte_count: int = 16):
        """
        pkcs5 padding
        """
        pad_len = byte_count - len(byte_array) % byte_count
        return byte_array + (bytes([pad_len]) * pad_len)

    @staticmethod
    def unpad(s: bytearray):
        return s[0:-s[-1]]

    def invalidate_cache_element(self):
        key = f'{self.host}:{self.port2}'
        subkey = int(self.id)
        if key in DevicePrimelan.STATE_CACHE and subkey in (cacheel := DevicePrimelan.STATE_CACHE[key]):
            del cacheel[subkey]

    def get_cache_element(self, max_age: Optional[float] = None) -> Optional[CacheElement]:
        key = f'{self.host}:{self.port2}'
        subkey = int(self.id)
        if key in DevicePrimelan.STATE_CACHE and subkey in (cacheel := DevicePrimelan.STATE_CACHE[key]):
            if not max_age or (chs := cacheel[subkey]).age() < max_age:
                return chs
            else:
                del cacheel[subkey]
                return None
        else:
            return None

    def pkt_state_set(self, newstate):
        pre = b'\x50\x53\x00\x00\x1a\x00\x00\x00\x2a\x00\x00\x00\x50\x50'
        out = b'\x01\x00\x1a\x00\x00\x00'
        onoff = 0xAE40
        aesc = b'\x08\x00\x00\x00\x69\x00\x00\x00' + struct.pack("<H", onoff) + struct.pack(
            "<B", int(self.id)) + b'\x00' + struct.pack("<B", int(newstate)) + b'\x00'
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        aesc2 = cipher.encrypt(DevicePrimelan.pad(aesc))
        crc = DevicePrimelan.crc16(bytearray(out + aesc2))
        return pre + struct.pack("<H", crc) + out + aesc2

    @staticmethod
    def pkt_state_get_c(startidx: int, n: int, key: bytes, iv: bytes) -> bytes:
        pre = b'\x50\x53\x00\x00\x1a\x00\x00\x00\xea\x00\x00\x00\x50\x50'
        out = b'\x01\x00\x1a\x00\x00\x00'
        aesc = b'\x07\x00\x00\x00\x69\x00\x00\x00\x40\x01' + struct.pack("<B", startidx) + b'\x00' + struct.pack("<B", startidx + n) + b'\x00'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        aesc2 = cipher.encrypt(DevicePrimelan.pad(aesc))
        crc = DevicePrimelan.crc16(bytearray(out + aesc2))
        return pre + struct.pack("<H", crc) + out + aesc2

    @staticmethod
    def pkt_state_get_process_response(rv: bytes, key: bytes, iv: bytes) -> Optional[bytes]:
        if rv and rv[0] == 0x50 and rv[1] == 0x53 and rv[12] == 0x50 and rv[13] == 0x50 and rv[4] == 0xEA and rv[8] == 0xEA and rv[18] == 0xEA and rv[16] == 0x01:
            crc = DevicePrimelan.crc16(bytearray(rv[16:]))
            if crc == struct.unpack("<H", rv[14:16])[0]:
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted = DevicePrimelan.unpad(cipher.decrypt(rv[22:]))
                _LOGGER.info(f"Decry: {decrypted.hex()}")
                return decrypted
        return None

    def pkt_state_get(self, n: int = 1) -> bytes:
        return DevicePrimelan.pkt_state_get_c((int(self.id) // n) * n, n, self.key, self.iv)

    def pkt_state_get_parse(self, rv: bytes, startidx: int) -> Optional[CacheElement]:
        exitv = None
        if (decrypted := DevicePrimelan.pkt_state_get_process_response(rv, self.key, self.iv)):
            start = 18
            while start < len(decrypted):
                typeel = decrypted[start]
                state0 = state1 = None
                if typeel == 0x01 or typeel == 0x06:
                    state0 = int(decrypted[start + 1])
                    _LOGGER.info(f'Device {startidx} state: {state0}')
                elif typeel == 0x05:
                    state0 = int(decrypted[start + 1])
                    state1 = int(decrypted[start + 2])
                    _LOGGER.info(f'Device {startidx} state: {state1}/{state0}')
                if state0 is not None:
                    key = f'{self.host}:{self.port2}'
                    cacheel = DevicePrimelan.STATE_CACHE.get(key, dict())
                    DevicePrimelan.STATE_CACHE[key] = cacheel
                    if startidx in cacheel:
                        cacheel[startidx].update(state0, state1)
                    else:
                        cacheel[startidx] = CacheElement(startidx, typeel, state0, state1)
                    _LOGGER.info(f'State of {startidx} is {state0}/{state1}: start is {start}[{len(decrypted)}]')
                    if startidx == int(self.id):
                        exitv = cacheel[startidx]
                    else:
                        event.EventManager.fire(
                            eventname='ExtChangeState',
                            hp=(self.host, self.port),
                            mac=s2b(DevicePrimelan.generate_mac(self.host, startidx)),
                            newstate=DevicePrimelan.cache_state_to_real_state(cacheel[startidx]))
                start += 10
                startidx += 1
        return exitv

    def change_state_http(self, pay, timeout):
        r = requests.post('http://{}:{}/cgi-bin/web.cgi'.format(self.host, self.port),
                          data={'tk': self.tk, 'qindex': self.qindex, 'mod': 'do_cmd', 'par': self.id, 'act': pay}, timeout=timeout)
        return 1 if r.status_code == 200 else r.status_code

    @staticmethod
    def states_to_real_state(state0: int, state1: int) -> str:
        if state1 is None:
            return '1' if state0 else '0'
        elif state1:
            return f'{state0}'
        else:
            return '0'

    @staticmethod
    def cache_state_to_real_state(ce: Optional[CacheElement]) -> str:
        if ce:
            DevicePrimelan.states_to_real_state(ce.state0, ce.state1)
        else:
            return None

    @staticmethod
    def http_state_to_real_state(d):
        return d['st'] if d['t'] != "1" or int(d['p']) > 0 else '0'

    def get_state_http(self, timeout):
        now = time.time()
        if now - self.last_get > 10:
            r = requests.post('http://{}:{}/cgi-bin/web.cgi'.format(self.host, self.port),
                              data={'tk': self.tk, 'qindex': self.qindex, 'mod': 'cmd'}, timeout=timeout)
            lst = r.json()['cmd']
            _LOGGER.info(
                f'Get state (difftime = {now - self.last_get}) rv = {lst}')
            rv = None
            self.last_get = now
            for d in lst:
                idv = d['id']
                if idv == str(self.id):
                    rv = DevicePrimelan.http_state_to_real_state(d)
                else:
                    event.EventManager.fire(
                        eventname='ExtChangeState',
                        hp=(self.host, self.port),
                        mac=s2b(DevicePrimelan.generate_mac(self.host, idv)),
                        newstate=DevicePrimelan.http_state_to_real_state(d))
        else:
            rv = self.state
        return rv

    def get_state_tcp(self, timeout):
        if not (ce := self.get_cache_element(10)):
            t = TCPClient(timeout)
            idi = int(self.id)
            byvals = self.pkt_state_get(20)
            _LOGGER.info(f'Get state for id {self.id} -> {byvals.hex()}')
            if (rv := t.send_packet((self.host, self.port2), byvals)) and (ce := self.pkt_state_get_parse(rv, (idi // 20) * 20)):
                self.last_get = time.time()
        return DevicePrimelan.cache_state_to_real_state(ce)

    def change_state_tcp(self, state, timeout):
        t = TCPClient(timeout)
        byvals = self.pkt_state_set(state)
        _LOGGER.info(f'Set state for id {self.id} -> {byvals.hex()}')
        if t.send_packet((self.host, self.port2), byvals):
            self.invalidate_cache_element()
            return 1
        else:
            return None

    @staticmethod
    def key_from_passw(passw: str) -> bytes:
        return s2b(passw) + (b'\x00' * (16 - len(passw)))

    @staticmethod
    def iv_from_key(key: bytes) -> bytes:
        return reduce(lambda x, y: x + struct.pack("<B", y[1] ^ y[0]), enumerate(key), b'')

    def __init__(self, hp=('', 0), mac='', root=None, name='', idv=0, typev=0, tk='', qindex=0, passw='', port2=6004, state=0):
        nn = DevicePrimelan.generate_name_nick(name)
        nick = nn[1]
        name = nn[0]
        Device.__init__(self, hp, mac, root, name)
        self.oldstate = "0"
        self.last_get = -1
        if root is not None:
            self.id = root.attributes['id'].value
            self.subtype = int(root.attributes['subtype'].value)
            self.tk = root.attributes['tk'].value
            self.qindex = root.attributes['qindex'].value
            self.nick = root.attributes['nick'].value
            self.passw = root.attributes['passw'].value
            self.port2 = int(root.attributes['port2'].value)
            self.state = "0"
        else:
            self.id = idv
            self.subtype = int(typev)
            self.tk = tk
            self.qindex = qindex
            self.state = str(state)
            self.nick = nick
            self.passw = passw
            self.port2 = port2

        self.key = DevicePrimelan.key_from_passw(self.passw)
        self.iv = DevicePrimelan.iv_from_key(self.key)

    def to_dict(self):
        rv = Device.to_dict(self)
        rv.update({
            'tk': self.tk,
            'id': self.id,
            'qindex': self.qindex,
            'subtype': str(self.subtype),
            'passw': self.passw,
            'port2': str(self.port2),
            'nick': self.nick})
        return rv

    def to_json(self):
        rv = Device.to_json(self)
        rv.update({'state': self.state,
                   'oldstate': self.oldstate})
        return rv

    def send_action(self, actionexec, action, pay):
        timeout = action.get_timeout()
        if timeout is None or timeout < 0:
            timeout = DevicePrimelan.TIMEOUT
        if isinstance(action, ActionStatechange) and action.newstate != DevicePrimelan.GET_STATE_ACTION:
            try:
                state = int(pay)
                self.last_get = -1
                _LOGGER.info(f'States {state} -> {self.state}')
                if state != int(self.state):
                    rv = self.change_state_tcp(state, timeout)
                else:
                    rv = 1
            except:  # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")
                rv = None
            return action.exec_handler(rv, self.state)
        elif isinstance(action, ActionStatechange):
            try:
                rv = self.get_state_tcp(timeout)
                if rv is not None:
                    if self.state != rv:
                        st = int(self.state)
                        if st > 0 and st <= 100:
                            self.oldstate = self.state
                        self.state = rv
                    rv = 1
            except:  # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")
                rv = None
            return action.exec_handler(rv, self.state)
        else:
            return Device.send_action(self, actionexec, action, pay)
