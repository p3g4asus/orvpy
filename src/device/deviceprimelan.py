import json
import logging
import struct
import sys
import time
import traceback
from xml.dom import minidom

import requests

import event
from action import ActionNotifystate, ActionStatechange
from Crypto.Cipher import AES
from device import Device
from transport import TCPClient
from util import b2s, init_logger, s2b

if sys.version_info >= (3, 0):
    from functools import reduce


_LOGGER = init_logger(__name__, level=logging.DEBUG)


class DevicePrimelan(Device):
    # 0: doppio pulsante
    # 2: On off slider
    # 1: slider 0-100
    TIMEOUT = 7

    def process_asynch_state_change(self, state):
        self.last_get = time.time()
        _LOGGER.info(f"{id(self)} {self.name} last_get = {self.last_get}")
        if self.state != state:
            self.oldstate = self.state
            self.state = state

    def state_value_conv(self, s):
        try:
            realv = int(s)
        except: # noqa: E722
            realv = 0
        if realv == 0:
            return "0"
        elif realv >= 1000:
            if self.subtype == 1:
                try:
                    ost = int(self.oldstate)
                except: # noqa: E722
                    ost = 0
                try:
                    st = int(self.state)
                except: # noqa: E722
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
            actionexec.insert_action(ActionStatechange(self, DevicePrimelan.GET_STATE_ACTION), 0)
            return 0
        else:
            return Device.do_presend_operations(self, action, actionexec)

    def do_postsend_operations(self, action, actionexec):
        if isinstance(action, ActionStatechange) and action.newstate != DevicePrimelan.GET_STATE_ACTION:
            actionexec.insert_action(ActionStatechange(self, DevicePrimelan.GET_STATE_ACTION), 1)
        else:
            Device.do_postsend_operations(self, action, actionexec)

    def mqtt_publish_onstart(self):
        out = {
            'subtype': self.subtype,
            'nick': self.nick,
            'state': self.state,
            'oldstate': self.oldstate}
        return [dict(topic=self.mqtt_topic("stat", "device"), msg=json.dumps(out), options=dict(retain=True))]

    def mqtt_on_message(self, client, userdata, msg):
        Device.mqtt_on_message(self, client, userdata, msg)
        sub = self.mqtt_sub(msg.topic)
        try:
            if sub == "state":
                event.EventManager.fire(eventname='ExtInsertAction', hp=(
                        self.host, self.port), cmdline="", action=ActionStatechange(self, b2s(msg.payload)))
        except: # noqa: E722
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
    def discovery(hp, passw, codu, port2, timeout=10):
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
            _LOGGER.info('received '+txt+" tk = "+tk+" qindex = "+qindex)
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
                out['{}:{}'.format(*hp)+':'+idv] = dev
            return out
        except: # noqa: E722
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

    def pkt_state(self, newstate):
        pre = b'\x50\x53\x00\x00\x1a\x00\x00\x00\x2a\x00\x00\x00\x50\x50'
        out = b'\x01\x00\x1a\x00\x00\x00'
        if newstate < 0:
            onoff = 0x4000
            newstate = -newstate
        else:
            onoff = 0x30E0
        aesc = b'\x08\x00\x00\x00\x69\x00\x00\x00'+struct.pack("<H", onoff)+struct.pack(
            "<B", int(self.id))+b'\x00'+struct.pack("<B", int(newstate))+b'\x00\x02\x02'
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        aesc2 = cipher.encrypt(aesc)
        crc = DevicePrimelan.crc16(bytearray(out+aesc2))
        return pre+struct.pack("<H", crc)+out+aesc2

    def change_state_http(self, pay, timeout):
        r = requests.post('http://{}:{}/cgi-bin/web.cgi'.format(self.host, self.port),
                          data={'tk': self.tk, 'qindex': self.qindex, 'mod': 'do_cmd', 'par': self.id, 'act': pay}, timeout=timeout)
        return 1 if r.status_code == 200 else r.status_code

    @staticmethod
    def http_state_to_real_state(d):
        return d['st'] if d['t'] != "1" or int(d['p']) > 0 else '0'

    def get_state_http(self, timeout):
        now = time.time()
        if now - self.last_get > 10:
            r = requests.post('http://{}:{}/cgi-bin/web.cgi'.format(self.host, self.port),
                              data={'tk': self.tk, 'qindex': self.qindex, 'mod': 'cmd'}, timeout=timeout)
            lst = r.json()['cmd']
            _LOGGER.info(f'Get state (difftime = {now - self.last_get}) rv = {lst}')
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

    def change_state_tcp(self, state, timeout):
        t = TCPClient(timeout)
        return 1 if t.send_packet((self.host, self.port2), self.pkt_state(state)) > 0 else None

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

        self.key = s2b(self.passw)+(b'\x00'*(16-len(self.passw)))
        self.iv = reduce(lambda x, y: x+struct.pack("<B",
                                                    y[1] ^ y[0]), enumerate(self.key), b'')

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
                if state != int(self.state):
                    rv = self.change_state_tcp(state, timeout)
                else:
                    rv = 1
            except: # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")
                rv = None
            return action.exec_handler(rv, self.state)
        elif isinstance(action, ActionStatechange):
            try:
                rv = self.get_state_http(timeout)
                if rv is not None:
                    if self.state != rv:
                        st = int(self.state)
                        if st > 0 and st <= 100:
                            self.oldstate = self.state
                        self.state = rv
                    rv = 1
            except: # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")
                rv = None
            return action.exec_handler(rv, self.state)
        else:
            return Device.send_action(self, actionexec, action, pay)
