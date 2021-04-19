import logging
import re
import struct
import time

import event
from action import ActionDiscovery
from device.devicect10 import DK_MSG_ID, PK_MSG_ID, DeviceCT10, SendBufferTimer
from device.deviceudp import (DISCOVERY_ID, MAC_START, MAGIC,
                              STATECHANGE_EXT_ID, DeviceUDP)
from util import b2s, generatestring, init_logger, tohexs

_LOGGER = init_logger(__name__, level=logging.DEBUG)


class RoughParser(object):
    DISCARD_BUFFER = -2000
    UNRECOGNIZED = -3000
    STILL_WAIT = -1000

    def __init__(self, reply=None):
        # self.pk = AES.new(PK_KEY, AES.MODE_ECB)
        pass

    def parse(self, clinfo, data):
        if isinstance(clinfo, dict):
            returnv = clinfo
        else:
            returnv = {'addr': clinfo}

        hp = returnv['addr']
        if len(data) > 6 and data[0:1] == b'@':
            returnv['type'] = b'mfz'
            idx = data.find(b'\n')
            if idx < 0:
                if len(data) >= 200:
                    returnv['idxout'] = RoughParser.DISCARD_BUFFER
                else:
                    returnv['idxout'] = RoughParser.STILL_WAIT
            else:
                _LOGGER.info(
                    "R [" + hp[0] + ":" + str(hp[1]) + "] <-" + b2s(data))
                event.EventManager.fire(eventname='ExtInsertAction', hp=hp,
                                        cmdline=b2s(data[1:]), action=None)
                returnv['idxout'] = idx + 1
        elif len(data) > 7 and data[0:2] == MAGIC:
            msgid = data[4:6]
            ln = struct.unpack('>H', data[2:4])[0]
            _LOGGER.info("Detected Magic with ln %d and id %s" %
                         (ln, b2s(msgid)))
            if len(data) >= ln:
                returnv['type'] = b'cry' if msgid == PK_MSG_ID or msgid == DK_MSG_ID else b'orv'
                returnv['idxout'] = ln
                contentmsg = data[0:ln]
                if msgid == PK_MSG_ID:
                    outv = SendBufferTimer.handle_incoming_data(contentmsg)
                    if outv is not None:
                        obj = outv['msg']
                        if obj['cmd'] == 0:
                            name = obj['hardwareVersion']
                            # obj['serial']
                            dictout = {'serial': 0, 'cmd': 0,
                                       'key': None, 'status': 0}
                            returnv['name'] = name.replace(' ', '_')
                            returnv['reply'] = SendBufferTimer.get_send_bytes(
                                dictout, None, typemsg=b"pk")
                            returnv['key'] = dictout['key']
                elif msgid == DK_MSG_ID:
                    if 'sender' in clinfo:
                        outv = clinfo['sender'].handle_incoming_data2(
                            contentmsg)
                    else:
                        outv = SendBufferTimer.handle_incoming_data(
                            contentmsg, returnv['key'])
                    if outv is not None:
                        obj = outv['msg']
                        if obj['cmd'] == 6:
                            returnv['hp'] = hp
                            returnv['localIp'] = obj['localIp']
                            returnv['localPort'] = obj['localPort']
                            returnv['password'] = obj['password']
                            returnv['mac'] = tohexs(obj['uid'])
                            returnv['convid'] = outv['convid']
                            dictout = {
                                'serial': obj['serial'], 'cmd': 6, 'status': 0}
                            returnv['reply'] = SendBufferTimer.get_send_bytes(
                                dictout, outv['convid'], key=returnv['key'], typemsg=b"dk")
                            dev = DeviceCT10(hp=hp,
                                             mac=returnv['mac'],
                                             name=returnv['name'] +
                                             '_' + obj['uid'],
                                             key=returnv['key'],
                                             password=obj['password'],
                                             deviceid=generatestring(32),
                                             clientsessionid=generatestring(
                                                 32),
                                             hp2=(obj['localIp'], obj['localPort']))
                            returnv['device'] = dev
                            act = ActionDiscovery()
                            act.hosts[obj['uid']] = dev
                            event.EventManager.fire(eventname='ActionDiscovery',
                                                    device=dev, action=act, retval=1)
                        elif obj['cmd'] == 116 or obj['cmd'] == 32:
                            dictout = {'serial': obj['serial'],
                                       'cmd': obj['cmd'], 'status': 0, 'uid': obj['uid']}
                            returnv['reply'] = SendBufferTimer.get_send_bytes(
                                dictout, outv['convid'], key=returnv['key'], typemsg=b"dk")
                            returnv['disconnecttimer'] = time.time() + 3 * 60
                else:
                    if msgid == STATECHANGE_EXT_ID or msgid == DISCOVERY_ID:
                        event.EventManager.fire(eventname='ExtChangeState', hp=hp, mac=DeviceUDP.mac_from_data(
                            data), newstate="1" if data[-1:] == b'\x01' else "0")
                    rx = re.compile(MAGIC + b'(.{2}).{2}.*' + MAC_START)
                    control = {}
                    off = 0
                    while True:
                        m = re.search(rx, data)
                        if m:
                            st = m.start()
                            ln = struct.unpack('>H', m.group(1))[0]
                            # _LOGGER.info("st = {} ln = {}".format(st,ln))
                            off = st + ln
                            if off <= len(data):
                                sect = data[st:off]
                                data = data[off:]
                                keyv = DeviceUDP.keyfind(hp, sect)
                                if keyv not in control:
                                    control[keyv] = 1
                                    event.EventManager.fire(
                                        eventname='RawDataReceived', key=keyv, hp=hp, data=sect)
                                    _LOGGER.info(
                                        "R [" + keyv + "] <-" + tohexs(sect))
                            else:
                                break
                        else:
                            break
                    returnv['idxout'] = RoughParser.UNRECOGNIZED if not off else off
            else:
                returnv['idxout'] = RoughParser.STILL_WAIT
        else:
            returnv['idxout'] = RoughParser.UNRECOGNIZED
        return returnv
