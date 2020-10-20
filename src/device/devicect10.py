import binascii
import collections
import json
import logging
import struct
import threading
import time
import traceback
from datetime import datetime

from action import RV_ASYNCH_EXEC, RV_DATA_WAIT, ActionEmitir, ActionLearnir
from Crypto.Cipher import AES
from device import Device
from device.irmanager import IrManager
from device.mantimermanager import ManTimerManager
from util import b2s, cmp_to_key, generatestring, init_logger, s2b, tohexs

PK_KEY = 'khggd54865SNJHGF'
MAGIC = b'\x68\x64'
PK_MSG_ID = b'\x70\x6B'
DK_MSG_ID = b'\x64\x6B'

_LOGGER = init_logger(__name__, level=logging.DEBUG)


class SendBufferTimer(object):
    ACTION_FAILED = -1
    ACTION_OK = -2
    SERIAL = 0

    @staticmethod
    def get_serial():
        serial = SendBufferTimer.SERIAL
        SendBufferTimer.SERIAL += 1
        return serial

    def __init__(self, jsono, action, addr, mac, actionexec):
        if action is None:
            timeout = 0
        else:
            timeout = action.get_timeout()
        if timeout is None or timeout < 0:
            timeout = actionexec.udpmanager.timeout
        self.jsono = jsono
        self.mac = mac
        self.timeout = timeout
        self.timer = None
        self.addr = addr
        self.action = action
        self.status = 0
        self.retry = actionexec.udpmanager.retry
        self.actionexec = actionexec
        self.clientinfo = dict()

    @staticmethod
    def handle_incoming_data(data, key=PK_KEY):
        try:
            valasci = binascii.crc32(data[42:])
            _LOGGER.info(f"K={b2s(key)} Computed CRC %08X vs {tohexs(data[6:10])}" % valasci)
            if valasci == struct.unpack('>i', data[6:10])[0]:
                cry = AES.new(s2b(key), AES.MODE_ECB)
                msg = cry.decrypt(data[42:])
                _LOGGER.info("Decrypted MSG %s" % b2s(msg))
                jsono = json.loads(msg[0:msg.rfind(b'}')+1])
                return {'msg': jsono, 'convid': b2s(data[10:42])}
        except: # noqa: E722
            traceback.print_exc()
            pass
        return None

    def handle_incoming_data2(self, data):
        try:
            if data[4:6] == b"pk":
                key = PK_KEY
            else:
                key = self.clientinfo['key']
            rv = SendBufferTimer.handle_incoming_data(data, key)
            if rv is not None:
                exitv = self.action.device.receive_handler(
                    self.addr, self.action, rv['msg'])
                _LOGGER.info("exitv = "+str(exitv))
                if exitv is not None and exitv != RV_DATA_WAIT:
                    self.set_finished(exitv)
            return rv
        except: # noqa: E722
            traceback.print_exc()
        return None

    def set_finished(self, exitv):
        if exitv is None:
            self.status = SendBufferTimer.ACTION_FAILED
            # self.action.tcpserver.unsetclientinfo(self.addr)
        else:
            self.clientinfo["disconnecttimer"] = time.time()+3*60
            self.status = SendBufferTimer.ACTION_OK
        if self.timer is not None:
            self.timer.cancel()
            self.timer = None
        self.action.run(self.actionexec, exitv)

    def manage_timeout(self):
        self.status += 1
        threading.currentThread().name = ("manage_timeout")
        if self.status < self.retry:
            self.timer = None
            _LOGGER.info("Timeout in action Retry!")
        else:
            _LOGGER.info("Timeout in action fail!")
            self.set_finished(None)

    def has_failed(self):
        return self.status == SendBufferTimer.ACTION_FAILED

    def has_succeeded(self):
        return self.status == SendBufferTimer.ACTION_OK

    def schedule(self):
        if self.action is not None and self.timeout is not None and self.timeout > 0:
            self.timer = threading.Timer(self.timeout, self.manage_timeout, ())
            self.timer.start()
            _LOGGER.info("Scheduling timeouttimer "+str(self.timeout))
        else:
            self.status = SendBufferTimer.ACTION_OK
        return self.get_send_bytes2()

    def get_send_bytes2(self):
        if len(self.jsono):
            if 'key' in self.clientinfo:
                key = self.clientinfo['key']
                typemsg = b'dk'
            else:
                key = PK_KEY
                typemsg = b'pk'
            if 'convid' in self.clientinfo:
                convid = self.clientinfo['convid']
            else:
                convid = ("\x00")*32
            return SendBufferTimer.get_send_bytes(self.jsono, convid, key, typemsg)
        else:
            return b''

    @staticmethod
    def get_send_bytes(jsono, convid, key=PK_KEY, typemsg="dk"):
        try:
            if convid is None:
                convid = generatestring(32)
            if 'serial' in jsono and jsono['serial'] is None:
                jsono['serial'] = SendBufferTimer.get_serial()
            if 'key' in jsono and jsono['key'] is None:
                jsono['key'] = generatestring(16)
            msg = s2b(json.dumps(jsono))
            _LOGGER.info("Encrypting with %s MSG %s" % (b2s(key), b2s(msg)))
            lnmsg = len(msg)
            remain = lnmsg % 16
            if remain > 0:
                remain = (lnmsg//16)*16+16-lnmsg
                msg += b"\x20"*remain
            ln = lnmsg+remain+4+2+2+2+32
            cry = AES.new(s2b(key), AES.MODE_ECB)
            newbytes = cry.encrypt(msg)
            crc32 = binascii.crc32(newbytes)
            bytesa = MAGIC+struct.pack('>H', ln)+typemsg + \
                struct.pack('>i', crc32)+s2b(convid)
            return bytesa+newbytes
        except: # noqa: E722
            traceback.print_exc()
            return b''


class DeviceCT10(IrManager, ManTimerManager):

    @staticmethod
    def is_learnir_intermediate_response(data):
        return data["cmd"] == 25

    def receive_handler(self, hp, action, data, **kwargs):
        if isinstance(action, ActionLearnir):
            if DeviceCT10.is_learnir_intermediate_response(data):
                return action.exec_handler(RV_DATA_WAIT, None)
            else:
                attrs = dict()
            if 'freq' in data:
                attrs['freq'] = data['freq']
            if 'pluse' not in data:
                return action.exec_handler(None, None)
            else:
                return action.exec_handler(1, {'irc': data['pluse'], 'attrs': attrs})
        elif isinstance(action, ActionEmitir):
            if 'clientSessionId' in data and self.clientSessionId == data['clientSessionId']:
                return action.exec_handler(1, data)
        return action.exec_handler(None, None)

    def __init__(self, hp=('', 0), mac='', root=None, name='', key=PK_KEY, password='', deviceid='', clientsessionid='', hp2=('', 0)):
        Device.__init__(self, hp, mac, root, name)
        ManTimerManager.__init__(self, root)
        IrManager.__init__(self, hp, mac, root, name)
        self.key = key
        self.fid = 0
        if len(clientsessionid) == 0:
            self.clientSessionId = generatestring(32)
        else:
            self.clientSessionId = clientsessionid
        if root is None:
            self.password = password
            self.deviceId = deviceid
            self.localPort = hp2[1]
            self.localIp = hp2[0]
        else:
            self.password = root.attributes['password'].value
            self.deviceId = root.attributes['deviceId'].value
            self.localPort = root.attributes['localPort'].value
            self.localIp = root.attributes['localIp'].value
            # _LOGGER.info("HERE1 "+str(self.dir))
            # _LOGGER.info("HERE2 "+str(self.sh))
            # self.dir_file_min(self.dir)
            # self.sh_file_min(self.sh)

    def get_action_payload(self, action):
        if isinstance(action, ActionLearnir):
            if len(action.irdata):
                fk = action.irdata[action.irdata.find(
                    ':')+1:].translate(None, '!@#$/\\+-_')
                if len(fk) < 2:
                    fk = generatestring(5)
                cmd = collections.OrderedDict()
                cmd['fKey'] = fk
                cmd['fid'] = self.get_fid()
                cmd['uid'] = tohexs(self.mac)
                cmd['cmd'] = 25
                cmd['order'] = 'ir control'
                cmd['lastUpdateTime'] = int(
                    Device.unix_time_millis(datetime.now())/1000.0)
                cmd['clientSessionId'] = self.clientSessionId
                cmd['serial'] = None
                cmd['deviceId'] = self.deviceId
                cmd['fName'] = fk
                return cmd
        elif isinstance(action, ActionEmitir):
            if len(action.irdata):
                cmd = collections.OrderedDict()
                cmd['uid'] = tohexs(self.mac)
                cmd['defaultResponse'] = 1
                cmd['delayTime'] = 0
                cmd['qualityOfService'] = 1
                cmd['clientSessionId'] = self.clientSessionId
                cmd.update(action.irdata[2])
                cmd['pluseNum'] = action.irdata[0].count(',')+1
                cmd['value1'] = 0
                cmd['value2'] = 0
                cmd['value3'] = 0
                cmd['value4'] = 0
                cmd['cmd'] = 15
                cmd['order'] = 'ir control'
                # cmd['userName'] = 'fulminedipegasus@gmail.com'
                cmd['pluseData'] = action.irdata[0]
                cmd['serial'] = None
                cmd['deviceId'] = self.deviceId
                return cmd
        return IrManager.get_action_payload(self, action)

    def get_fid(self):
        self.fid += 1
        return self.fid

    @staticmethod
    def discovery(actionexec, timeout, **kwargs):
        return actionexec.tcpserver.get_connected_clients()

    def get_arduraw(self, remote, irdata):
        out = []
        irenc = irdata[0].split(',')
        for h in irenc:
            out.append(int(h))
        return {'key': irdata[1], 'remote': remote, 'a': out}

    def get_from_arduraw(self, msg):
        out = ''
        for h in msg['a']:
            out += str(h)+","
        return (out[:-1], msg['key'], {'freq': 38000})

    def send_action(self, actionexec, action, pay):
        if isinstance(action, (ActionEmitir, ActionLearnir)):
            buf = SendBufferTimer(
                pay, action, (self.host, self.port), self.mac, actionexec)
            if actionexec.tcpserver.schedulewrite(buf):
                return RV_ASYNCH_EXEC
            else:
                return None
        else:
            return IrManager.send_action(self, actionexec, action, pay)

    def copy_extra_from(self, already_saved_device):
        savep = self.port
        IrManager.copy_extra_from(self, already_saved_device)
        ManTimerManager.copy_extra_from(self, already_saved_device)
        self.deviceId = already_saved_device.deviceId
        self.port = savep

    def to_dict(self):
        rv = IrManager.to_dict(self)
        rv.update({'key': self.key, 'password': self.password, 'deviceId': self.deviceId,
                   'localIp': self.localIp, 'localPort': str(self.localPort)})
        return rv

    def on_stop(self):
        IrManager.on_stop(self)
        ManTimerManager.on_stop(self)

    def to_json(self):
        rv = IrManager.to_json(self)
        rv.update(ManTimerManager.to_json(self))
        return rv

    def xml_element(self, root, flag=0):
        el = IrManager.xml_element(self, root, flag)
        ManTimerManager.xml_element(self, el, flag)
        return el

    def ir_decode(self, irc):
        return irc

    def ir_encode(self, irc):
        return irc

    def ir_att_decode(self, irc):
        if 'freq' in irc:
            irc = irc.copy()
            irc['freq'] = int(irc['freq'])
        return irc

    def ir_att_encode(self, irc):
        if 'freq' in irc:
            irc = irc.copy()
            irc['freq'] = str(irc['freq'])
        return irc

    def dir_file_min(self, lst):
        with open("remotes.bin", "wb") as f:
            lst2 = sorted(lst)
            for nm in lst2:
                d433d = lst[nm]
                lst3 = sorted(d433d)
                f.write(struct.pack("<B", len(nm)))
                f.write(bytearray(nm, 'utf8'))
                f.write(struct.pack(
                    "<B", sum(1 for i in d433d if len(d433d[i][1]))))

                for irnm in lst3:
                    tpl = d433d[irnm]
                    if len(tpl[1]):
                        f.write(struct.pack("<B", len(tpl[1])))
                        f.write(bytearray(tpl[1], 'utf8'))
                        arrj = json.loads("["+tpl[0]+"]")
                        if len(arrj):
                            f.write(struct.pack("<H", len(arrj)))
                            f.write(struct.pack("<"+str(len(arrj))+"H", *
                                                tuple([(lambda i: 65535 if i > 65535 else i)(i) for i in arrj])))
            f.close()

    def sh_file_min(self, lst):
        with open("shs.bin", "wb") as f:
            lst2 = sorted(lst, key=cmp_to_key(IrManager.sh_comparer))
            for nm in lst2:
                d433d = lst[nm]
                f.write(struct.pack("<B", len(nm)))
                f.write(bytearray(nm, 'utf8'))
                f.write(struct.pack("<B", len(d433d)))
                for x in d433d:
                    idx = x.find(':')
                    if idx > 0 and idx < len(x)-1:
                        remnm = x[0:idx]
                        keynm = x[idx+1:]
                    else:
                        remnm = ""
                        keynm = x
                    f.write(struct.pack("<B", len(remnm)))
                    if len(remnm):
                        f.write(bytearray(remnm, 'utf8'))
                    f.write(struct.pack("<B", len(keynm)))
                    f.write(bytearray(keynm, 'utf8'))
            f.close()
