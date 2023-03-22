import json
import logging
import random
import struct
import time
import traceback
from datetime import datetime
from xml.dom import minidom
from xml.etree.ElementTree import SubElement

import event
from action import (DELRECORD_CODE, RV_DATA_WAIT, ActionEmitir, ActionLearnir,
                    ActionNotifystate, ActionSettable, ActionSettable3,
                    ActionSettable4, ActionStatechange, ActionStateoff,
                    ActionStateon, ActionSubscribe, ActionViewtable,
                    ActionViewtable1, ActionViewtable3)
from device import DEVICE_SAVE_FLAG_MAIN, DEVICE_SAVE_FLAG_TABLE, Device
from device.irmanager import IrManager
from device.mantimermanager import ManTimerManager
from util import b2s, init_logger, s2b, tohexs

_LOGGER = init_logger(__name__, level=logging.DEBUG)


MAGIC = b'\x68\x64'
DISCOVERY_LEN = b'\x00\x06'
DISCOVERY_ID = b'\x71\x61'
SUBSCRIBE_LEN = b'\x00\x1e'
SUBSCRIBE_ID = b'\x63\x6c'
PADDING_1 = b'\x20\x20\x20\x20\x20\x20'
PADDING_2 = b'\x00\x00\x00\x00'
MAC_START = b'\xac\xcf'
DISCOVERY_ALLONE = b'\x49\x52\x44'
DISCOVERY_S20 = b'\x53\x4f\x43'
INSERT_ACTION_ID = b'\x11\x12'
STATECHANGE_EXT_ID = b'\x73\x66'
DEFAULT_RESUBSCRIPTION_STIMEOUT = 7
DEFAULT_RESUBSCRIPTION_TIMEOUT = 60
VIEW_TABLE_LEN = b'\x00\x1d'
VIEW_TABLE_ID = b'\x72\x74'
WRITE_TABLE_ID = b'\x74\x6d'
STATECHANGE_ID = b'\x64\x63'
STATECHANGE_LEN = b'\x00\x17'
LEARNIR_ID = b'\x6c\x73'
LEARNIR_LEN = b'\x00\x18'
LEARNIR_2 = b'\x01\x00\x00\x00\x00\x00'
EMITIR_ID = b'\x69\x63'
EMITIR_2 = b'\x65\x00\x00\x00'


class DeviceUDP(Device):
    TIMEZONE_NOT_SET = 9000
    TIMEZONE_NONE = 70000
    OFF_AFTER_ON_NONE = 70000

    @staticmethod
    def keyfind(addr, data):
        mac = DeviceUDP.mac_from_data(data)
        return tohexs(mac) if mac else "{}:{}".format(*addr)

    @staticmethod
    def mac_from_data(data):
        idx = data.find(MAC_START)
        if idx >= 0 and idx + 6 <= len(data):
            return data[idx:idx + 6]
        else:
            return None

    def is_my_mac(self, data):
        mac = DeviceUDP.mac_from_data(data)
        return False if not mac else mac == self.mac

    def do_presend_operations(self, action, actionexec):
        if isinstance(action, (ActionStatechange, ActionLearnir, ActionEmitir, ActionViewtable, ActionSettable)):
            if self.needs_resubscription():
                actionexec.insert_action(ActionSubscribe(self), 0)
                return 0
            self.subs_action()
        return Device.do_presend_operations(self, action, actionexec)

    @staticmethod
    def discovery_handler(hp, action, buf, **kwargs):
        hosts = dict()
        for keyv, buffcont in buf.copy().items():
            data = buffcont.data
            if not len(data) >= 41 and data[4:6] == (DISCOVERY_ID):
                continue
            if keyv not in hosts:
                if data.find(DISCOVERY_ALLONE) >= 0:
                    typed = DeviceAllOne
                elif data.find(DISCOVERY_S20) >= 0:
                    typed = DeviceS20
                else:
                    _LOGGER.info(
                        f"Unknown device type {keyv} {tohexs(data[31:37])}")
                    continue
                dev = typed(hp=buffcont.addr, mac=data[7:13],
                            sec1900=struct.unpack('<I', data[37:41])[0])
                _LOGGER.info("Discovered device %s" % dev)
                hosts[keyv] = dev
                _LOGGER.info("ln = " + str(len(hosts)) + " h = " + str(keyv))
        return hosts

    @staticmethod
    def discovery(actionexec, timeout=5, **kwargs):
        return actionexec.udpmanager._udp_transact(
            action=None,
            hp=(None, 0),
            payload=MAGIC + DISCOVERY_LEN + DISCOVERY_ID,
            handler=DeviceUDP.discovery_handler,
            keyfind=DeviceUDP.keyfind,
            timeout=timeout)

    def prepare_additional_file(self, root, flag):
        self.xml_table_element(root, flag)

    @staticmethod
    def is_subscribe_response(data):
        return len(data) >= 13 and data[4:6] == (SUBSCRIBE_ID)

    @staticmethod
    def is_statechange_response(data):
        return len(data) > 6 and data[4:6] == (STATECHANGE_ID)

    @staticmethod
    def is_viewtable_response(data):
        return len(data) >= 28 and data[4:6] == (VIEW_TABLE_ID)

    @staticmethod
    def is_viewtable4_response(data):
        return len(data) >= 168 and data[4:6] == (VIEW_TABLE_ID)

    @staticmethod
    def is_settable_response(data):
        return len(data) >= 6 and data[4:6] == (WRITE_TABLE_ID)

    @staticmethod
    def ip2string(ip):
        ipp = ip.split('.')
        if len(ipp) == 4:
            ipr = ''
            for i in ipp:
                try:
                    ipr += struct.pack('<B', int(i))
                except:  # noqa: E722
                    _LOGGER.warning(f"{traceback.format_exc()}")
                    ipr += b'\x01'
            return ipr
        else:
            return b'\x0A\x00\x00\x01'

    def get_ver_flag(self, table, defv):
        stable = str(table)
        if self.tablever is not None and stable in self.tablever:
            return str(self.tablever[stable]['flgn'])
        else:
            return defv

    def parse_table1(self, data):
        start = 28
        ln = len(data)
        self.tablever = {}
        while start + 8 <= ln:
            '''_LOGGER.info("allv = "+data[start+2:start+8].encode('hex'))'''
            vern = struct.unpack('<H', data[start + 2:start + 4])[0]
            tabn = struct.unpack('<H', data[start + 4:start + 6])[0]
            flgn = struct.unpack('<H', data[start + 6:start + 8])[0]
            tabns = str(tabn)
            self.tablever[tabns] = {}
            self.tablever[tabns]['vern'] = vern
            self.tablever[tabns]['flgn'] = flgn
            start += 8

    def parse_timer_record(self, rec):
        tcode = struct.unpack('<H', rec[2:4])[0]
        swAction = 0 if rec[20:21] == b'\x00' else 1
        year = struct.unpack('<H', rec[22:24])[0]
        month = struct.unpack('<B', rec[24:25])[0]
        day = struct.unpack('<B', rec[25:26])[0]
        h = struct.unpack('<B', rec[26:27])[0]
        m = struct.unpack('<B', rec[27:28])[0]
        s = struct.unpack('<B', rec[28:29])[0]
        rep = struct.unpack('<B', rec[29:30])[0]
        self.timers.append(dict(code=tcode, action=swAction, rep=rep, hour=h,
                                minute=m, second=s, year=year, month=month, day=day))

    def parse_table3(self, data):
        start = 28
        ln = len(data)
        self.timers = []
        while start < ln:
            lenrec = struct.unpack('<H', data[start:start + 2])[0]
            rec = data[start:start + 2 + lenrec]
            self.parse_timer_record(rec)
            start += 2 + lenrec

    def parse_table4(self, data):
        if len(self.name) == 0 or self.name == self.default_name():
            strname = b2s(data[70:86].replace(
                b'\xff', '').replace(b'\x00', '').strip())
            if len(strname):
                self.name = strname
        timerSetString = struct.unpack('<B', data[164:165])[0]
        timerValString = struct.unpack('<H', data[166:168])[0]
        self.timer_off_after_on = 0 if not timerSetString else timerValString
        tzS = struct.unpack('<B', data[162:163])[0]
        tz = struct.unpack('<B', data[163:164])[0]
        self.timezone = DeviceUDP.TIMEZONE_NOT_SET if tzS else tz

    def process_response(self, hp, action, data, **kwargs):
        out = dict(rv=None, data=None)
        if isinstance(action, ActionSubscribe) and DeviceUDP.is_subscribe_response(data) and self.is_my_mac(data):
            self.process_subscribe(data)
            self.subs_action()
            out['rv'] = 1
        elif isinstance(action, ActionViewtable) and \
            (DeviceUDP.is_viewtable_response(data) or DeviceUDP.is_viewtable4_response(data)) and \
                struct.unpack('<B', data[23])[0] == action.tablenum and self.is_my_mac(data):
            if self.rawtables is None:
                self.rawtables = dict()
            self.rawtables[str(action.tablenum)] = data
            if isinstance(action, ActionViewtable1):
                self.parse_table1(data)
            elif isinstance(action, ActionViewtable3):
                self.parse_table3(data)
            else:
                self.parse_table4(data)
            out['rv'] = 1
        elif isinstance(action, ActionSettable) and \
                DeviceUDP.is_settable_response(data) and \
                self.is_my_mac(data):
            out['rv'] = 1
        elif isinstance(action, ActionStatechange) and DeviceUDP.is_statechange_response(data) and self.is_my_mac(data):
            out['rv'] = 1
        return out

    def receive_handler(self, hp, action, data, **kwargs):
        out = self.process_response(hp, action, data)
        return action.exec_handler(**out)

    def send_action(self, actionexec, action, pay):
        return actionexec.udpmanager._udp_transact(
            action=action,
            hp=(self.host, self.port),
            payload=pay,
            handler=self.receive_handler,
            keyfind=DeviceUDP.keyfind,
            timeout=action.get_timeout())

    def get_table3_record(self, action):
        if action.datetime is None:
            return struct.pack('<H', action.timerid)
        else:
            if action.timerid is None or action.timerid < 0:
                timerid = 1
                while True:
                    repeat = False
                    for t in self.timers:
                        if t['code'] == timerid:
                            timerid += 1
                            repeat = True
                            break
                    if not repeat:
                        break
            else:
                timerid = action.timerid

            record = struct.pack('<H', timerid) + PADDING_1 + PADDING_1\
                + b'\x20\x20\x20\x20' + struct.pack('<H', action.action) + struct.pack('<H', action.datetime.year)\
                + struct.pack('<B', action.datetime.month) + struct.pack('<B', action.datetime.day)\
                + struct.pack('<B', action.datetime.hour) + struct.pack('<B', action.datetime.minute)\
                + struct.pack('<B', action.datetime.second) + \
                struct.pack('<B', action.rep)

            return record

    def get_table4_record(self, action):
        if self.rawtables is None or "4" not in self.rawtables:
            return ''
        else:
            pay = self.rawtables["4"]
            lenrec = struct.unpack('<H', pay[28:30])[0]
            record = pay[30:30 + lenrec]

            if action.name is None:
                nm = None
            elif len(action.name) > 16:
                nm = action.name[0:16]
            else:
                nm = action.name.ljust(16)
            if nm is not None:
                record = record[0:40] + s2b(nm) + record[56:]
            if action.ip is not None:
                record = record[0:118] + s2b(DeviceUDP.ip2string(action.ip) + DeviceUDP.ip2string(
                    action.gateway) + DeviceUDP.ip2string(action.nmask)) + b'\x00\x01' + record[132:]
            if action.timezone is not None:
                record = record[0:132] + (b'\x01\x00' if action.timezone ==
                                          DeviceUDP.TIMEZONE_NOT_SET else b'\x00' + struct.pack('<b', action.timezone)) + record[134:]
            if action.timer_off_after_on is not None:
                record = record[0:134] + (b'\x00\xff' if action.timer_off_after_on <=
                                          0 else b'\x01\x00') + struct.pack('<H', action.timer_off_after_on) + record[138:]
            return record

# concetto di handler dopo send_action rimane ma  ha come parametri rv (valore di ritorno e data che dipende dall'azione')
# l'handler esegue quello che deve con il data controllando rv. ritorna il valore che deve in vase ad rv (valore ok 0)'
    def get_action_payload(self, action):
        if isinstance(action, ActionSubscribe):
            return MAGIC + SUBSCRIBE_LEN + SUBSCRIBE_ID + self.mac \
                + PADDING_1 + self.mac_reversed + PADDING_1
        elif isinstance(action, ActionStatechange) and action.newstate != Device.GET_STATE_ACTION:
            newst = self.state_value_conv(action.newstate)
            return MAGIC + STATECHANGE_LEN + STATECHANGE_ID + self.mac + PADDING_1\
                + PADDING_2 + (b'\x01' if newst != "0" else b'\x00')
        elif isinstance(action, ActionStatechange):
            return b''
        elif isinstance(action, ActionViewtable):
            return MAGIC + VIEW_TABLE_LEN + VIEW_TABLE_ID + self.mac + PADDING_1\
                + PADDING_2 + struct.pack('<B', action.tablenum) + b'\x00' + \
                struct.pack('<B', action.vflag) + PADDING_2
        elif isinstance(action, ActionSettable):
            if isinstance(action, ActionSettable4):
                record = self.get_table4_record(action)
            else:
                record = self.get_table3_record(action)
            if len(record):
                pay = WRITE_TABLE_ID + self.mac + PADDING_1\
                    + PADDING_2 + struct.pack('<H', action.tablenum) + \
                    struct.pack('<B', action.actionid)

                if action.actionid != DELRECORD_CODE:
                    pay += struct.pack('<H', len(record))
                pay += record
                return MAGIC + struct.pack('>H', len(pay) + 4) + pay
        return Device.get_action_payload(self, action)

    def __init__(self, hp=('', 0), mac='', root=None, timeout=DEFAULT_RESUBSCRIPTION_TIMEOUT, name='', sec1900=0, lsa_timeout=DEFAULT_RESUBSCRIPTION_STIMEOUT, **kw):
        Device.__init__(self, hp, mac, root, name)
        if root is None:
            self.subscribe_time = 0
            self.resubscription_timeout = timeout
            self.last_subs_action_timeout = lsa_timeout
            self.sec1900 = int(((datetime.now() - datetime(1900, 1, 1, 0, 0, 0, 0)).total_seconds() -
                                (datetime.utcnow() - datetime.now()).total_seconds() - sec1900) * 1000)
        else:
            self.subscribe_time = int(root.attributes['sst'].value)
            self.sec1900 = int(root.attributes['sec1900'].value)
            self.resubscription_timeout = int(root.attributes['rtime'].value)
            self.last_subs_action_timeout = int(root.attributes['stime'].value)
        self.last_subs_action = 0
        self.get_reversed_mac()
        self.rawtables = None
        self.tablever = None
        self.timer_off_after_on = None
        self.timezone = None

    def copy_extra_from(self, already_saved_device):
        Device.copy_extra_from(self, already_saved_device)
        self.rawtables = already_saved_device.rawtables
        self.tablever = already_saved_device.tablever
        self.timer_off_after_on = already_saved_device.timer_off_after_on
        self.timezone = already_saved_device.timezone
        self.resubscription_timeout = already_saved_device.resubscription_timeout
        self.last_subs_action_timeout = already_saved_device.last_subs_action_timeout

    def process_subscribe(self, data):
        self.subscribe_time = int(time.time())

    def to_dict(self):
        dct = Device.to_dict(self)
        # a = datetime(1900,1,1,0,0,0)
        # b = a + timedelta(seconds=self.sec1900)
        # b.strftime('%d/%m/%Y %H:%M:%S')
        dct.update({
            "sst": str(self.subscribe_time),
            "sec1900": str(self.sec1900),
            "rtime": str(self.resubscription_timeout),
            "stime": str(self.last_subs_action_timeout),
        })
        return dct

    def to_json(self):
        dct = Device.to_json(self)
        dct.update({
            'tablever': {} if self.tablever is None else self.tablever,
            'timer_off_after_on': DeviceUDP.OFF_AFTER_ON_NONE if self.timer_off_after_on is None else self.timer_off_after_on,
            'timezone': DeviceUDP.TIMEZONE_NONE if self.timezone is None else self.timezone
        })
        return dct

    def xml_table_element(self, root, flag=0):
        el = self.xml_element(root, flag) if (flag & DEVICE_SAVE_FLAG_TABLE) and (
            flag & DEVICE_SAVE_FLAG_MAIN) else self.__xml_basic(root)
        tables_el = SubElement(el, "tables")
        tv = {} if self.tablever is None else self.tablever
        for tn, tinfo in tv.copy().items():
            table_el = SubElement(tables_el, "table", {"num": tn})
            v = SubElement(table_el, "version")
            v.text = str(tinfo['vern'])
            v = SubElement(table_el, "flag")
            v.text = str(tinfo['flgn'])

        offafteron = SubElement(el, 'offafteron')
        offafteron.text = str(DeviceUDP.OFF_AFTER_ON_NONE) if self.timer_off_after_on is None else str(
            self.timer_off_after_on)
        timezone = SubElement(el, 'timezone')
        timezone.text = str(
            DeviceUDP.TIMEZONE_NONE) if self.timezone is None else str(self.timezone)
        ManTimerManager.timer_xml_device_node_write(el, self.timers)

    @staticmethod
    def loadtables(fn, devn):
        out = dict()
        xmldoc = minidom.parse(fn)
        items = xmldoc.getElementsByTagName('device')
        outitem = None
        for item in items:
            nm = item.attributes['name'].value
            if nm == devn:
                outitem = item
                break
        if outitem is None:
            return out
        out['offafteron'] = None
        sub = outitem.getElementsByTagName('offafteron')
        for s in sub:
            out['offafteron'] = int(s.childNodes[0].nodeValue)
            if out['offafteron'] == DeviceUDP.OFF_AFTER_ON_NONE:
                out['offafteron'] = None
            break

        out['timezone'] = None
        sub = outitem.getElementsByTagName('timezone')
        for s in sub:
            out['timezone'] = int(s.childNodes[0].nodeValue)
            if out['timezone'] == DeviceUDP.TIMEZONE_NONE:
                out['timezone'] = None
            break

        out['timers'] = ManTimerManager.timer_xml_device_node_parse(outitem)

        return out

    def needs_resubscription(self):
        now = time.time()
        return now - self.subscribe_time >= self.resubscription_timeout or now - self.last_subs_action >= self.last_subs_action_timeout

    def subs_action(self):
        self.last_subs_action = int(time.time())

    def get_reversed_mac(self):
        ba = bytearray(self.mac)
        ba.reverse()
        self.mac_reversed = bytes(ba)


class DeviceAllOne(DeviceUDP, ManTimerManager, IrManager):
    def __init__(self, hp=('', 0), mac='', root=None, timeout=DEFAULT_RESUBSCRIPTION_TIMEOUT, name='', sec1900=0, lsa_timeout=DEFAULT_RESUBSCRIPTION_STIMEOUT):
        DeviceUDP.__init__(self, hp=hp, mac=mac, root=root, timeout=timeout,
                           name=name, sec1900=sec1900, lsa_timeout=lsa_timeout)
        ManTimerManager.__init__(self, root)
        IrManager.__init__(self, hp, mac, root, name)

    def to_json(self):
        rv = DeviceUDP.to_json(self)
        rv.update(IrManager.to_json(self))
        rv.update(ManTimerManager.to_json(self))
        return rv

    @staticmethod
    def is_learnir_response(data):
        return len(data) >= 6 and data[4:6] == (LEARNIR_ID)

    @staticmethod
    def is_learnir_intermediate_response(data):
        return data[2:4] == LEARNIR_LEN

    @staticmethod
    def is_emitir_response(data):
        return len(data) >= 6 and data[4:6] == (EMITIR_ID)

    def get_action_payload(self, action):
        if isinstance(action, ActionLearnir):
            if len(action.irdata):
                return MAGIC + LEARNIR_LEN + LEARNIR_ID + self.mac + PADDING_1\
                    + LEARNIR_2
        elif isinstance(action, ActionEmitir):
            if len(action.irdata):
                irc = action.irdata[0]
                plen = struct.pack('>H', len(irc) + 26)
                ilen = struct.pack('<H', len(irc))
                rnd = struct.pack('<H', random.randint(0, 65535))
                return MAGIC + plen + EMITIR_ID + self.mac + PADDING_1\
                    + EMITIR_2 + rnd + ilen + irc
        else:
            return DeviceUDP.get_action_payload(self, action)

    def process_response(self, hp, action, data, **kwargs):
        if isinstance(action, ActionLearnir) and self.is_my_mac(data) and DeviceAllOne.is_learnir_response(data):
            if DeviceAllOne.is_learnir_intermediate_response(data):
                return dict(rv=RV_DATA_WAIT, data=None)
            else:
                return dict(rv=1, data={'irc': data[26:], 'attrs': {}})
        elif isinstance(action, ActionEmitir) and self.is_my_mac(data) and DeviceAllOne.is_emitir_response(data):
            return dict(rv=1, data=None)
        else:
            return DeviceUDP.process_response(self, hp, action, data, **kwargs)

    def copy_extra_from(self, already_saved_device):
        DeviceUDP.copy_extra_from(self, already_saved_device)
        IrManager.copy_extra_from(self, already_saved_device)
        ManTimerManager.copy_extra_from(self, already_saved_device)

    def xml_element(self, root, flag=0):
        el = IrManager.xml_element(self, root, flag)
        ManTimerManager.xml_element(self, el, flag)
        return el

    def on_stop(self):
        IrManager.on_stop(self)
        ManTimerManager.on_stop(self)

    def get_arduraw(self, remote, irdata):
        irenc = list(struct.unpack_from(
            '<' + ('H' * ((len(irdata[0]) - 16) / 2)), irdata[0], 16))
        return {'key': irdata[1], 'remote': remote, 'a': irenc}

    def get_from_arduraw(self, msg):
        tpl = (0, 0, len(msg['a']) * 2 + 16, 0, 0, 0, 0, len(msg['a']) * 2)
        out = struct.pack('<' + ('H' * len(tpl)), *tpl)
        out += struct.pack('<' + ('H' * len(msg['a'])), *tuple(msg['a']))
        return (out, msg['key'], {})


class DeviceS20(DeviceUDP):
    def __init__(self, hp=('', 0), mac='', root=None, timeout=DEFAULT_RESUBSCRIPTION_TIMEOUT, name='', sec1900=0, lsa_timeout=DEFAULT_RESUBSCRIPTION_STIMEOUT):
        DeviceUDP.__init__(self, hp, mac, root, timeout,
                           name, sec1900, lsa_timeout)
        self.state = ""
        # if root is None:
        #    self.state = -1
        # else:
        #    self.state = int(root.attributes['state'].value)

    def process_asynch_state_change(self, state, device_connected=None):
        self.state = b2s(state)

    def parse_action_timer_args(self, args):
        return None if args[0] is None else int(args[0])

    def mqtt_publish_onfinish(self, action, retval):
        if isinstance(action, (ActionSubscribe, ActionNotifystate)):
            return self.mqtt_power_state()
        else:
            return DeviceUDP.mqtt_publish_onfinish(self, action, retval)

    def state_value_conv(self, s):
        return "1" if s != "0" else "0"

    def do_presend_operations(self, action, actionexec):
        if isinstance(action, ActionSettable3):
            if self.timers is None:
                act = ActionViewtable3(self)
                act.m_device = False
                actionexec.insert_action(act, 0)
                return 0
        return DeviceUDP.do_presend_operations(self, action, actionexec)

    def do_postsend_operations(self, action, actionexec):
        # quando devo solo ottenere lo stato basta il subscribe che si fa in presend
        if isinstance(action, ActionStatechange) and action.newstate != Device.GET_STATE_ACTION:
            actionexec.insert_action(ActionSubscribe(self), 1)
        else:
            DeviceUDP.do_postsend_operations(self, action, actionexec)

    def copy_extra_from(self, already_saved_device):
        DeviceUDP.copy_extra_from(self, already_saved_device)
        self.state = already_saved_device.state

    def mqtt_on_message(self, client, userdata, msg):
        DeviceUDP.mqtt_on_message(self, client, userdata, msg)
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
        except:  # noqa: E722
            _LOGGER.warning(f"{traceback.format_exc()}")

    def xml_element(self, root, flag=0):
        el = DeviceUDP.xml_element(self, root, flag)
        el.set('state', str(self.state))
        return el

    def process_subscribe(self, data):
        DeviceUDP.process_subscribe(self, data)
        self.state = "0" if data[-1:] == b'\x00' else "1"

    def to_json(self):
        rv = DeviceUDP.to_json(self)
        rv.update({'state': self.state})
        return rv

    def mqtt_power_state(self):
        lst = [dict(topic=self.mqtt_topic("stat", "power"), msg="-1" if self.state != "0" and self.state != "1" else str(self.state), options=dict(retain=True))]
        if self.homeassistant:
            cmd = dict(
                availability_topic=f'stat/{self.__class__.__name__[6:].lower()}/{self.name}/power',
                command_topic=f'cmnd/{self.__class__.__name__[6:].lower()}/{self.name}/state',
                payload_not_available='-1',
                payload_off='0',
                payload_on='1',
                state_off='0',
                state_on='1',
                unique_id=tohexs(self.mac),
                name=self.name
            )
            lst.append(dict(topic=f'{self.homeassistant}/switch/{self.name}/config', msg=json.dumps(cmd), options=dict(retain=True)))
        return lst

    def mqtt_publish_onstart(self):
        return self.mqtt_power_state()
