import json
import logging
import re
import threading
import traceback
from xml.etree.ElementTree import SubElement

import event
from action import (ActionBackup, ActionCreatesh, ActionEmitir,
                    ActionInsertKey, ActionIrask, ActionLearnir,
                    ActionStatechange)
from device import Device
from dictionary import DICTIONARY
from util import b2s, bfromhex, cmp_to_key, init_logger, tohexs

_LOGGER = init_logger(__name__, level=logging.DEBUG)


class IrManager(Device):
    def __init__(self, hp, mac, root, name, **kw):
        Device.__init__(self, hp, mac, root, name)
        self.d433 = {}
        self.dir = {}
        self.sh = {}
        self.emit_ir_delay = 1
        self.backupstate = 0
        self.backuptimer = None
        if root is not None:
            if root.hasAttribute('emit_delay'):
                try:
                    ed = float(root.attributes['emit_delay'].value)
                    if ed > 0:
                        self.emit_ir_delay = ed
                except:  # noqa: E722
                    pass
            self.ir_xml_device_node_parse(root, self.d433, "d433")
            self.ir_xml_device_node_parse(root, self.dir, "dir")
            self.sh_xml_device_node_parse(root, self.sh, "sh")

    def schedule_action(self, topic, convert, *args):
        event.EventManager.fire(eventname='ExtInsertAction', hp=(self.host, self.port), cmdline="",
                                action=ActionBackup(self, topic, convert))

    def send_action(self, actionexec, action, pay):
        if isinstance(action, ActionStatechange) and action.newstate != Device.GET_STATE_ACTION:
            return action.exec_handler(1, None)
        else:
            return Device.send_action(self, actionexec, action, pay)

    def do_presend_operations(self, action, actionexec):
        if isinstance(action, ActionStatechange) and action.newstate != Device.GET_STATE_ACTION:
            actionexec.insert_action(ActionEmitir(self, action.newstate), 0)
            return 1
        elif isinstance(action, ActionLearnir):
            if self.backupstate == 0 and action.asked < action.idx:
                action.asked += 1
                actionexec.insert_action(ActionIrask(
                    self, action.irname[action.asked]), 0)
                return 0
            else:
                return 1
        else:
            return Device.do_presend_operations(self, action, actionexec)

    def on_stop(self):
        Device.on_stop(self)
        if self.backuptimer:
            self.backuptimer.cancel()
            self.backuptimer = None

    def get_dir(self, rem, key):
        if rem in self.dir and key in self.dir[rem]:
            return self.dir[rem][key]
        else:
            return []

    def get_arduraw(self, remote, irdata):
        return {}

    def get_from_arduraw(self, a):
        return ()

    def nextbackup(self, topic, convert):
        lst2 = sorted(self.dir)
        idx = 0
        for nm in lst2:
            d433d = self.dir[nm]
            lst3 = sorted(d433d)
            for irnm in lst3:
                tpl = d433d[irnm]
                if len(tpl[1]):
                    idx += 1
                    if idx == self.backupstate + 1:
                        self.backupstate += 1
                        try:
                            attrib = {'remote': nm, 'key': tpl[1]}
                            if len(tpl) > 2:
                                attrib.update(self.ir_att_encode(tpl[2]))
                            attrib.update({"a": self.get_arduraw(nm, tpl)[
                                          'a'] if convert else self.ir_encode(tpl[0])})
                            self.backuptimer = threading.Timer(
                                2, self.schedule_action, [topic, convert])
                            self.backuptimer.start()
                            return [attrib]
                        except:  # noqa: E722
                            _LOGGER.warning(f"{traceback.format_exc()}")
        lst2 = sorted(self.sh, key=cmp_to_key(IrManager.sh_comparer))
        for nm in lst2:
            d433l = self.sh[nm]
            idx += 1
            if idx == self.backupstate + 1:
                self.backupstate += 1
                outl = [{'remote': '', 'key': '@' + nm}]
                for irc in d433l:
                    remkey = irc.split(':')
                    if len(remkey) == 1:
                        outl.append({'remote': '', 'key': remkey[0]})
                    else:
                        outl.append({'remote': remkey[0], 'key': remkey[1]})
                self.backuptimer = threading.Timer(
                    2, self.schedule_action, [topic, convert])
                self.backuptimer.start()
                return outl
        self.backupstate = 0
        self.backuptimer = None
        return []

    def to_dict(self):
        dct = Device.to_dict(self)
        # a = datetime(1900,1,1,0,0,0)
        # b = a + timedelta(seconds=self.sec1900)
        # b.strftime('%d/%m/%Y %H:%M:%S')
        dct.update({
            "emit_delay": str(self.emit_ir_delay)
        })
        return dct

    def to_json(self):
        rv = Device.to_json(self)
        rv.update({
            'sh': self.readable_sh(self.sh),
            'd433': self.readable_ir(self.d433),
            'dir': self.readable_ir(self.dir)
        })
        return rv

    def set_emit_delay(self, d):
        if d >= 0.3:
            self.emit_ir_delay = d

    def copy_extra_from(self, already_saved_device):
        Device.copy_extra_from(self, already_saved_device)
        self.d433 = already_saved_device.d433
        self.dir = already_saved_device.dir
        self.sh = already_saved_device.sh
        self.emit_ir_delay = already_saved_device.emit_ir_delay

    def readable_sh(self, lst):
        out = list()
        lst2 = sorted(lst, key=cmp_to_key(IrManager.sh_comparer))
        for nm in lst2:
            d433l = lst[nm]
            for ir in d433l:
                out.append("@" + nm + ":" + ir)
#         for nm,d433l in lst.copy().items():
#             for ir in d433l:
#                 out.append(nm+":"+ir)
        return out

    def readable_ir(self, lst):
        out = list()
        lst2 = sorted(lst)
        for nm in lst2:
            d433d = lst[nm]
            lst3 = sorted(d433d)
            for irnm in lst3:
                tpl = d433d[irnm]
                if len(tpl[1]):
                    out.append(nm + ":" + irnm + ":" + self.ir_encode(tpl[0]))
#         for nm,d433d in lst.copy().items():
#             for irnm,irc in d433d.copy().items():
#                 out.append(nm+":"+irnm+":"+irc.encode('hex'))
        return out

    def ir_decode(self, irc):
        return bfromhex(irc)

    def ir_encode(self, irc):
        return tohexs(irc)

    def ir_att_decode(self, irc):
        return irc

    def ir_att_encode(self, irc):
        return irc

    def ir_xml_device_node_parse(self, root, lst, dname):
        d433s = root.getElementsByTagName(dname)
        for d433 in d433s:
            try:
                irnm = ''
                irc = ''
                nm = d433.attributes['name'].value
                irs = d433.getElementsByTagName("ir")
                lst.update({nm: dict()})
                for ir in irs:
                    try:
                        irnm = ir.attributes['name'].value
                        irc = ir.childNodes[0].nodeValue
                        iratt = {}
                        for attname, attobject in ir.attributes.items():
                            if attname != 'name':
                                iratt[attname] = attobject
                        iratt = self.ir_att_decode(iratt)
                        if len(nm) and len(irc):
                            ircdec = self.ir_decode(irc)
                            lst[nm].update({irnm: (ircdec, irnm, iratt)})
                            if irnm in DICTIONARY:
                                irnma = DICTIONARY[irnm]
                                for x in irnma:
                                    if len(x):
                                        lst[nm].update(
                                            {x: (ircdec, '', iratt)})
                    except:  # noqa: E722
                        pass
            except:  # noqa: E722
                pass

    def sh_xml_device_node_parse(self, root, lst, dname):
        d433s = root.getElementsByTagName(dname)
        for d433 in d433s:
            try:
                irc = ''
                nm = d433.attributes['name'].value
                irs = d433.getElementsByTagName("ir")
                lst.update({nm: list()})
                for ir in irs:
                    try:
                        irc = ir.childNodes[0].nodeValue
                        if len(nm) and len(irc):
                            lst[nm].append(irc)
                    except:  # noqa: E722
                        pass
            except:  # noqa: E722
                pass

    def ir_xml_device_node_write(self, root, lst, dname):
        d433s = SubElement(root, dname + "s", {})
        lst2 = sorted(lst)
        for nm in lst2:
            d433 = SubElement(d433s, dname, {'name': nm})
            d433d = lst[nm]
            lst3 = sorted(d433d)
            for irnm in lst3:
                tpl = d433d[irnm]
                if len(tpl[1]):
                    attrib = {'name': tpl[1]}
                    if len(tpl) > 2:
                        attrib.update(self.ir_att_encode(tpl[2]))
                    ir = SubElement(d433, 'ir', attrib)
                    ir.text = self.ir_encode(tpl[0])
#         for nm,d433d in lst.copy().items():
#             d433 = SubElement(d433s, dname, {'name':nm})
#             for irnm,irc in d433d.copy().items():
#                 ir = SubElement(d433, 'ir', {'name':irnm})
#                 ir.text = irc.encode('hex')

    @staticmethod
    def sh_comparer(it1, it2):
        v1 = re.search("^[@]?([a-z])_([0-9]+)_(.*)", it1)
        v2 = re.search("^[@]?([a-z])_([0-9]+)_(.*)", it2)
        if v1 is not None and v2 is not None and v1.group(1) == v2.group(1):
            return int(v1.group(2)) - int(v2.group(2))
        elif it1 > it2:
            return 1
        elif it2 > it1:
            return -1
        else:
            return 0

    def sh_xml_device_node_write(self, root, lst, dname):
        d433s = SubElement(root, dname + "s", {})
        lst2 = sorted(lst, key=cmp_to_key(IrManager.sh_comparer))
        for nm in lst2:
            d433 = SubElement(d433s, dname, {'name': nm})
            d433l = lst[nm]
            for irc in d433l:
                ir = SubElement(d433, 'ir')
                ir.text = irc
#         for nm,d433l in lst.copy().items():
#             d433 = SubElement(d433s, dname, {'name':nm})
#             for irc in d433l:
#                 ir = SubElement(d433, 'ir')
#                 ir.text = irc

    def xml_element(self, root, flag=0):
        el = Device.xml_element(self, root, flag)
        self.ir_xml_device_node_write(el, self.d433, "d433")
        self.ir_xml_device_node_write(el, self.dir, "dir")
        self.sh_xml_device_node_write(el, self.sh, "sh")
        return el

    def mqtt_publish_dir(self, lst2, topic):
        lst = dict()
        for nm in lst2:
            d433d = lst2[nm]
            lst[nm] = list()
            for irnm in d433d:
                tpl = d433d[irnm]
                if len(tpl[1]):
                    lst[nm].append(tpl[1])
        return [dict(topic=self.mqtt_topic("stat", topic), msg=json.dumps(lst), options=dict(retain=True))]

    def mqtt_sanitize_name(self, nm):
        return nm.replace('+', 'plus').replace('-', 'minus').replace('!', '').replace(' ', '_').replace('.', '_')

    def mqtt_homeassistant_publish_dir(self, lst2, topic):
        lst = list()
        for nm in lst2:
            d433d = lst2[nm]
            for _, tpl in d433d.items():
                if len(tpl[1]):
                    irnm = self.mqtt_sanitize_name(tpl[1])
                    dct = [dict(key=tpl[1], remote=nm)]
                    cmd = dict(
                        command_topic=f'cmnd/{self.__class__.__name__[6:].lower()}/{self.name}/emit',
                        payload_on=json.dumps(dct),
                        name=f'{self.name}-{nm}:{tpl[1]}',
                        unique_id=f'{tohexs(self.mac)}_r_{nm}_k_{irnm}',
                    )
                    lst.append(dict(topic=f'{self.homeassistant}/scene/{topic}_{self.name}_{nm}_{irnm}/config', msg=json.dumps(cmd), options=dict(retain=True)))
        return lst

    def mqtt_publish_sh(self, lst2, topic):
        lst = lst2.keys()
        return [dict(topic=self.mqtt_topic("stat", topic), msg=json.dumps(lst), options=dict(retain=True))]

    def mqtt_homeassistant_publish_sh(self, lst2, topic):
        lst = []
        for nm, _ in lst2.items():
            irnm = self.mqtt_sanitize_name(nm)
            dct = [dict(key=f'@{nm}')]
            cmd = dict(
                command_topic=f'cmnd/{self.__class__.__name__[6:].lower()}/{self.name}/emit',
                payload_on=json.dumps(dct),
                unique_id=f'{tohexs(self.mac)}_s_{irnm}',
                name=f'{self.name}-{nm}'
            )
            lst.append(dict(topic=f'{self.homeassistant}/scene/{topic}_{self.name}_{irnm}/config', msg=json.dumps(cmd), options=dict(retain=True)))
        return lst

    def mqtt_publish_onstart(self):
        out = self.mqtt_publish_dir(self.dir, "remotes")
        out.extend(self.mqtt_publish_dir(self.d433, "r433s"))
        out.extend(self.mqtt_publish_sh(self.sh, "shortcuts"))
        if self.homeassistant:
            out.extend(self.mqtt_homeassistant_publish_dir(self.dir, "remotes"))
            out.extend(self.mqtt_homeassistant_publish_sh(self.sh, "sh"))
        return out

    def mqtt_on_message(self, client, userdata, msg):
        Device.mqtt_on_message(self, client, userdata, msg)
        sub = self.mqtt_sub(msg.topic)
        try:
            if sub == "backup":
                if len(msg.payload):
                    try:
                        out = json.loads(msg.payload)
                    except:  # noqa: E722
                        out = msg.payload
                    if isinstance(out, dict):
                        topic = out["topic"]
                        convert = 'convert' not in out or out['convert']
                    else:
                        topic = out
                        convert = False

                    event.EventManager.fire(eventname='ExtInsertAction', hp=(self.host, self.port), cmdline="",
                                            action=ActionBackup(self, topic, convert))
            elif sub == "learn" or sub == "emit":
                _LOGGER.info("topic " + msg.topic +
                             " [" + b2s(msg.payload) + "]")
                learnk = json.loads(msg.payload)
                keyall = []
                for d in learnk:
                    ksing = ('' if d['key'][0] == '@' or d['key'][0]
                             == '$' else (d["remote"] + ':')) + d["key"]
                    # _LOGGER.info("KSING "+ksing+" "+str(type(ksing)))
                    if 'a' in d and 'remote' in d and len(d['remote']):
                        event.EventManager.fire(eventname='ExtInsertAction', hp=(self.host, self.port), cmdline="",
                                                action=ActionInsertKey(self, d['remote'], d['key'], d['a'], {k: v for k, v in d.items() if k not in ['a', 'remote', 'key']}))
                    else:
                        keyall.append(ksing)
                if len(keyall):
                    tall = tuple(keyall)
                    if sub == "learn":
                        if keyall[0][0] == '@':
                            tall = tuple(keyall[1:])
                            action = ActionCreatesh(self, keyall[0][1:], *tall)
                        else:
                            action = ActionLearnir(self, *tall)
                    else:
                        action = ActionEmitir(self, *tall)
                    event.EventManager.fire(eventname='ExtInsertAction', hp=(self.host, self.port), cmdline="",
                                            action=action)
        except:  # noqa: E722
            _LOGGER.warning(f"{traceback.format_exc()}")
