import logging
import re
import struct
import time
import traceback
from xml.dom import minidom
from xml.etree.ElementTree import SubElement
from xml.sax.saxutils import escape

import requests

import upnpclient
from action import ActionEmitir, ActionGetstate
from device import Device
from device.irmanager import IrManager
from device.mantimermanager import ManTimerManager
from devicesamsungctl import DeviceSamsungCtl
from dictionary import DICTIONARY
from util import b2s, init_logger, upar

_LOGGER = init_logger(__name__, level=logging.DEBUG)


class DeviceUpnp(Device):

    @staticmethod
    def correct_upnp_name(name):
        return name.replace('/', ' ').\
            replace('\\', ' ').\
            replace('-', ' ').\
            replace('_', ' ').\
            replace('[', '').\
            replace(']', ' ').\
            replace('(', ' ').\
            replace(')', ' ')

    def __init__(self, hp=('', 0), mac='', root=None, name='', location='', deviceobj=None):
        Device.__init__(self, hp, mac, root, name)
        self.upnp_obj = deviceobj
        self.offt = -1
        if root is None:
            self.upnp_location = location
        else:
            self.upnp_location = root.attributes['upnp_location'].value

    def init_device(self):
        if self.upnp_obj is None:
            try:
                self.upnp_obj = upnpclient.Device(
                    self.upnp_location, self.name)
            except: # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")
                self.upnp_obj = None
        return self.upnp_obj

    def to_dict(self):
        rv = Device.to_dict(self)
        rv.update({'upnp_location': self.upnp_location})
        return rv

    def copy_extra_from(self, already_saved_device):
        Device.copy_extra_from(self, already_saved_device)
        self.upnp_location = already_saved_device.upnp_location

    @staticmethod
    def get_name(d):
        if len(d.friendly_name):
            rv = d.friendly_name
        elif len(d.model_name):
            rv = d.model_name
        elif len(d.model_description):
            rv = d.model_description
        else:
            rv = d.location
        return DeviceUpnp.correct_upnp_name(rv)

    @staticmethod
    def discovery(timeout=5):
        out = {}
        try:
            _LOGGER.info("Searching upnp devices")
            devs = upnpclient.discover(timeout=5)
            _LOGGER.info("Found "+str(len(devs))+" upnp devices")
            rc = {"RenderingControl": DeviceUpnpIRRC,
                  "MainTVAgent2": DeviceUpnpIRTA2}
            for d in devs:
                u = upar(d.location)
                for k, v in rc.items():
                    if k in d.service_map:
                        _LOGGER.info("Found "+k+" at "+d.location)
                        hp = (u.hostname, u.port)
                        m = '{}:{}:'.format(*hp)+k
                        out[m] = v(hp=hp,
                                   mac=m,
                                   name='',
                                   location=d.location,
                                   deviceobj=d)
        except: # noqa: E722
            _LOGGER.warning(f"{traceback.format_exc()}")
        return out


class ContextException(Exception):
    """An Exception class with context attached to it, so a caller can catch a
    (subclass of) ContextException, add some context with the exception's
    add_context method, and rethrow it to another callee who might again add
    information."""

    def __init__(self, msg, context=[]):
        self.msg = msg
        self.context = list(context)

    def __str__(self):
        if self.context:
            return '%s [context: %s]' % (self.msg, '; '.join(self.context))
        else:
            return self.msg

    def add_context(self, context):
        self.context.append(context)


class ParseException(ContextException):
    """An Exception for when something went wrong parsing the channel list."""
    pass


def _getint(buf, offset):
    """Helper function to extract a 16-bit little-endian unsigned from a char
    buffer 'buf' at offset 'offset'..'offset'+2."""
    x = struct.unpack('<H', buf[offset:offset+2])
    return x[0]


class Channel(object):
    """Class representing a Channel from the TV's channel list."""

    def __init__(self, from_dat):
        """Constructs the Channel object from a binary channel list chunk."""
        if isinstance(from_dat, minidom.Node):
            self._parse_xml(from_dat)
        else:
            self._parse_dat(from_dat)

    def _parse_xml(self, root):
        try:
            self.ch_type = root.getElementsByTagName(
                'ChType')[0].childNodes[0].nodeValue
            self.major_ch = root.getElementsByTagName(
                'MajorCh')[0].childNodes[0].nodeValue
            self.minor_ch = root.getElementsByTagName(
                'MinorCh')[0].childNodes[0].nodeValue
            self.ptc = root.getElementsByTagName(
                'PTC')[0].childNodes[0].nodeValue
            self.prog_num = root.getElementsByTagName(
                'ProgNum')[0].childNodes[0].nodeValue
            self.dispno = self.major_ch
            self.title = ''
        except: # noqa: E722
            raise ParseException("Wrong XML document")

    def _parse_dat(self, buf):
        """Parses the binary data from a channel list chunk and initilizes the
        member variables."""

        # Each entry consists of (all integers are 16-bit little-endian unsigned):
        #   [2 bytes int] Type of the channel. I've only seen 3 and 4, meaning
        #                 CDTV (Cable Digital TV, I guess) or CATV (Cable Analog
        #                 TV) respectively as argument for <ChType>
        #   [2 bytes int] Major channel (<MajorCh>)
        #   [2 bytes int] Minor channel (<MinorCh>)
        #   [2 bytes int] PTC (Physical Transmission Channel?), <PTC>
        #   [2 bytes int] Program Number (in the mux'ed MPEG or so?), <ProgNum>
        #   [2 bytes int] They've always been 0xffff for me, so I'm just assuming
        #                 they have to be :)
        #   [4 bytes string, \0-padded] The (usually 3-digit, for me) channel number
        #                               that's displayed (and which you can enter), in ASCII
        #   [2 bytes int] Length of the channel title
        #   [106 bytes string, \0-padded] The channel title, in UTF-8 (wow)

        t = _getint(buf, 0)
        if t == 4:
            self.ch_type = 'CDTV'
        elif t == 3:
            self.ch_type = 'CATV'
        elif t == 2:
            self.ch_type = 'DTV'
        else:
            raise ParseException('Unknown channel type %d' % t)

        self.major_ch = _getint(buf, 2)
        self.minor_ch = _getint(buf, 4)
        self.ptc = _getint(buf, 6)
        self.prog_num = _getint(buf, 8)

        if _getint(buf, 10) != 0xffff:
            raise ParseException(
                'reserved field mismatch (%04x)' % _getint(buf, 10))

        self.dispno = b2s(buf[12:16].rstrip(b'\x00'))

        title_len = _getint(buf, 22)
        self.title = buf[24:24+title_len].decode('utf-8')

    def display_string(self):
        """Returns a unicode display string, since both __repr__ and __str__ convert it
        to ascii."""

        return u'[%s] % 4s %s' % (self.ch_type, self.dispno, self.title)

    def __repr__(self):
        # return self.as_xml
        return '<Channel %s %s ChType=%s MajorCh=%d MinorCh=%d PTC=%d ProgNum=%d>' % \
            (self.dispno, repr(self.title), self.ch_type, self.major_ch, self.minor_ch, self.ptc,
             self.prog_num)

    @property
    def as_xml(self):
        """The channel list as XML representation for SetMainTVChannel."""

        return ('<?xml version="1.0" encoding="UTF-8" ?><Channel><ChType>%s</ChType><MajorCh>%d'
                '</MajorCh><MinorCh>%d</MinorCh><PTC>%d</PTC><ProgNum>%d</ProgNum></Channel>') % \
            (escape(self.ch_type), self.major_ch,
             self.minor_ch, self.ptc, self.prog_num)

    def as_params(self, chtype, sid):
        return {'ChannelListType': chtype, 'Channel': self.as_xml, 'SatelliteID': sid}


class Source(object):
    def __init__(self, root):
        name = root.getElementsByTagName('SourceType')
        sid = root.getElementsByTagName('ID')
        self.sname = name[0].childNodes[0].nodeValue
        self.sid = int(sid[0].childNodes[0].nodeValue)

    def as_params(self):
        return {'Source': self.sname, 'ID': self.sid, 'UiID': self.sid}


class DeviceUpnpIR(DeviceUpnp, IrManager, ManTimerManager):
    NUMBER_KEY = "1"
    SOURCE_KEY = "0"
    RC_KEY = "2"

    def __init__(self, hp=('', 0), mac='', root=None, name='', location='', deviceobj=None):
        DeviceUpnp.__init__(self, hp, mac, root, name, location, deviceobj)
        ManTimerManager.__init__(self, root)
        IrManager.__init__(self, hp, mac, root, name)
        self.a = None
        if root is not None and root.hasAttribute('remote_name'):
            self.remote_name = root.attributes['remote_name'].value
            self.ir_load = True
        else:
            self.ir_load = False
            self.remote_name = self.name
        self.offt = -1

    def ir_decode(self, irc):
        return irc

    def ir_encode(self, irc):
        return irc

    def get_action_payload(self, action):
        if isinstance(action, ActionGetstate):
            return 'a'
        elif isinstance(action, ActionEmitir):
            return action.irdata
        else:
            return DeviceUpnp.get_action_payload(self, action)

    def copy_extra_from(self, already_saved_device):
        DeviceUpnp.copy_extra_from(self, already_saved_device)
        IrManager.copy_extra_from(self, already_saved_device)
        ManTimerManager.copy_extra_from(self, already_saved_device)
        self.remote_name = already_saved_device.remote_name

    def xml_element(self, root, flag=0):
        el = IrManager.xml_element(self, root, flag)
        ManTimerManager.xml_element(self, el, flag)
        return el

    def on_stop(self):
        IrManager.on_stop(self)
        ManTimerManager.on_stop(self)

    def to_json(self):
        rv = DeviceUpnp.to_json(self)
        rv.update(IrManager.to_json(self))
        rv.update(ManTimerManager.to_json(self))
        return rv


class DeviceUpnpIRTA2(DeviceUpnpIR):
    def __init__(self, hp=('', 0), mac='', root=None, name='', location='', deviceobj=None):
        DeviceUpnpIR.__init__(self, hp, mac, root, name, location, deviceobj)
        self.channel_list_type = None
        self.channel_satellite_id = None
        self.channels = {}
        self.sources = {}
        self.samsungctl_dev_name = ''
        self.upnp_rc_dev_name = ''
        self.tv_source = "TV"
        self.upnp_rc_dev = None
        self.samsungctl_dev = None
        self.current_source = ''
        self.current_source_t = 0
        if root is not None:
            self.upnp_rc_dev_name = root.attributes['upnp_rc_dev_name'].value
            self.samsungctl_dev_name = root.attributes['samsungctl_dev_name'].value
            self.tv_source = root.attributes['tv_source'].value

        # _LOGGER.info("LOC "+self.upnp_drc_location)
        if deviceobj is not None:
            self.init_device()

    def connect_devices(self, device_map):
        DeviceUpnpIR.connect_devices(self, device_map)
        fill = False
        if self.samsungctl_dev_name in device_map:
            self.samsungctl_dev = device_map[self.samsungctl_dev_name]
            if self.upnp_obj is not None and self.samsungctl_dev.init_device():
                fill = True
        if self.upnp_rc_dev_name in device_map:
            self.upnp_rc_dev = device_map[self.upnp_rc_dev_name]
            if self.upnp_obj is not None and self.upnp_rc_dev.init_device():
                fill = True
        if fill:
            self.fill_ir_list()

    def get_current_source(self):
        now = time.time()
        if not len(self.current_source) or now-self.current_source_t >= 10:
            try:
                vv = self.a["GetCurrentExternalSource"]()
                if 'Result' in vv and vv['Result'] == "OK":
                    rv = DeviceUpnp.correct_upnp_name(
                        vv['CurrentExternalSource'])
                    self.current_source_t = now
                else:
                    rv = ''
            except: # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")
                rv = ''
            self.current_source = rv
        return self.current_source

    def copy_extra_from(self, already_saved_device):
        DeviceUpnpIR.copy_extra_from(self, already_saved_device)
        self.samsungctl_dev_name = already_saved_device.samsungctl_dev_name
        self.upnp_rc_dev_name = already_saved_device.upnp_rc_dev_name
        self.tv_source = already_saved_device.tv_source

    def get_dir(self, rem, key):
        if self.init_device():
            if rem in self.dir:
                if key in self.dir[rem]:
                    pay = self.dir[rem][key]
                    tp = pay[2]["type"]
                    if tp == DeviceUpnpIR.SOURCE_KEY:
                        return self.dir[rem][key]
                # _LOGGER.info("JJJ "+key+" "+str(self.upnp_drc_dev.dir))
                if self.upnp_rc_dev and len(self.upnp_rc_dev.dir):
                    rv = self.upnp_rc_dev.get_dir(
                        next(iter(self.upnp_rc_dev.dir.keys())), key)
                    if rv:
                        return rv
                mo = re.search("^([0-9]+)$", key)
                if mo is not None:
                    if (self.samsungctl_dev is not None and self.get_current_source() == self.tv_source) or\
                            self.samsungctl_dev is None:
                        return (key, '', {"type": DeviceUpnpIR.NUMBER_KEY})
                if self.samsungctl_dev and len(self.samsungctl_dev.dir):
                    rv = self.samsungctl_dev.get_dir(
                        next(iter(self.samsungctl_dev.dir.keys())), key)
                    if rv:
                        return rv
        return []

    def to_dict(self):
        rv = DeviceUpnpIR.to_dict(self)
        rv.update({'upnp_rc_dev_name': self.upnp_rc_dev_name})
        rv.update({'samsungctl_dev_name': self.samsungctl_dev_name})
        rv.update({'tv_source': self.tv_source})
        return rv

    def destroy_device(self):
        self.upnp_obj = None

    def init_device(self):
        if self.upnp_obj is None or self.a is None or len(self.dir) == 0 or len(self.sources) == 0:
            rv = DeviceUpnpIR.init_device(self)
            if rv:
                if self.upnp_rc_dev is not None:
                    self.upnp_rc_dev.init_device()
                if self.samsungctl_dev is not None:
                    self.samsungctl_dev.init_device()
                try:
                    self.a = rv.service_map['MainTVAgent2'].action_map
                    self.get_channels_list()
                    self.get_sources_list()
                    self.fill_ir_list()
                except: # noqa: E722
                    _LOGGER.warning(f"{traceback.format_exc()}")
                    self.destroy_device()

        return self.upnp_obj

    def fill_ir_list(self):
        if not self.ir_load:
            dc = dict()
            for i in range(10):
                dc[str(i)] = (str(i), str(i), {
                    "type": DeviceUpnpIR.NUMBER_KEY})
            for s in self.sources.keys():
                dc[s] = (s, s, {"type": DeviceUpnpIR.SOURCE_KEY})
            k = list(dc.keys())
            for s in k:
                if s in DICTIONARY:
                    irnma = DICTIONARY[s]
                    for x in irnma:
                        if len(x):
                            dc.update({x: (s, '', dc[s][2])})
            if self.samsungctl_dev:
                _, v = next(iter(self.samsungctl_dev.dir.items()))
                dc.update(v)
            if self.upnp_rc_dev:
                _, v = next(iter(self.upnp_rc_dev.dir.items()))
                for k in v.keys():
                    mo = re.search("^([^\\+]+)(\\+?)", k)
                    if mo is not None:
                        if len(mo.group(2)):
                            try:
                                del dc[mo.group(1)+"-"]
                            except: # noqa: E722
                                pass
                dc.update(v)

            self.dir[self.remote_name] = dc

    def get_channels_list(self):
        if not len(self.channels):
            try:
                res = self.a["GetChannelListURL"]()
                self.channel_list_type = res["ChannelListType"]
                self.channel_satellite_id = 0 if res["SatelliteID"] is None else res["SatelliteID"]
                r = requests.get(res['ChannelListURL'])
                webContent = r.content
                self.channels = DeviceUpnpIRTA2._parse_channel_list(webContent)
            except: # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")
                self.channels = {}

    def send_action(self, actionexec, action, pay):
        rv = None
        outstate = None
        if isinstance(action, ActionEmitir):
            try:
                tp = pay[2]["type"]
                if tp == DeviceUpnpIR.RC_KEY:
                    if self.upnp_rc_dev:
                        pay[2]["mac"] = self.mac
                        return self.upnp_rc_dev.send_action(actionexec, action, pay)
                if tp == DeviceSamsungCtl.CTL_KEY:
                    if self.samsungctl_dev:
                        pay[2]["mac"] = self.mac
                        return self.samsungctl_dev.send_action(actionexec, action, pay)
                elif tp == DeviceUpnpIR.NUMBER_KEY:
                    if self.init_device():
                        if pay[0] in self.channels:
                            vv = self.a["SetMainTVChannel"](
                                **self.channels[pay[0]].as_params(self.channel_list_type, self.channel_satellite_id))
                            if 'Result' in vv and vv['Result'] == "OK":
                                rv = 1
                            else:
                                _LOGGER.info("Change channel rv "+str(vv))
                                rv = 127
                        else:
                            rv = 255
                elif tp == DeviceUpnpIR.SOURCE_KEY:
                    if self.init_device():
                        if pay[0] in self.sources:
                            vv = self.a["SetMainTVSource"](
                                **self.sources[pay[0]].as_params())
                            if 'Result' in vv and vv['Result'] == "OK":
                                rv = 1
                            else:
                                _LOGGER.info("Change source rv "+str(vv))
                                rv = 127
                        else:
                            rv = 255
            except: # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")
        elif isinstance(action, ActionGetstate):
            outstate = dict()
            if self.init_device():
                rv = 1
                try:
                    vv = self.a["GetCurrentMainTVChannel"]()
                    if 'Result' in vv and vv['Result'] == "OK":
                        xmldoc = minidom.parseString(vv['CurrentChannel'])
                        c = Channel(xmldoc)
                        outstate['channel'] = c.major_ch
                    else:
                        rv = 32
                except: # noqa: E722
                    _LOGGER.warning(f"{traceback.format_exc()}")
                    rv = 2
                vv = self.get_current_source()
                if len(vv):
                    outstate['source'] = vv
                else:
                    rv |= 4

                if self.upnp_rc_dev:
                    rv2 = self.upnp_rc_dev.get_states()
                    outstate.update(self.upnp_rc_dev.states)
                    if rv2 is None:
                        rv |= 8
                    elif rv2 > 0:
                        rv |= 16
        if rv is None or rv != 1:
            self.destroy_device()
        return action.exec_handler(rv, outstate) if isinstance(action, (ActionEmitir, ActionGetstate))\
            else DeviceUpnpIR.send_action(self, actionexec, action, pay)

    def get_sources_list(self):
        if not len(self.sources):
            try:
                res = self.a["GetSourceList"]()
                xmldoc = minidom.parseString(res['SourceList'])
                sources = xmldoc.getElementsByTagName('Source')
                self.sources = dict()
                for s in sources:
                    src = Source(s)
                    p = DeviceUpnp.correct_upnp_name(src.sname)
                    if p != 'av' and p != 'AV':
                        self.sources[DeviceUpnp.correct_upnp_name(
                            src.sname)] = src
            except: # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")
                self.sources = None

    @staticmethod
    def _parse_channel_list(channel_list):
        """Splits the binary channel list into channel entry fields and returns a list of Channels."""

        # The channel list is binary file with a 4-byte header, containing 2 unknown bytes and
        # 2 bytes for the channel count, which must be len(list)-4/124, as each following channel
        # is 124 bytes each. See Channel._parse_dat for how each entry is constructed.

        if len(channel_list) < 128:
            raise ParseException(('channel list is smaller than it has to be for at least '
                                  'one channel (%d bytes (actual) vs. 128 bytes' % len(channel_list)),
                                 ('Channel list: %s' % repr(channel_list)))

        if (len(channel_list)-4) % 124 != 0:
            raise ParseException(('channel list\'s size (%d) minus 128 (header) is not a multiple of '
                                  '124 bytes' % len(channel_list)),
                                 ('Channel list: %s' % repr(channel_list)))

        actual_channel_list_len = (len(channel_list)-4) / 124
        expected_channel_list_len = _getint(channel_list, 2)
        if actual_channel_list_len != expected_channel_list_len:
            raise ParseException(('Actual channel list length ((%d-4)/124=%d) does not equal expected '
                                  'channel list length (%d) as defined in header' % (len(channel_list),
                                                                                     actual_channel_list_len, expected_channel_list_len))
                                 ('Channel list: %s' % repr(channel_list)))

        channels = {}
        pos = 4
        while pos < len(channel_list):
            chunk = channel_list[pos:pos+124]
            try:
                ch = Channel(chunk)
                channels[ch.dispno] = ch
            except ParseException as pe:
                pe.add_context('chunk starting at %d: %s' % (pos, repr(chunk)))
                raise pe

            pos += 124

        _LOGGER.info('Parsed %d channels' % len(channels))
        return channels


class DeviceUpnpIRRC(DeviceUpnpIR):
    def __init__(self, hp=('', 0), mac='', root=None, name='', location='', deviceobj=None):
        DeviceUpnpIR.__init__(self, hp, mac, root, name, location, deviceobj)
        self.params = ["Contrast", "Brightness", "Volume", "Mute", "Sharpness"]
        self.state_init = False
        self.states = dict.fromkeys(self.params)
        if deviceobj is not None:
            self.init_device()

    def states_xml_device_node_write(self, el):
        targets = SubElement(el, "states")
        for k, v in self.states.items():
            if v is not None:
                stel = SubElement(targets, "state", {'value': str(v)})
                stel.text = k

    def xml_element(self, root, flag=0):
        el = DeviceUpnpIR.xml_element(self, root, flag)
        self.states_xml_device_node_write(el)
        return el

    def fill_ir_list(self):
        if not self.ir_load:
            dc = dict()
            for s, v in self.states.items():
                if v is not None:
                    s = s.lower()
                    if s == "mute":
                        dc[s] = (s, s, {"type": DeviceUpnpIR.RC_KEY})
                    else:
                        dc[s+"+"] = (s+"+", s+"+",
                                     {"type": DeviceUpnpIR.RC_KEY})
                        for x in range(0, 104, 5):
                            m = s+str(x)+"+"
                            dc[m] = (m, m, {"type": DeviceUpnpIR.RC_KEY})

            k = list(dc.keys())
            for s in k:
                if s in DICTIONARY:
                    irnma = DICTIONARY[s]
                    for x in irnma:
                        if len(x):
                            dc.update({x: (s, '', dc[s][2])})
            self.dir[self.remote_name] = dc

    def get_dir(self, rem, key):
        if self.init_device():
            # _LOGGER.info("KKK "+key+" "+rem+str(self.dir))
            if rem in self.dir:
                # _LOGGER.info("UUU "+key+" "+rem)
                mo = re.search("^([^0-9\\+\\-]+)([0-9]*)([\\+\\-]?)$", key)
                if mo is not None:
                    fp = mo.group(1)+("+"*len(mo.group(3)))
                    if fp in self.dir[rem]:
                        p = mo.group(2)
                        return (key, int(p) if len(p) else 1, {"type": DeviceUpnpIR.RC_KEY})
                mo = re.search("^([^#\\+\\-]+)([\\+\\-]?)#([0-9]+)$", key)
                # _LOGGER.info("DDDD "+key+" "+rem)
                if mo is not None:
                    fp = mo.group(1)+("+"*len(mo.group(2)))
                    if fp in self.dir[rem]:
                        return (fp, int(mo.group(3)), {"type": DeviceUpnpIR.RC_KEY})
        return []

    def send_action(self, actionexec, action, pay):
        cmd = {}
        dt = None
        if isinstance(action, ActionEmitir):
            tp = pay[2]["type"]
            if tp != DeviceUpnpIR.RC_KEY:
                dt = 1023
            else:
                mo = re.search("^([^0-9\\+]+)", pay[0])
                k = mo.group(1)
                k = k.capitalize()
                v = pay[1]
                if k not in self.states or self.set_state(k, v) is None:
                    dt = None
                elif self.states[k] != v and k != "Mute":
                    dt = 511
                else:
                    dt = 0
                    cmd[k] = v
        elif isinstance(action, ActionGetstate):
            dt = self.get_states()
            cmd.update(self.states)
        if dt is not None:
            dt += 1
        return action.exec_handler(dt, cmd) if isinstance(action, (ActionGetstate, ActionEmitir))\
            else DeviceUpnpIR.send_action(self, actionexec, action, pay)

    def destroy_device(self):
        self.upnp_obj = None

    def init_device(self):
        if self.upnp_obj is None or self.a is None:
            rv = DeviceUpnpIR.init_device(self)
            if rv:
                try:
                    self.a = rv.service_map['RenderingControl'].action_map
                    self.states = dict.fromkeys(self.params)
                    self.state_init = False
                    self.get_states()
                except: # noqa: E722
                    _LOGGER.warning(f"{traceback.format_exc()}")
                    self.destroy_device()
        if self.upnp_obj and self.a and len(self.dir) == 0 and self.state_init:
            self.fill_ir_list()

        return self.upnp_obj

    def set_state(self, k, val):
        if self.init_device():
            try:
                if "Set"+k in self.a:
                    if k == "Mute":
                        self.get_states([k])
                        val = 0 if self.states[k] else 1
                    a = self.a['Set'+k]
                    p = {'InstanceID': 0, 'Channel': 'Master'}
                    p[a.argsdef_in[2][0]] = str(val)
                    out = a(**p)
                    self.get_states([k])
                    _LOGGER.info("Calling method upnp "+k+" out "+str(out))
                    return self.states[k]
            except: # noqa: E722
                _LOGGER.info("Action Set"+k+" args "+str(self.a['Set'+k].argsdef_in))
                self.destroy_device()
                _LOGGER.warning(f"{traceback.format_exc()}")
        return None

    def get_states(self, what=None):
        rv = 0
        if self.init_device():
            if what is None:
                what = list(self.states.keys())
            for k in what:
                try:
                    st = self.a['Get'+k](InstanceID=0, Channel='Master')
                    if len(st) > 1 and 'Current'+k in st:
                        st = st['Current'+k]
                    elif len(st):
                        st = next(iter(st.values()))
                    else:
                        rv += 1
                        st = None
                    self.states[k] = st
                    if st is not None:
                        if rv < 500:
                            rv += 500
                            self.state_init = True
                    _LOGGER.info(self.name+" Upnp State "+k+" = "+str(st))
                except: # noqa: E722
                    _LOGGER.warning(f"{traceback.format_exc()}")
        if rv >= 500:
            return rv-500
        else:
            return None
