import logging
import time
import traceback

import broadlink
import lircbroadlink
from action import ActionEmitir, ActionLearnir
from device import Device
from device.irmanager import IrManager
from device.mantimermanager import ManTimerManager
from util import bfromhex, init_logger, tohexs

_LOGGER = init_logger(__name__, level=logging.DEBUG)


class DeviceRM(IrManager, ManTimerManager):

    def inner_init(self):
        try:
            self.inner = broadlink.rm(
                (self.host, self.port), bytearray(self.mac), 0x27c2)
            if not self.inner.auth():
                self.inner = None
        except: # noqa: E722
            traceback.print_exc()
            self.inner = None

    def get_action_payload(self, action):
        if isinstance(action, ActionLearnir):
            return action.irdata
        elif isinstance(action, ActionEmitir):
            return action.irdata
        else:
            return IrManager.get_action_payload(self, action)

    @staticmethod
    def discovery(actionexec, timeout, **kwargs):
        hosts = dict()
        dev3 = broadlink.discover(
            timeout=timeout, timeout2=actionexec.udpmanager.timeout if actionexec.udpmanager.timeout > 0 else None)
        for d in dev3:
            if d.auth():
                keyv = '{}:{}'.format(*d.host)
                hosts[keyv] = DeviceRM(
                    hp=d.host,
                    mac=str(d.mac),
                    root=None, name='', inner=d)
        return hosts

    def __init__(self, hp=('', 0), mac='', root=None, name='', inner=None):
        Device.__init__(self, hp, mac, root, name)
        ManTimerManager.__init__(self, root)
        IrManager.__init__(self, hp, mac, root, name)
        self.offt = -1
        self.inner = inner

    def get_arduraw(self, remote, irdata):
        return {'key': irdata[1], 'remote': remote, 'a': lircbroadlink.broadlink2lirc(irdata[0])}

    def get_from_arduraw(self, msg):
        return (lircbroadlink.lirc2broadlink(msg['a']), msg['key'], {})

    def send_action(self, actionexec, action, pay):
        if isinstance(action, (ActionEmitir, ActionLearnir)):
            if self.inner is None:
                self.inner_init()
                if self.inner is None:
                    return action.exec_handler(None, None)
            data = None
            timeout = action.get_timeout()
            if timeout is None or timeout < 0:
                timeout = actionexec.udpmanager.timeout
            if timeout < 0:
                timeout = None
            self.inner.timeout = timeout
            try:
                if isinstance(action, ActionLearnir):
                    response = self.inner.enter_learning()
                    if response is None:
                        rv = None
                    else:
                        rv = response[0x22] | (response[0x23] << 8)
                        time.sleep(self.inner.timeout)
                        data2 = self.inner.check_data()
                        if data2 is None or isinstance(data2, int):
                            data = {'irc': None, 'attrs': None}
                            rv = data2
                        else:
                            if data2[0:1] == b'\x26':
                                freq = 38000
                            elif data2[0:1] == b'\xb2':
                                freq = 433000000
                            elif data2[0:1] == b'\xd7':
                                freq = 315000000
                            else:
                                freq = 0
                            data = {'irc': data2, 'attrs': {'freq': freq}}
                else:
                    _LOGGER.info(f"S({self.inner.host[0]}:{self.inner.host[1]})-> {tohexs(pay[0])}")
                    response = self.inner.send_data(pay[0])
                    if response is None:
                        rv = None
                    else:
                        rv = response[0x22] | (response[0x23] << 8)
            except: # noqa: E722
                traceback.print_exc()
                rv = None
            if rv is None or rv != 0:
                # Forzo futura riconnessione
                _LOGGER.info("Blackbeam %s error: will try to reconnect" % self.name)
                self.inner = None
                if rv is not None:
                    rv += 600
            else:
                rv += 1
            return action.exec_handler(rv, data)
        else:
            return IrManager.send_action(self, actionexec, action, pay)

    def copy_extra_from(self, already_saved_device):
        savep = self.port
        IrManager.copy_extra_from(self, already_saved_device)
        ManTimerManager.copy_extra_from(self, already_saved_device)
        self.port = savep

    def to_dict(self):
        return IrManager.to_dict(self)

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
        return bfromhex(irc)

    def ir_encode(self, irc):
        return tohexs(irc)

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
