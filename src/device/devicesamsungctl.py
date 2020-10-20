import logging
import time
import traceback

import samsungctl
from action import ActionEmitir
from device import Device
from device.irmanager import IrManager
from device.mantimermanager import ManTimerManager
from device.samsung_mappings import samsung_mappings
from util import init_logger

_LOGGER = init_logger(__name__, level=logging.DEBUG)


class DeviceSamsungCtl(IrManager, ManTimerManager):
    CTL_KEY = "ctl"

    def __init__(self, hp=('', 0), mac='', root=None, name='', conf=''):
        Device.__init__(self, hp, name, root, name)
        ManTimerManager.__init__(self, root)
        IrManager.__init__(self, hp, mac, root, name)
        self.remote = None
        self.last_init = 0
        self.fill_ir_list()
        if root is None:
            self.conffile = conf
        else:
            self.conffile = root.attributes['conffile'].value
        self.config = None
        self.offt = -1
        self.init_device()

    def ir_decode(self, irc):
        return irc

    def get_action_payload(self, action):
        if isinstance(action, ActionEmitir):
            return action.irdata
        else:
            return IrManager.get_action_payload(self, action)

    def fill_ir_list(self):
        dc = {k: (v, k, {'type': DeviceSamsungCtl.CTL_KEY})
              for k, v in samsung_mappings.items()}
        k = list(dc.keys())
        for s in k:
            if s in Device.dictionary:
                irnma = Device.dictionary[s]
                for x in irnma:
                    if len(x):
                        dc.update({x: (s, '', dc[s][2])})
        self.dir[self.name] = dc

    def destroy_device(self):
        if self.remote is not None:
            try:
                self.remote.close()
            except: # noqa: E722
                pass
            self.remote = None

    def init_device(self):
        now = time.time()

        if self.remote is None or now-self.last_init >= 60:
            try:
                self.last_init = now
                self.destroy_device()
                if self.config is None:
                    cc = samsungctl.Config.load(self.conffile)
                    cc.log_level = samsungctl.Config.LOG_DEBUG
                    self.config = cc
                self.remote = samsungctl.Remote(self.config)
                if not self.remote.open():
                    self.destroy_device()
            except: # noqa: E722
                traceback.print_exc()
                self.destroy_device()

        return self.remote

    def ir_encode(self, irc):
        return irc

    def to_dict(self):
        rv = Device.to_dict(self)
        rv.update({'conffile': self.conffile})
        return rv

    def copy_extra_from(self, already_saved_device):
        Device.copy_extra_from(self, already_saved_device)
        IrManager.copy_extra_from(self, already_saved_device)
        ManTimerManager.copy_extra_from(self, already_saved_device)

    def xml_element(self, root, flag=0):
        el = IrManager.xml_element(self, root, flag)
        ManTimerManager.xml_element(self, el, flag)
        return el

    def on_stop(self):
        IrManager.on_stop(self)
        ManTimerManager.on_stop(self)

    def to_json(self):
        rv = Device.to_json(self)
        rv.update(IrManager.to_json(self))
        rv.update(ManTimerManager.to_json(self))
        return rv

    def send_action(self, actionexec, action, pay):
        if isinstance(action, ActionEmitir):
            try:
                if self.init_device():
                    _LOGGER.info(self.name+" sending "+pay[0])
                    if not self.remote.control(pay[0]):
                        rv = 5
                        self.destroy_device()
                    else:
                        rv = 1
            except: # noqa: E722
                traceback.print_exc()
                self.destroy_device()
                rv = None
            return action.exec_handler(rv, None)
        else:
            return IrManager.send_action(self, actionexec, action, pay)
