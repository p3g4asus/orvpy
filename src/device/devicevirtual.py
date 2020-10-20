import logging
import traceback
from xml.etree.ElementTree import SubElement

import event
from action import ActionStatechange
from device import Device
from util import init_logger

_LOGGER = init_logger(__name__, level=logging.DEBUG)


class DeviceVirtual(Device):
    def target_xml_device_node_parse(self, root, lst):
        d433s = root.getElementsByTagName('target')
        for d433 in d433s:
            try:
                lst.append(d433.childNodes[0].nodeValue)
            except: # noqa: E722
                traceback.print_exc()
                pass

    def get_last_target_from_state(self):
        d2 = []
        if self.state in self.states_map:
            for t in self.states_map[self.state]:
                d2.append(t["d"])
        return d2

    def get_action_payload(self, action):
        if isinstance(action, ActionStatechange):
            return self.state_value_conv(action.newstate)
        else:
            return Device.get_action_payload(self, action)

    def do_presend_operations(self, action, actionexec):
        if isinstance(action, ActionStatechange):
            if action.newstate in self.states_map:
                i = 0
                for act in self.states_map[action.newstate]:
                    realdev = self.get_real_dev(act)
                    for d in realdev:
                        randid = 8950+i
                        i += 1
                        actcmd = "%d statechange %s %s" % (randid, d, act["s"])
                        _LOGGER.info("Scheduling "+actcmd)
                        event.EventManager.fire(eventname='ExtInsertAction',
                                                cmdline=actcmd, action=None)
                self.state = action.newstate
                return 1
            else:
                return None
        return Device.do_presend_operations(self, action, actionexec)

    def get_real_dev(self, el):
        d = el['d']
        d2 = [el['d']]
        if d == "$lasttargetdef":
            if len(self.state):
                d2 = self.get_last_target_from_state()
            else:
                d2 = self.target
        elif d == "$lasttargetnone":
            if len(self.state):
                d2 = self.get_last_target_from_state()
        _LOGGER.info("D is "+d+" Real Dev is "+str(d2))
        return d2

    def states_xml_device_node_parse(self, root, lst, nicks):
        d433s = root.getElementsByTagName('state')
        for d433 in d433s:
            try:
                nm = d433.attributes['value'].value
                try:
                    nicks[nm] = d433.attributes['nick'].value
                except: # noqa: E722
                    nicks[nm] = nm
                acts = d433.getElementsByTagName('action')
                lst[nm] = []
                devact = lst[nm]
                for act in acts:
                    try:
                        dev = act.attributes['device'].value
                        stateact = act.childNodes[0].nodeValue
                        devact.append({
                            "d": dev,
                            "s": stateact})
                    except: # noqa: E722
                        traceback.print_exc()
            except: # noqa: E722
                traceback.print_exc()
                pass

    def states_xml_device_node_write(self, el, lst, nicks):
        states = SubElement(el, "states")
        for stname, acts in lst.items():
            stel = SubElement(states, "state", {
                              "value": stname, "nick": nicks[stname]})
            for a in acts:
                actel = SubElement(stel, "action", {"device": a["d"]})
                actel.text = a["s"]

    def target_xml_device_node_write(self, el, lst):
        targets = SubElement(el, "targets")
        for t in lst:
            stel = SubElement(targets, "target")
            stel.text = t

    def xml_element(self, root, flag=0):
        el = Device.xml_element(self, root, flag)
        self.target_xml_device_node_write(el, self.target)
        self.states_xml_device_node_write(
            el, self.states_map, self.states_nick_map)
        return el

    def __init__(self, hp=('', 0), mac='', root=None, name=''):
        Device.__init__(self, hp, mac, root, name)
        self.state = ''
        self.states_map = {}
        self.states_nick_map = {}
        self.target = []
        if root is not None:
            self.states_xml_device_node_parse(
                root, self.states_map, self.states_nick_map)
            self.target_xml_device_node_parse(root, self.target)

    def to_json(self):
        rv = Device.to_json(self)
        rv.update({
            'states': self.states_map,
            'nicks': self.states_nick_map,
            'state': self.state})
        return rv

    def send_action(self, actionexec, action, state):
        if isinstance(action, ActionStatechange):
            return action.exec_handler(1, None)
        else:
            return Device.send_action(self, actionexec, action, state)
