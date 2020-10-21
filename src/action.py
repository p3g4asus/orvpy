'''
Created on 01 gen 2016

@author: Matteo
'''
import json
import logging
import re
import sys
import time
import traceback
from datetime import datetime, timedelta

import event
from dictionary import DICTIONARY
from util import class_forname, init_logger

if sys.version_info >= (3, 0):
    long = int


_LOGGER = init_logger(__name__, level=logging.DEBUG)

RV_DATA_WAIT = 10523
RV_NOT_EXECUTED = -1
RV_ASYNCH_EXEC = -2
MODRECORD_CODE = 1
ADDRECORD_CODE = 0
DELRECORD_CODE = 2


'''
Created on 12/ott/2014

@author: Matteo
'''


class Action(object):

    def __str__(self, *args, **kwargs):
        rv = self.__class__.__name__
        if self.device is not None:
            rv += " d = "+self.device.name
        return rv

    def set_randomid(self, randid):
        self.randomid = randid

    def modifies_device(self):
        return True

    def __init__(self, device):
        self.randomid = -1
        if device is None or device.__class__.__name__.startswith("Device"):
            self.device = device
        else:
            raise TypeError(f'Invalid device argument. Class is {device.__class__.__name__} value = {device}')

    def to_json(self):
        return {'actionclass': self.__class__.__name__,
                'device': self.device,
                'randomid': self.randomid,
                'dev': 1 if self.modifies_device() else 0
                }

    def mqtt_publish_onfinish(self, rv):
        return list()

    def exec_handler(self, rv, data, **kwargs):
        return rv

    def get_timeout(self):
        return None

    def run(self, actionexec, returnvalue=RV_NOT_EXECUTED):
        now = time.time()
        if self.device is None or now-self.device.offt > self.device.offlimit:
            rv = self.runint(actionexec, returnvalue)
            if rv is None and self.device is not None and self.device.offt >= 0:
                now = time.time()
                self.device.offt = now
        else:
            # _LOGGER.info("non va be "+str(0 if self.device is None else 1)+" "+str(now-self.device.offt))
            rv = None
        if rv is None or rv > 0:
            event.EventManager.fire(eventname=self.__class__.__name__,
                                    device=self.device, action=self, retval=rv)
            event.EventManager.fire(eventname='ActionDone',
                                    device=self.device, action=self, retval=rv)
        if returnvalue != RV_NOT_EXECUTED:
            actionexec.notify_asynch_action_done(self, rv)
        return rv

    def do_presend_operations(self, actionexec):
        return 1

    def do_postsend_operations(self, actionexec):
        pass

    def runint(self, actionexec, returnvalue=RV_NOT_EXECUTED):
        if returnvalue == RV_NOT_EXECUTED:
            retval = self.do_presend_operations(actionexec)
            if retval and retval > 0:
                pay = ''
                if self.device:
                    retval = self.device.do_presend_operations(
                        self, actionexec)
                    if retval > 0:
                        pay = self.device.get_action_payload(self)

                if pay is not None and len(pay):
                    retval = self.device.send_action(actionexec, self, pay)
                if retval and retval > 0:
                    if self.device:
                        self.device.do_postsend_operations(self, actionexec)
                    self.do_postsend_operations(actionexec)
        else:
            retval = returnvalue
            if retval and retval > 0:
                if self.device:
                    self.device.do_postsend_operations(self, actionexec)
                self.do_postsend_operations(actionexec)
        return retval


class ActionPingresponse(Action):
    def __init__(self, *args, **kwargs):
        super(ActionPingresponse, self).__init__(None)

    def modifies_device(self):
        return False


class ActionPing(ActionPingresponse):
    def __init__(self, *args, **kwargs):
        super(ActionPing, self).__init__(None)


class ActionSubscribe(Action):
    pass


class ActionDiscovery(Action):

    def __init__(self, primelanhost='', primelanport=80, primelanpassw='', primelancodu='', primelanport2=0):
        self.php = (primelanhost, primelanport)
        self.ppasw = primelanpassw
        self.pcodu = primelancodu
        self.pport2 = primelanport2
        self.hosts = {}
        super(ActionDiscovery, self).__init__(None)
        self.m_device = False

    def to_json(self):
        rv = Action.to_json(self)
        rv.update({'hosts': self.hosts})
        return rv

    def modifies_device(self):
        return self.m_device

    def runint(self, actionexec, returnvalue=RV_NOT_EXECUTED):
        timeout = self.get_timeout()
        if timeout is None or timeout < 0:
            timeout = actionexec.udpmanager.timeout
        if timeout < 0:
            timeout = None
        from device.devicect10 import DeviceCT10
        from device.deviceprimelan import DevicePrimelan
        from device.devicerm import DeviceRM
        from device.deviceudp import DeviceUDP
        from device.deviceupnp import DeviceUpnp
        self.hosts.update(DeviceCT10.discovery(actionexec, timeout))
        self.hosts.update(DeviceRM.discovery(actionexec, timeout))
        php = self.php if len(self.php[0]) else actionexec.prime_hp
        ppasw = self.ppasw if len(self.ppasw) else actionexec.prime_pass
        pcodu = self.pcodu if len(self.pcodu) else actionexec.prime_code
        pport2 = self.pport2 if self.pport2 else actionexec.prime_port2
        if len(php[0]) and len(ppasw) and len(pcodu):
            self.hosts.update(DevicePrimelan.discovery(
                php, ppasw, pcodu, pport2, timeout))
        self.hosts.update(DeviceUpnp.discovery())
        self.hosts.update(DeviceUDP.discovery(actionexec, timeout))
        return 1 if len(self.hosts) else 2

    def get_timeout(self):
        return 5


class ActionPause(Action):
    def __str__(self, *args, **kwargs):
        return Action.__str__(self, *args, **kwargs)+" p = "+str(self.pause)

    def __init__(self, p):
        super(ActionPause, self).__init__(None)
        self.pause = int(p)

    def modifies_device(self):
        return False

    def runint(self, actionexec, returnvalue=RV_NOT_EXECUTED):
        time.sleep(self.pause)
        return 1


class ActionDevicedl(Action):
    def __init__(self, device=None):
        self.hosts = {}
        super(ActionDevicedl, self).__init__(None)

    def to_json(self):
        rv = Action.to_json(self)
        rv.update({'hosts': self.hosts})
        return rv

    def set_devices(self, h):
        self.hosts = h

    def modifies_device(self):
        return False

    def runint(self, actionexec, returnvalue=RV_NOT_EXECUTED):
        return 1


class ActionNotifystate(Action):
    def __init__(self, device, state):
        super(ActionNotifystate, self).__init__(device)
        self.device.process_asynch_state_change(state)

    def modifies_device(self):
        return False

    def runint(self, actionexec, returnvalue=RV_NOT_EXECUTED):
        return 1


class ActionIrask(Action):
    def __str__(self, *args, **kwargs):
        return Action.__str__(self, *args, **kwargs)+" a = "+self.irname

    def __init__(self, device, irname):
        super(ActionIrask, self).__init__(device)
        self.irname = irname

    def modifies_device(self):
        return False

    def runint(self, actionexec, returnvalue=RV_NOT_EXECUTED):
        _LOGGER.info("Please press "+self.irname)
        return 1

    def to_json(self):
        rv = Action.to_json(self)
        rv.update({'irname': self.irname})
        return rv

    def mqtt_publish_onfinish(self, rv):
        try:
            remnm = self.irname.split(':')
            keynm = remnm[1]
            remnm = remnm[0]
        except: # noqa: E722
            keynm = self.irname
            remnm = ""
        return [dict(topic=self.device.mqtt_topic("stat", "learn"), msg=json.dumps([dict(remote=remnm, key=keynm, status=-2)]), options=dict())]


class ActionExit(Action):
    def __init__(self):
        super(ActionExit, self).__init__(None)

    def runint(self, actionexec, returnvalue=RV_NOT_EXECUTED):
        return 1

    def modifies_device(self):
        return False


class ActionStatechange(Action):

    def __str__(self, *args, **kwargs):
        return Action.__str__(self, *args, **kwargs)+" st = "+self.newstate

    def __init__(self, device, newstate):
        super(ActionStatechange, self).__init__(device)
        self.newstate = str(newstate)

    def to_json(self):
        rv = Action.to_json(self)
        rv.update({'newstate': self.newstate})
        return rv


class ActionStateoff(ActionStatechange):
    def __init__(self, device):
        super(ActionStateoff, self).__init__(device, 0)


class ActionStateon(ActionStatechange):
    def __init__(self, device):
        super(ActionStateon, self).__init__(device, 1)


class ActionBackup(Action):
    def __str__(self, *args, **kwargs):
        return Action.__str__(self, *args, **kwargs)+" topic = "+str(self.topic)

    def __init__(self, device, topic, convert, *args):
        super(ActionBackup, self).__init__(device)
        self.topic = topic
        self.convert = convert
        self.publish = []

    def runint(self, actionexec, returnvalue=RV_NOT_EXECUTED):
        nextbackup = getattr(self.device, "nextbackup", None)
        if nextbackup:
            self.publish = self.device.nextbackup(self.topic, self.convert)
            if len(self.publish):
                return 1
            else:
                return 2
        else:
            return 11

    def mqtt_publish_onfinish(self, rv):
        if rv == 1:
            return [dict(topic="cmnd/"+self.topic+"/learn", msg=json.dumps(self.publish), options=dict())]
        else:
            return list()


class ActionInsertKey(Action):
    def __str__(self, *args, **kwargs):
        return Action.__str__(self, *args, **kwargs)+" rk = "+self.remote+':'+self.key

    def __init__(self, device, remote, key, a, other={}, *args):
        super(ActionInsertKey, self).__init__(device)
        self.remote = remote
        self.key = key
        self.a = self.device.get_from_arduraw(
            {'remote': remote, 'key': key, 'a': a})
        self.a[2].update(other)
        self.other = other

    def runint(self, actionexec, returnvalue=RV_NOT_EXECUTED):
        dir = getattr(self.device, "dir", None)
        if dir:
            if self.remote not in self.device.dir:
                self.device.dir[self.remote] = dict()
            self.device.dir[self.remote].update({self.key: self.a})
            return 1
        else:
            return 11

    def mqtt_publish_onfinish(self, rv):
        return [dict(topic=self.device.mqtt_topic("stat", "learn"), msg=json.dumps([{'remote': self.remote, 'key': self.key, 'status': rv}]), options=dict())]


class ActionLearnir(Action):

    def get_timeout(self):
        return 25

    def __str__(self, *args, **kwargs):
        return Action.__str__(self, *args, **kwargs)+" ir = "+str(self.irname)

    def __init__(self, device, *args):
        super(ActionLearnir, self).__init__(device)
        self.irname = ActionEmitir.parse_args(device, *args)
        self.irc = []
        self.idx = 0
        self.asked = -1
        self.publish = []
        self.irdata = []

    def to_json(self):
        rv = Action.to_json(self)
        rv.update({'irname': self.irname, 'irc': self.irc})
        return rv

    def runint(self, actionexec, returnvalue=RV_NOT_EXECUTED):
        backupstate = getattr(self.device, "backupstate", None)
        if backupstate:
            if self.device.backupstate == 0:
                return super(ActionLearnir, self).runint(actionexec, returnvalue)
            else:
                return 10
        else:
            return 11

    def mqtt_publish_key(self, remnm, keynm, rv=1):
        self.publish.append(dict(remote=remnm, key=keynm, status=rv))

    def mqtt_publish_onfinish(self, rv):
        return [dict(topic=self.device.mqtt_topic("stat", "learn"), msg=json.dumps(self.publish), options=dict())]

    def do_presend_operations(self, actionexec):
        self.irdata = []
        while self.idx < len(self.irname):
            try:
                ird = self.irname[self.idx]
                tt = ird.split(':')
                if len(tt) == 2 and len(tt[0]) and len(tt[1]):
                    self.irdata = ird
                    return 1
                else:
                    self.idx += 1
            except: # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")
                self.idx += 1
        return Action.do_presend_operations(self, actionexec)

    def exec_handler(self, rv, irdata, **kwargs):
        if not self.irname:
            return 3
        else:
            tt = self.irname[self.idx].split(':')
            dname = tt[0]
            irname = tt[1]
            if rv != 1:
                self.mqtt_publish_key(dname, irname, rv)
                return rv
            else:
                irc = irdata['irc']
                self.irc.append(self.device.ir_encode(irc))
                if dname not in self.device.dir:
                    self.device.dir[dname] = dict()
                irnamea = irname.split(',')
                first = True
                for x in irnamea:
                    if len(x):
                        if first:
                            first = False
                            save = irname
                            self.mqtt_publish_key(dname, x, 1)
                        else:
                            save = ''
                        self.device.dir[dname].update(
                            {x: (irc, save, irdata['attrs'])})
                self.idx += 1
                time.sleep(1)
                if self.idx >= len(self.irname):
                    return 1
                else:
                    return 0


class ActionEditraw(Action):

    def __str__(self, *args, **kwargs):
        return Action.__str__(self, *args, **kwargs)+" ir = "+self.irshname+'/'+self.newraw

    def modifies_device(self):
        return True

    def __init__(self, device, irshname, *args):
        super(ActionEditraw, self).__init__(device)
        self.irshname = irshname
        self.newraw = '' if len(args) == 0 else args[0]
        self.remote = ''
        self.irname = ''
        self.remote_src = ''
        self.irname_src = ''
        if len(self.irshname) and self.irshname[0] == '@':
            self.irname = self.irshname[1:]
        else:
            aa = self.irshname.split(':')
            if len(aa) == 4 and len(aa[0]) and len(aa[1]):
                self.remote_src = aa[0]
                self.irname_src = aa[1]
                self.remote = aa[2]
                self.irname = aa[3]

    def runint(self, actionexec, returnvalue=RV_NOT_EXECUTED):
        sh = getattr(self.device, "sh", None)
        if sh:
            if len(self.newraw):
                if self.irshname[0] == '@':
                    mo = re.search("[^a-zA-Z0-9_\\-]", self.irname)
                    if len(self.irshname) > 1 and mo is None:
                        self.device.sh[self.irname] = self.newraw.split('|')
                    else:
                        return 3
                else:
                    if len(self.remote) and len(self.irname):
                        irnm = self.irname
                        ircdec = self.device.ir_decode(self.newraw)
                        if self.remote_src in self.device.dir and self.irname_src in self.device.dir[self.remote_src]:
                            src = self.device.dir[self.remote_src][self.irname_src]
                            self.device.dir[self.remote][irnm] = (
                                ircdec, irnm, src[2])
                        elif self.remote in self.device.dir and irnm in self.device.dir[self.remote]:
                            src = self.device.dir[self.remote][irnm]
                            iratt = src[2]
                            self.device.dir[self.remote][irnm] = (
                                ircdec, irnm, iratt)
                            if irnm in DICTIONARY:
                                irnma = DICTIONARY[irnm]
                                for x in irnma:
                                    if len(x):
                                        self.device.dir[self.remote].update(
                                            {x: (ircdec, '', iratt)})
                        else:
                            return 7
                    else:
                        return 4
            else:
                if self.irshname[0] == '@':
                    if self.irname in self.device.sh:
                        del self.device.sh[self.irname]
                    else:
                        return 5
                else:
                    if self.remote_src in self.device.dir and self.irname_src in self.device.dir[self.remote_src]:
                        del self.device.dir[self.remote_src][self.irname_src]
                        if len(self.device.dir[self.remote_src]) == 0:
                            del self.device.dir[self.remote_src]
                    else:
                        return 6

            return 1
        else:
            return 2

    def to_json(self):
        rv = Action.to_json(self)
        rv.update({'irshname': self.irshname, 'newraw': self.newraw})
        return rv

    def mqtt_publish_onfinish(self, rv):
        return [dict(
            topic=self.device.mqtt_topic("stat", "learn"), msg=json.dumps([dict(
                key=self.irshname if len(
                    self.irshname) and self.irshname[0] == '@' else self.irname,
                remote=self.remote, status=rv)]), options=dict())]


class ActionCreatesh(Action):

    def modifies_device(self):
        return True

    def __init__(self, device, shname, *args):
        super(ActionCreatesh, self).__init__(device)
        self.irname = ActionEmitir.parse_args(device, *args)
        self.shname = shname

    def runint(self, actionexec, returnvalue=RV_NOT_EXECUTED):
        sh = getattr(self.device, "sh", None)
        if sh:
            if len(self.irname):
                self.device.sh[self.shname] = self.irname
            else:
                if self.shname in self.device.sh:
                    del self.device.sh[self.shname]
            return 1
        else:
            return 2

    def to_json(self):
        rv = Action.to_json(self)
        rv.update({'irname': self.irname, 'shname': self.shname})
        return rv

    def mqtt_publish_onfinish(self, rv):
        return [dict(topic=self.device.mqtt_topic("stat", "learn"), msg=json.dumps([dict(key='@'+self.shname, remote='', status=rv)]), options=dict())]


class ActionEmitir(Action):

    def modifies_device(self):
        return False

    @staticmethod
    def parse_args(device, *args):
        irname = []
        dname = ''
        x = 0
        while x < len(args):
            a = args[x]
            cnt = a.count(':')
            if cnt == 1:
                tmpa = a.split(':')
                tmp = tmpa[0]
                if len(tmp):
                    irname.append(a)
                    dname = tmp
            elif cnt == 2:
                irname.append(a)
            elif cnt == 0:
                if len(a) > 1 and a[0] == '$':
                    irname.append(a)
                elif len(a) > 1 and a[0] == '@':
                    try:
                        c = args[0:x+1] + tuple(device.sh[a[1:]]) + args[x+1:]
                        args = c
                    except: # noqa: E722
                        pass
                elif len(dname):
                    irname.append(dname+":"+a)
            x += 1
        return irname

    def __str__(self, *args, **kwargs):
        return Action.__str__(self, *args, **kwargs)+" ir = "+str(self.irname)

    def __init__(self, device, *args):
        super(ActionEmitir, self).__init__(device)
        self.irname = ActionEmitir.parse_args(device, *args)
        self.irc = []
        self.idx = 0
        self.publish = []
        self.irdata = []

    def to_json(self):
        rv = Action.to_json(self)
        rv.update({'irname': self.irname, 'irc': self.irc})
        return rv

    def do_presend_operations(self, actionexec):
        while 1:
            if self.idx < len(self.irname):
                currentk = self.irname[self.idx]
                if currentk[0] == '$':
                    try:
                        p = float(currentk[1:])
                        time.sleep(p)
                    except: # noqa: E722
                        pass
                    self.idx += 1
                else:
                    break
            else:
                break
        if self.idx < len(self.irname):
            currentk = self.irname[self.idx]
            if currentk.count(':') == 2:
                self.idx += 1
                tmp = currentk.split(':')
                event.EventManager.fire(eventname='ExtInsertAction', hp=(
                    self.device.host, self.device.port), action=None, cmdline="45 emitir %s %s:%s" % (tmp[0], tmp[1], tmp[2]), pos=0)
                return 0
        self.irdata = []
        while self.idx < len(self.irname):
            try:
                tt = self.irname[self.idx].split(':')
                nm = tt[1]
                dev = tt[0]
                self.irdata = self.device.get_dir(dev, nm)
                if not self.irdata:
                    self.irdata = self.convert_ir(dev, nm)
                if len(self.irdata):
                    self.irc.append(self.device.ir_encode(self.irdata[0]))
                    self.mqtt_publish_key(dev, nm, 1)
                    return 1
                else:
                    self.mqtt_publish_key(dev, nm, 2)
                    self.idx += 1
            except: # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")
                self.idx += 1
        return 2

    def exec_handler(self, rv, data):
        if rv is None or rv != 1:
            return rv
        else:
            self.idx += 1
            p = self.device.emit_ir_delay
            if self.idx < len(self.irname) and self.irname[self.idx][0] == '$':
                p = float(self.irname[self.idx][1:])
                self.idx += 1
            time.sleep(p)
            if self.idx >= len(self.irname):
                return 1
            else:
                return 0

    def convert_ir(self, dev, nm):
        irc = ()
        convdict = {'zero': '0', 'uno': '1', 'due': '2', 'tre': '3', 'quattro': '4',
                    'cinque': '5', 'sei': '6', 'sette': '7', 'otto': '8', 'nove': '9', 'I': '1', 'i': '1'}
        idxa = -1
        idxbis = -1
        nma = []
        del self.irname[self.idx]
        while True:
            if (nm in convdict) and (not self.device.get_dir(dev, nm)):
                nm = convdict[nm]
            if self.device.get_dir(dev, nm):
                idxbis += 1
                self.irname.insert(self.idx+idxbis, dev+":"+nm)
                idxa += 1
                if idxa >= len(nma):
                    break
                else:
                    nm = nma[idxa]
            else:
                mo = re.search("([^#]+)#([0-9]+)", nm)
                if mo is not None:
                    x = int(mo.group(2))
                    c = mo.group(1)
                    if (c in convdict) and (not self.device.get_dir(dev, c)):
                        c = convdict[c]
                    if not self.device.get_dir(dev, c):
                        nma = [c]*x
                        idxa = 0
                        nm = nma[idxa]
                    else:
                        for _ in range(x):
                            idxbis += 1
                            self.irname.insert(self.idx+idxbis, dev+":"+c)
                        break
                mo = re.search("[^\\s]+ ([0-9]+)$", nm)
                if mo is not None:
                    x = int(mo.group(1))
                    c = nm[0:nm.rfind(' ')]
                    if (c in convdict) and (not self.device.get_dir(dev, c)):
                        c = convdict[c]
                    if x > 20 or (not self.device.get_dir(dev, c)):
                        nma = nm.split(' ')
                        idxa = 0
                        nm = nma[idxa]
                    else:
                        for _ in range(x):
                            idxbis += 1
                            self.irname.insert(self.idx+idxbis, dev+":"+c)
                        break
                else:
                    mo = re.search("^[0-9]+$", nm)
                    if mo is not None:
                        for _, c in enumerate(nm):
                            idxbis += 1
                            self.irname.insert(self.idx+idxbis, dev+":"+c)
                        idxa += 1
                        if idxa >= len(nma):
                            break
                        else:
                            nm = nma[idxa]
                    elif nm.find(' ') >= 0:
                        nma = nm.split(' ')
                        idxa = 0
                        nm = nma[idxa]
                    else:
                        idxa += 1
                        if idxa >= len(nma):
                            break
                        else:
                            nm = nma[idxa]
        if idxbis >= 0:
            irc = self.device.get_dir(dev, self.irname[self.idx][len(dev)+1:])
        return irc

    def mqtt_publish_key(self, remnm, keynm, rv=1):
        self.publish.append(dict(remote=remnm, key=keynm, status=rv))

    def mqtt_publish_onfinish(self, rv):
        return [dict(topic=self.device.mqtt_topic("stat", "emit"), msg=json.dumps(self.publish), options=dict())]


class ActionViewtable(Action):

    def modifies_device(self):
        return self.m_device

    def __str__(self, *args, **kwargs):
        return Action.__str__(self, *args, **kwargs)+" tbl = "+str(self.tablenum)+":"+str(self.vflag)

    def __init__(self, device, tablenum, vflag):
        super(ActionViewtable, self).__init__(device)
        self.tablenum = int(tablenum)
        self.vflag = int(vflag)
        self.m_device = True

    def to_json(self):
        rv = Action.to_json(self)
        rv.update({'tbl': str(self.tablenum)+":"+str(self.vflag)})
        return rv


class ActionViewtable1(ActionViewtable):

    def __init__(self, device):
        super(ActionViewtable1, self).__init__(device, "1", "0")


class ActionViewtable3(ActionViewtable):

    def __init__(self, device):
        get_ver_flag = getattr(device, "get_ver_flag", None)
        verflag = get_ver_flag("3", "2") if get_ver_flag else "2"
        super(ActionViewtable3, self).__init__(device, "3", verflag)


class ActionViewtable4(ActionViewtable):

    def __init__(self, device):
        get_ver_flag = getattr(device, "get_ver_flag", None)
        verflag = get_ver_flag("4", "23") if get_ver_flag else "23"
        super(ActionViewtable4, self).__init__(device, "4", verflag)


class ActionSettable(Action):

    def modifies_device(self):
        return False

    def __str__(self, *args, **kwargs):
        return Action.__str__(self, *args, **kwargs)+" tbl = "+str(self.tablenum)+":"+str(self.actionid)

    def __init__(self, device, tablenum, actionid):
        super(ActionSettable, self).__init__(device)
        self.tablenum = tablenum
        self.actionid = actionid

    def to_json(self):
        rv = Action.to_json(self)
        rv.update({'tbl': str(self.tablenum)+":"+str(self.actionid)})
        return rv


class ActionSettable3(ActionSettable):
    def __str__(self, *args, **kwargs):
        rv = ActionSettable.__str__(self, *args, **kwargs)
        if self.actionid == DELRECORD_CODE:
            rv += " cod = "+str(self.timerid)
        else:
            rv += " date = " + \
                self.datetime.strftime(
                    '%d/%m/%Y %H:%M:%S')+" r = "+str(self.rep)
            rv += " act = "+str(self.action)
            if self.actionid == MODRECORD_CODE:
                rv += " cod = "+str(self.timerid)
        return rv

    def __init__(self, device, datev=None, timev=None, rep=0, timerid=0, *args, **kwargs):
        # datev = None if 'datev' not in kwargs else kwargs['datev']
        # timev = None if 'timev' not in kwargs else kwargs['timev'],
        # rep = 0 if 'rep' not in kwargs else kwargs['rep']
        # timerid = None if 'timerid' not in kwargs else kwargs['timerid']
        if timev is None:
            code = DELRECORD_CODE
        elif int(timerid) <= 0:
            code = ADDRECORD_CODE
        else:
            code = MODRECORD_CODE
        super(ActionSettable3, self).__init__(device, 3, code)
        if timev is None:
            self.datetime = None
        else:
            try:
                self.datetime = datetime.strptime(
                    datev+" "+timev, '%d/%m/%Y %H:%M:%S')
            except: # noqa: E722
                try:
                    do = int(datev)
                    ho = int(timev)
                    self.datetime = datetime.now()+timedelta(days=do, seconds=ho)
                except: # noqa: E722
                    self.datetime = None

        self.rep = 0 if rep is None else int(rep)
        self.timerid = None if timerid is None else int(timerid)
        self.action = device.parse_action_timer_args(args)

    def to_json(self):
        rv = Action.to_json(self)
        rv.update({
            'datetime': None if self.datetime is None else self.datetime.strftime('%d/%m/%Y %H:%M:%S'),
            'rep': self.rep,
            'timerid': self.timerid,
            'action': self.action})
        return rv

    def do_postsend_operations(self, actionexec):
        actionexec.insert_action(ActionViewtable3(self.device), 1)


class ActionDeltimer(ActionSettable3):
    def __init__(self, device, timerid):
        super(ActionDeltimer, self).__init__(device, timerid=timerid)


class ActionCleartimers(Action):
    def __init__(self, device, *args):
        super(ActionCleartimers, self).__init__(device)
        self.timerid = list()
        for arg in args:
            try:
                self.timerid.append(int(arg))
            except: # noqa: E722
                pass
        self.idx = 0

    def do_presend_operations(self, actionexec):
        if self.device.timers is None:
            actionexec.insert_action(ActionViewtable3(self.device), 0)
            return 0
        elif len(self.timerid):
            if self.idx < len(self.timerid):
                actionexec.insert_action(ActionDeltimer(
                    self.device, self.timerid[self.idx]), 0)
                self.idx += 1
                return 0
            else:
                return 1
        elif self.idx < len(self.device.timers):
            actionexec.insert_action(ActionDeltimer(
                self.device, self.device.timers[self.idx]['code']), 0)
            self.idx += 1
            return 0
        else:
            return Action.do_presend_operations(self, actionexec)


class ActionGetstate(Action):
    def __init__(self, device, *args, **kwargs):
        super(ActionGetstate, self).__init__(device)
        self.outstate = {}

    def to_json(self):
        rv = Action.to_json(self)
        rv.update({'outstate': self.outstate})
        return rv

    def exec_handler(self, rv, data):
        self.outstate = data
        return rv


class ActionGetinfo(Action):
    def __init__(self, *args, **kwargs):
        super(ActionGetinfo, self).__init__(None)
        self.state = 0
        self.disc = ActionDiscovery()
        self.devs = None

    def to_json(self):
        rv = Action.to_json(self)
        rv.update({'discovery': self.disc.hosts})
        return rv

    def do_presend_operations(self, actionexec):
        if self.state == 0:
            actionexec.insert_action(self.disc, 0)
            self.state += 1
            return 0
        elif self.state == 1:
            if self.devs is None:
                self.devs = list(self.disc.hosts.items())
            for x in range(len(self.devs)):
                actionexec.insert_action(ActionViewtable1(self.devs[x][1]), x)
            self.state += 1
            return 0
        elif self.state == 2:
            dudpok = 0
            dudptot = 0
            now = time.time()
            dtcpok = 0
            for x in range(len(self.devs)):
                d = self.devs[x][1]
                tablever = getattr(d, "tablever", None)
                if tablever:
                    dudptot += 1
                    if now-d.offt > d.offlimit:
                        if d.tablever:
                            for k, _ in d.tablever.copy().items():
                                if k != "1":
                                    kls = class_forname(
                                        'action.ActionViewtable'+k)
                                    actionexec.insert_action(kls(d), dudpok)
                                    dudpok += 1
                else:
                    dtcpok += 1
            self.state += 1
            if dudpok > 0:
                return 0
            elif dudpok != dudptot and dudpok == 0:
                return 2 if dtcpok > 0 else None
            elif dtcpok > 0:
                return 1
            else:
                return None
        else:
            return 1


class ActionSynctimers(Action):
    def __init__(self, device, fn):
        super(ActionSynctimers, self).__init__(device)
        self.idx = -1
        try:
            tablever = getattr(device, "tablever", None)
            self.out = None if not tablever else self.device.loadtables(fn, self.device.name)
        except: # noqa: E722
            _LOGGER.warning(f"{traceback.format_exc()}")
            self.out = None

    def do_presend_operations(self, actionexec):
        if self.out is None:
            return 3
        elif self.idx < 0:
            actionexec.insert_action(ActionCleartimers(self.device), 0)
            self.idx = 0
            return 0
        elif self.idx < len(self.out['timers']):
            t = self.out['timers'][self.idx]
            _LOGGER.info("timer "+str(t))
            actionexec.insert_action(ActionSettable3(self.device, *tuple(t['action'].split(' ')),
                                                     datev="%02d/%02d/%04d" % (t['day'],
                                                                               t['month'], t['year']),
                                                     timev="%02d:%02d:%02d" % (
                                                         t['hour'], t['minute'], t['second']),
                                                     rep=t['rep'], timerid=0), 0)
            self.idx += 1
            return 0
        else:
            return 1


class ActionSettable4(ActionSettable):

    def __init__(self, device, newname=None, tz=None, offafteron=None, ipv=None, gatewayv=None, nmaskv=None):
        super(ActionSettable4, self).__init__(device, 4, MODRECORD_CODE)
        self.name = newname
        self.timezone = None if tz is None else int(tz)
        self.timer_off_after_on = None if offafteron is None else int(
            offafteron)
        if ipv is not None and gatewayv is not None and nmaskv is not None:
            self.ip = ipv
            self.gateway = gatewayv
            self.nmask = nmaskv
        else:
            self.ip = None
            self.gateway = None
            self.nmask = None

    def do_presend_operations(self, actionexec):
        if self.device.rawtables is None or "4" not in self.device.rawtables:
            actionexec.insert_action(ActionViewtable4(self.device), 0)
            return 0
        else:
            return 1

    def do_postsend_operations(self, actionexec):
        actionexec.insert_action(ActionViewtable4(self.device), 1)

    # ===========================================================================
    # def get_payload(self):
    #     if self.device.rawtables is None or "4" not in self.device.rawtables:
    #         return ''
    #     else:
    #         pay = self.device.rawtables["4"]
    #         pay = pay[0:4]+WRITE_TABLE_ID+pay[6:]
    #         if self.name is None:
    #             nm = None
    #         elif len(self.name)>16:
    #             nm = self.name[0:16]
    #         else:
    #             nm = self.name.ljust(16)
    #         if nm is not None:
    #             pay = pay[0:70]+nm+pay[86:]
    #         if self.timezone is not None:
    #             pay = pay[0:162]+b'\x00'+struct.pack('<B',self.timezone)+pay[164:]
    #         if self.timer_off_after_on is not None:
    #             if len(pay)>168:
    #                 payend = pay[168:]
    #             else:
    #                 payend = ''
    #             pay = pay[0:164]+(b'\x00\x00' if self.timer_off_after_on==0 else b'\x01\x00')+struct.pack('<H',self.timer_off_after_on)+payend
    #         pay = pay[0:18]+pay[19:]
    #         pay = pay[0:25]+pay[27:]
    #         pay = pay[0:2]+struct.pack('>H',len(pay))+pay[4:]
    #         return pay
    # ===========================================================================


class ActionSetname(ActionSettable4):
    def __str__(self, *args, **kwargs):
        return ActionSettable4.__str__(self, *args, **kwargs)+" name = "+self.name

    def __init__(self, device, newname):
        super(ActionSetname, self).__init__(device, newname=newname)


class ActionSettz(ActionSettable4):
    def __str__(self, *args, **kwargs):
        return ActionSettable4.__str__(self, *args, **kwargs)+" tz = "+str(self.timezone)

    def __init__(self, device, tz):
        super(ActionSettz, self).__init__(device, tz=tz)


class ActionSetoao(ActionSettable4):
    def __str__(self, *args, **kwargs):
        return ActionSettable4.__str__(self, *args, **kwargs)+" oao = "+str(self.timer_off_after_on)

    def __init__(self, device, offafteron):
        super(ActionSetoao, self).__init__(device, offafteron=offafteron)


class ActionSetip(ActionSettable4):
    def __str__(self, *args, **kwargs):
        return ActionSettable4.__str__(self, *args, **kwargs)+" ip = "+self.ip+" nm = "+self.nmask+" dg = "+self.gateway

    def __init__(self, device, ipv, gatewayv, nmaskv):
        super(ActionSetip, self).__init__(
            device, ipv=ipv, gatewayv=gatewayv, nmaskv=nmaskv)
