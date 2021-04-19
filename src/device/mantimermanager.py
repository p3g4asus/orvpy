import logging
import threading
import traceback
from datetime import date, datetime, timedelta
from xml.etree.ElementTree import SubElement

import event
from action import (ADDRECORD_CODE, DELRECORD_CODE, MODRECORD_CODE,
                    ActionSettable3)
from util import init_logger

_LOGGER = init_logger(__name__, level=logging.DEBUG)


class ManTimerManager(object):
    def __init__(self, root, **kw):
        self.timers_man = []
        if root is not None:
            self.timers = ManTimerManager.timer_xml_device_node_parse(root)
            for t in self.timers:
                self.timers_man.append(self.activate_timer(t))

    def on_stop(self):
        for t in self.timers_man:
            if t is not None:
                t.cancel()

    def to_json(self):
        return {}

    def do_presend_operations(self, action, actionexec):
        if isinstance(action, ActionSettable3):
            self.manage_timer(datetime_o=action.datetime, rep=action.rep,
                              action=action.action, timerid=action.timerid, actionid=action.actionid)
        return 1

    def copy_extra_from(self, already_saved_device):
        self.timers_man = already_saved_device.timers_man

    def exec_timer(self, t, *args, **kwargs):
        d = datetime(t['year'], t['month'], t['day'],
                     t['hour'], t['minute'], t['second'])
        self.manage_timer(datetime_o=d, rep=t['rep'], action=t["action"],
                          timerid=t['code'], actionid=MODRECORD_CODE)
        event.EventManager.fire(eventname='TimerAction',
                                device=self, timerobj=t)
        threading.currentThread().name = ("exec_timer")

    def activate_timer(self, t):
        rv = None
        d = datetime(t['year'], t['month'], t['day'],
                     t['hour'], t['minute'], t['second'])
        now = datetime.now()
        if d > now:
            pass
        elif (t['rep'] & 255) > 128:
            while True:
                b = d + timedelta(seconds=86400)
                d = b
                if ((1 << d.weekday()) & t['rep']) and d > now:
                    break
            t['year'] = d.year
            t['month'] = d.month
            t['day'] = d.day
            t['hour'] = d.hour
            t['minute'] = d.minute
            t['second'] = d.second
        else:
            d = None
        if d is not None:
            rv = threading.Timer((d - now).total_seconds(),
                                 self.exec_timer, (t,))
            rv.name = ("timer" + str(t["code"]))
            rv.daemon = True
            rv.start()
        return rv

    def xml_element(self, root, flag=0):
        ManTimerManager.timer_xml_device_node_write(root, self.timers)
        return root

    def manage_timer(self, datetime_o=None, rep=0, action=None, timerid=0, actionid=DELRECORD_CODE):
        if actionid == DELRECORD_CODE:
            delt = None
            for x in range(len(self.timers)):
                t = self.timers[x]
                if t['code'] == timerid:
                    delt = x
                    break
            if delt is not None:
                del self.timers[delt]
                if self.timers_man[delt] is not None:
                    self.timers_man[delt].cancel()
                del self.timers_man[delt]
        elif actionid == ADDRECORD_CODE:
            timerid = timerid if timerid > 0 else 1
            while True:
                repeat = False
                for x in range(len(self.timers)):
                    t = self.timers[x]
                    if t['code'] == timerid:
                        timerid += 1
                        repeat = True
                        break
                if not repeat:
                    break
            t = {
                'year': datetime_o.year,
                'month': datetime_o.month,
                'day': datetime_o.day,
                'hour': datetime_o.hour,
                'minute': datetime_o.minute,
                'second': datetime_o.second,
                'rep': rep,
                'action': action,
                'code': timerid
            }
            self.timers.append(t)
            self.timers_man.append(self.activate_timer(t))
        elif actionid == MODRECORD_CODE:
            self.manage_timer(datetime_o=datetime_o, rep=rep, action=action,
                              timerid=timerid, actionid=DELRECORD_CODE)
            self.manage_timer(datetime_o=datetime_o, rep=rep, action=action,
                              timerid=timerid, actionid=ADDRECORD_CODE)

    @staticmethod
    def timer_xml_device_node_write(el, timerlist):
        timers = SubElement(el, "timers")
        tv = [] if timerlist is None else timerlist
        for t in tv:
            timer = SubElement(timers, "timer")
            v = SubElement(timer, 'code')
            v.text = str(t['code'])
            v = SubElement(timer, 'rep', {"value": str(t['rep'])})
            r = t['rep']
            if r > 128:
                days = ''
                for i in range(7):
                    dt = date(2016, 1, 4 + i)
                    mask = (1 << i)
                    if mask & r:
                        if len(days):
                            days += ","
                        days += dt.strftime('%a')
                if len(days):
                    v.text = days
            v = SubElement(timer, 'action')
            v.text = str(t['action'])
            v = SubElement(timer, 'date')
            v.text = '%02d/%02d/%04d %02d:%02d:%02d' % (
                t['day'], t['month'], t['year'], t['hour'], t['minute'], t['second'])

    @staticmethod
    def timer_xml_device_node_parse(outitem):
        out = list()
        sub = outitem.getElementsByTagName('timer')
        for s in sub:
            try:
                t = dict()
                t['code'] = None
                ssub = s.getElementsByTagName('code')
                for ss in ssub:
                    t['code'] = int(ss.childNodes[0].nodeValue)
                    break

                t['rep'] = 0
                ssub = s.getElementsByTagName('rep')
                for ss in ssub:
                    try:
                        printable = ss.childNodes[0].nodeValue
                        if len(printable):
                            printable_l = printable.split(',')
                            rep = 128
                            for i in range(7):
                                dt = date(2016, 1, 4 + i)
                                day = dt.strftime('%a')
                                if day in printable_l:
                                    rep |= (1 << i)
                        t['rep'] = 0 if rep == 128 else rep
                    except:  # noqa: E722
                        pass
                    ''''t['rep'] = int(ss.attributes['value'].value)'''
                    break

                t['action'] = "1"
                ssub = s.getElementsByTagName('action')
                for ss in ssub:
                    t['action'] = ss.childNodes[0].nodeValue
                    break

                t['year'] = None
                t['month'] = None
                t['day'] = None
                t['hour'] = None
                t['minute'] = None
                t['second'] = None
                ssub = s.getElementsByTagName('date')
                for ss in ssub:
                    dtt = datetime.strptime(
                        ss.childNodes[0].nodeValue, '%d/%m/%Y %H:%M:%S')
                    t['year'] = dtt.year
                    t['month'] = dtt.month
                    t['day'] = dtt.day
                    t['hour'] = dtt.hour
                    t['minute'] = dtt.minute
                    t['second'] = dtt.second
                    break
                if t['year'] is not None:
                    out.append(t)
            except:  # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")
        return out
