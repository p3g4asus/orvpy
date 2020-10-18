#!/usr/local/bin/python2.7
# encoding: utf-8
'''
main -- shortdesc

main is a description

It defines classes_and_methods

@author:     user_name

@copyright:  2016 organization_name. All rights reserved.

@license:    license

@contact:    user_email
@deffield    updated: Updated
'''

import argparse as ap
import json
import logging
import os
import re
import shlex
import sys
import threading
import time
import traceback
from signal import SIGTERM, signal

import paho.mqtt.client as paho
from orvibo.action import (DEVICE_SAVE_FLAG_MAIN, DEVICE_SAVE_FLAG_TABLE,
                           ActionDiscovery, ActionEmitir, ActionExecutor,
                           ActionNotifystate, ActionPause, ActionStatechange,
                           ActionSubscribe, ActionViewtable, ActionViewtable1,
                           ActionViewtable4, Device, DeviceS20, IrManager,
                           class_forname)
from orvibo.event import EventManager

__all__ = []
__version__ = 0.1
__date__ = '2016-01-04'
__updated__ = '2016-01-04'

DEBUG = 0
TESTRUN = 0
PROFILE = 0

term_called = False


def sigterm_handler(_signo, _stack_frame):
    global term_called
    logging.info("SIGTERM RECEIVED")
    term_called = True


def valid_retry(val):
    try:
        v = int(val)
        if v < 0:
            raise ap.ArgumentTypeError('')
    except:
        raise ap.ArgumentTypeError('Retry must be>0; '+val+' not valid')
    return v


def valid_host(hostname):
    if len(hostname) > 255 or len(hostname) == 0:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]  # strip exactly one dot from the right, if present
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return hostname if all(allowed.match(x) for x in hostname.split(".")) else ''


def valid_port(val):
    try:
        v = int(val)
        if v < 0 or v > 65535:
            raise ap.ArgumentTypeError('')
    except:
        raise ap.ArgumentTypeError('Port must be>=1025 and <=65535; '+val+' not valid')
    return v


def valid_code(val):
    try:
        v = int(val)
        if v < 0 or v > 9999 or len(val) != 4:
            raise ap.ArgumentTypeError('')
    except:
        raise ap.ArgumentTypeError('Code must be>=0000 and <=9999; '+val+' not valid')
    return val


def valid_timeout(val):
    try:
        v = float(val)
        if v < 0.5:
            raise ap.ArgumentTypeError('')
    except:
        raise ap.ArgumentTypeError('Timeout must be>=0.5; '+val+' not valid')
    return v


def valid_delay(val):
    try:
        v = float(val)
        if v < 0.3 and v != 0:
            raise ap.ArgumentTypeError('')
    except:
        raise ap.ArgumentTypeError('Delay must be>=0.3 or 0; '+val+' not valid')
    return v


class ActionConf(ap.Action):
    def __init__(self, option_strings, dest, **kwargs):
        super(ActionConf, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
        if os.path.exists(values):
            try:
                devices = Device.load(values)
                setattr(namespace, 'devices', devices)
            except:
                traceback.print_exc()
                raise ap.ArgumentError(values+' is not a valid conf file')
        else:
            setattr(namespace, 'devices', {})


class ActionAction(ap.Action):
    def __init__(self, option_strings, dest, **kwargs):
        super(ActionAction, self).__init__(option_strings, dest, **kwargs)

    @staticmethod
    def create_action(values, devices):
        if len(values) >= 1:
            clname = values[0] if isinstance(values, list) else values
            print('orvibo.action.Action'+clname.title())
            cls = class_forname('orvibo.action.Action'+clname.title())
            if cls is not None:
                try:
                    '''print("ci sono qui -1 ")'''
                    t = tuple()
                    if isinstance(values, list) and len(values) > 1:
                        '''print("ci sono qui 0 ")'''
                        if values[1] in devices:
                            dev = devices[values[1]]
                            t = (dev,)
                        else:
                            t = (values[1],)
                        '''print("ci sono qui 1 "+str(t))'''
                        if len(values) > 2:
                            t += tuple(values[2:])
                    '''print('tuple '+str(t)+" val "+str(values))'''
                    return cls(*t)
                except:
                    traceback.print_exc()
        return None

    def __call__(self, parser, namespace, values, option_string=None):
        devices = getattr(namespace, 'devices', None)
        if devices is None:
            raise ap.ArgumentError('Invalid conf argument: must be before the first action')
        attr = getattr(namespace, self.dest, None)
        if attr is None:
            setattr(namespace, self.dest, list())
            attr = getattr(namespace, self.dest, None)
        act = ActionAction.create_action(values, devices)
        if act is None:
            raise ap.ArgumentError(str(values) + ' is not a valid action')
        else:
            print(str(act))
            attr.append(act)


class CLIError(Exception):
    '''Generic exception to raise and log different fatal errors.'''
    def __init__(self, msg):
        super(CLIError).__init__(type(self))
        self.msg = "E: %s" % msg

    def __str__(self):
        return self.msg

    def __unicode__(self):
        return self.msg


def main(argv=None):  # IGNORE:C0111
    '''Command line options.'''

    if argv is None:
        argv = sys.argv
    else:
        sys.argv.extend(argv)

    program_name = os.path.basename(sys.argv[0])
    program_version = "v%s" % __version__
    program_build_date = str(__updated__)
    program_version_message = '%%(prog)s %s (%s)' % (program_version, program_build_date)
    program_shortdesc = __import__('__main__').__doc__.split("\n")[1]
    program_license = '''%s

  Created by user_name on %s.
  Copyright 2016 organization_name. All rights reserved.

  Licensed under the Apache License 2.0
  http://www.apache.org/licenses/LICENSE-2.0

  Distributed on an "AS IS" basis without warranties
  or conditions of any kind, either express or implied.

USAGE
''' % (program_shortdesc, str(__date__))

    try:
        # Setup argument parser
        parser = ap.ArgumentParser(description=program_license, formatter_class=ap.RawDescriptionHelpFormatter)
        parser.add_argument("-c", "--conf", dest="conf", action=ActionConf)
        parser.add_argument("-b", "--broadcast", dest="broadcast")
        parser.add_argument("-m", "--mqtt-host", dest="mqtt_host", type=valid_host)
        parser.add_argument("-k", "--mqtt-port", dest="mqtt_port", type=valid_port)
        parser.add_argument("-f", "--prime-host", dest="prime_host", type=valid_host)
        parser.add_argument("-y", "--prime-port", dest="prime_port", type=valid_port)
        parser.add_argument("-w", "--prime-port2", dest="prime_port2", type=valid_port)
        parser.add_argument("-q", "--prime-code", dest="prime_code", type=valid_code)
        parser.add_argument("-z", "--prime-pass", dest="prime_pass")
        parser.add_argument("-p", "--port", dest="port", type=valid_port)
        parser.add_argument("-s", "--tcpport", dest="tcpport", type=valid_port)
        parser.add_argument("-g", "--httpport", dest="httpport", type=valid_port)
        parser.add_argument("-t", "--timeout", dest="timeout", type=valid_timeout)
        parser.add_argument("-j", "--emitdelay", dest="emit_delay", type=valid_delay)
        parser.add_argument("-r", "--retry", dest="retry", type=valid_retry)
        parser.add_argument("-a", "--action", dest="actions", nargs='+', action=ActionAction)
        parser.add_argument('-x', '--active_on_finish', action='store_true', dest="active_on_finish")
        parser.add_argument('-V', '--version', action='version', version=program_version_message)
        parser.add_argument('-d', '--debug', action='store_true', dest="debug")
        parser.add_argument('-e', '--remote', action='store_true', dest="remote")

        parser.set_defaults(conf=os.path.join(os.getcwd(), 'devices.xml'),
                            devices={},
                            mqtt_host='',
                            mqtt_port=1883,
                            emit_delay=0,
                            port=10000,
                            tcpport=2802,
                            httpport=2803,
                            actions=[],
                            broadcast='255.255.255.255',
                            active_on_finish=False,
                            timeout=1,
                            retry=3,
                            debug=False,
                            remote=False,
                            prime_host='',
                            prime_port=80,
                            prime_port2=6004,
                            prime_code='',
                            prime_pass=''
                            )

        def connect_devices(devices):
            for _, dv in devices.copy().items():
                dv.connect_devices(devices)

        def add_discovered_devices(action, devices, mqtt_host, mqtt_port, emit_delay, **kwargs):
            for _, v in action.hosts.copy().items():
                # print("current "+k+" nm "+v.name+" lndv "+str(len(devices)))
                already_saved_device = None
                # print("Confronto "+v.name)
                for _, dv in devices.copy().items():
                    # print("VS "+v.name+'/'+dv.name)
                    if v.mac == dv.mac:
                        already_saved_device = dv
                        break
                    # elif v.name==dv.name:
                    #    print("Are you sure? "+v.name+"->"+v.mac.encode('hex')+"/"+dv.mac.encode('hex'))
                if already_saved_device is None:
                    # print("changed "+str(v))
                    devices.update({v.name: v})
                    action.m_device = True
                    if len(mqtt_host):
                        v.mqtt_start((mqtt_host, mqtt_port))
                else:
                    v.copy_extra_from(already_saved_device)
                    v.name = already_saved_device.name
                    if isinstance(v, IrManager):
                        v.set_emit_delay(emit_delay)
                    devices.update({already_saved_device.name: v})
            connect_devices(devices)

        def save_modified_devices(save_filename, save_devices, debug, device, action, **kwargs):
            # print("lensv "+str(len(save_devices)))
            save = True
            if isinstance(action, ActionDiscovery):
                save = debug or action.modifies_device()
            elif isinstance(action, ActionViewtable):
                save = False
                if isinstance(action, ActionViewtable1):
                    save = debug
                elif isinstance(action, ActionViewtable4):
                    dn = device.default_name()
                    if dn in save_devices and dn != device.name:
                        del save_devices[dn]
                        save_devices[device.name] = device
                        save = True
                    else:
                        save = debug
                elif isinstance(device, DeviceS20):
                    save = debug
                elif isinstance(device, IrManager):
                    save = debug or action.modifies_device()
            elif isinstance(action, ActionStatechange) or isinstance(action, ActionSubscribe):
                save = debug
            if save:
                Device.save(save_devices, save_filename,
                            (DEVICE_SAVE_FLAG_MAIN | DEVICE_SAVE_FLAG_TABLE) if debug else DEVICE_SAVE_FLAG_MAIN)

        def terminate_on_finish(actionexec, force=False, **kwargs):
            if force or actionexec.action_list_len() <= 1:
                print("Terminating...")
                global term_called
                term_called = True

        def do_timer_action(device, timerobj, actionexec, **kwargs):
            act = ActionEmitir(device, *tuple(timerobj['action'].split(' ')))
            actionexec.insert_action(act)

        def insert_arrived_action(cmdline, action, devices, actionexec, pos=-1, **kwargs):
            if action is None:
                spl = shlex.split(cmdline)
                if len(spl) > 1:
                    action = ActionAction.create_action(spl[1:], devices)
                    randid = -1
                    if action is not None:
                        randid = int(spl[0])
                        action.set_randomid(randid)
                        EventManager.fire(eventname='ActionParsed', randid=randid, action=action)
                        actionexec.insert_action(action, pos)
            else:
                actionexec.insert_action(action, pos)

        def handle_device_dl(action, devices, **kwargs):
            if action is not None:
                action.set_devices(devices)

        def process_state_change(hp, newstate, devices, mac, actionexec, **kwargs):
            print(f'ExtStateChange {mac}')
            for _, dv in devices.copy().items():
                if mac == dv.mac:
                    act = ActionNotifystate(dv, newstate)
                    actionexec.insert_action(act)

        def mqtt_on_connect(client, userdata, flags, rc):
            client.subscribe([("cmnd/#", 0,)])

        def mqtt_on_message(client, userdata, msg):
            topic = msg.topic
            i = topic.rfind("/")
            if i >= 0 and i < len(topic) - 1:
                sub = topic[i+1:]
                if sub == "devicedl":
                    resp = json.dumps(userdata.devices)
                    client.publish("stat/devicedl", resp)

        def mqtt_init(hp, ud):
            client = paho.Client(userdata=ud)
            client.on_connect = mqtt_on_connect
            client.on_message = mqtt_on_message
            print("mqtt_start (%s:%d)" % hp)
            client.connect_async(hp[0], port=hp[1])
            client.loop_start()
            return client

        def mqtt_stop(client):
            client.loop_stop()
            client.disconnect()

        # Process arguments
        signal(SIGTERM, sigterm_handler)
        print("Parsing args")
        args = parser.parse_args()
        mqtt_client = None
        if len(args.mqtt_host):
            for _, d in args.devices.copy().items():
                d.mqtt_start((args.mqtt_host, args.mqtt_port))
            mqtt_client = mqtt_init((args.mqtt_host, args.mqtt_port), args)

        print(str(args))
        connect_devices(args.devices)
        actionexec = ActionExecutor()
        if not args.active_on_finish:
            EventManager.on('ActionDone', terminate_on_finish, actionexec=actionexec)
        pars = {'save_filename': args.conf, 'save_devices': args.devices, 'debug': args.debug}
        EventManager.on('TimerAction', do_timer_action, actionexec=actionexec, **pars)
        EventManager.on('ActionDiscovery', add_discovered_devices, devices=args.devices, mqtt_host=args.mqtt_host, mqtt_port=args.mqtt_port, emit_delay=args.emit_delay)
        EventManager.on('ExtInsertAction', insert_arrived_action, devices=args.devices, actionexec=actionexec)
        EventManager.on('ExtChangeState', process_state_change, actionexec=actionexec, devices=args.devices)
        EventManager.on('ActionDiscovery', save_modified_devices, **pars)
        EventManager.on('ActionLearnir', save_modified_devices, **pars)
        EventManager.on('ActionEditraw', save_modified_devices, **pars)
        EventManager.on('ActionSubscribe', save_modified_devices, **pars)
        EventManager.on('ActionViewtable1', save_modified_devices, **pars)
        EventManager.on('ActionInsertKey', save_modified_devices, **pars)
        EventManager.on('ActionViewtable3', save_modified_devices, **pars)
        EventManager.on('ActionViewtable4', save_modified_devices, **pars)
        EventManager.on('ActionStatechange', save_modified_devices, **pars)
        EventManager.on('ActionStateon', save_modified_devices, **pars)
        EventManager.on('ActionStateoff', save_modified_devices, **pars)
        EventManager.on('ActionCreatesh', save_modified_devices, **pars)
        EventManager.on('ActionDevicedl', handle_device_dl, devices=args.devices, **pars)
        EventManager.on('ActionExit', terminate_on_finish, actionexec=actionexec, force=True)
        actionexec.configure(args)
        if len(args.mqtt_host):
            actionexec.insert_action(ActionPause("5"))
            actionexec.insert_action(ActionDiscovery())
        actionexec.insert_action(args.actions)

        stopped = False
        numv = 2
        while threading.active_count() > 1 and numv > 1:
            try:
                time.sleep(1)
                if stopped:
                    thl = threading.enumerate()
                    rv = ""
                    numv = 0
                    for th in thl:
                        if not th.daemon:
                            numv += 1
                        rv += th.name + " "
                    print("TH=%s" % rv)
                elif term_called:
                    raise KeyboardInterrupt
            except KeyboardInterrupt:
                if not stopped:
                    print("Stopping")
                    stopped = True
                    actionexec.stop()
                    if mqtt_client:
                        mqtt_stop(mqtt_client)
                    for _, k in args.devices.copy().items():
                        k.on_stop()
        return 0
    except KeyboardInterrupt:
        # handle keyboard interrupt ###
        return 0
    except Exception as e:
        if DEBUG or TESTRUN:
            raise(e)
        traceback.print_exc()
        indent = len(program_name) * " "
        sys.stderr.write(program_name + ": " + repr(e) + "\n")
        sys.stderr.write(indent + "  for help use --help")
        return 2


if __name__ == "__main__":
    if DEBUG:
        sys.argv.append("-h")
        sys.argv.append("-v")
        sys.argv.append("-r")
    if TESTRUN:
        import doctest
        doctest.testmod()
    if PROFILE:
        import cProfile
        import pstats
        profile_filename = 'main_profile.txt'
        cProfile.run('main()', profile_filename)
        statsfile = open("profile_stats.txt", "wb")
        p = pstats.Stats(profile_filename, stream=statsfile)
        stats = p.strip_dirs().sort_stats('cumulative')
        stats.print_stats()
        statsfile.close()
        sys.exit(0)
    sys.exit(main())
