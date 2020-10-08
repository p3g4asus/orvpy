'''
Created on 01 gen 2016

@author: Matteo
'''
import abc
import binascii
import collections
import json
import random
import re
import select
import socket
import string
import struct
import sys
import threading
import time
import traceback
import urllib
from _collections_abc import dict_values
from datetime import date, datetime, timedelta
from xml.dom import minidom
from xml.etree import ElementTree
from xml.etree.ElementTree import Element, SubElement
from xml.sax.saxutils import escape

import broadlink
import orvibo.event as event
import paho.mqtt.client as paho
import requests
import upnpclient
from Crypto.Cipher import AES
from orvibo.samsung_mappings import samsung_mappings

import lircbroadlink
import samsungctl

if sys.version_info < (3, 0):
    import SocketServer
    import SimpleHTTPServer
else:
    long = int
    import socketserver as SocketServer
    import http.server as SimpleHTTPServer
    from _collections_abc import dict_keys
    from functools import reduce


def s2b(data):
    if isinstance(data, bytes):
        return data
    else:
        return bytes(data, 'utf8')


def b2s(data):
    if isinstance(data, str):
        return data
    else:
        return data.decode('utf8')


def uunq(url):
    if sys.version_info < (3, 0):
        return urllib.unquote(url).decode("utf-8")
    else:
        return urllib.parse.unquote(url)


def upar(url):
    if sys.version_info < (3, 0):
        import urlparse
        return urlparse.urlparse(url)
    else:
        return urllib.parse.urlparse(url)


def cmp_to_key(mycmp):
    """Convert a cmp= function into a key= function"""
    class K(object):
        __slots__ = ['obj']

        def __init__(self, obj):
            self.obj = obj

        def __lt__(self, other):
            return mycmp(self.obj, other.obj) < 0

        def __gt__(self, other):
            return mycmp(self.obj, other.obj) > 0

        def __eq__(self, other):
            return mycmp(self.obj, other.obj) == 0

        def __le__(self, other):
            return mycmp(self.obj, other.obj) <= 0

        def __ge__(self, other):
            return mycmp(self.obj, other.obj) >= 0
        __hash__ = None
    return K


def tohexb(data):
    if sys.version_info < (3, 0) or isinstance(data, bytes):
        return binascii.hexlify(data)
    elif isinstance(data, str):
        return binascii.hexlify(s2b(data))


def tohexs(data):
    return b2s(tohexb(data))


def bfromhex(data):
    return binascii.unhexlify(data)


def _default(self, obj):
    try:
        rv = getattr(obj, "to_json", None)
        if rv is not None:
            return rv()
        elif sys.version_info >= (3, 0) and isinstance(obj, (dict_keys, dict_values)):
            return list(obj)
        else:
            return obj.__dict__
    except (AttributeError, TypeError):
        traceback.print_exc()
        return _default.default(obj) if sys.version_info < (3, 0) else obj


_default.default = json.JSONEncoder().default  # Save unmodified default.
json.JSONEncoder.default = _default  # replacement

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
STATECHANGE_ID = b'\x64\x63'
STATECHANGE_LEN = b'\x00\x17'
LEARNIR_ID = b'\x6c\x73'
LEARNIR_LEN = b'\x00\x18'
LEARNIR_2 = b'\x01\x00\x00\x00\x00\x00'
EMITIR_ID = b'\x69\x63'
EMITIR_2 = b'\x65\x00\x00\x00'
INSERT_ACTION_ID = b'\x11\x12'
STATECHANGE_EXT_ID = b'\x73\x66'
DEFAULT_RESUBSCRIPTION_STIMEOUT = 7
DEFAULT_RESUBSCRIPTION_TIMEOUT = 60
VIEW_TABLE_LEN = b'\x00\x1d'
VIEW_TABLE_ID = b'\x72\x74'
WRITE_TABLE_ID = b'\x74\x6d'
MODRECORD_CODE = 1
ADDRECORD_CODE = 0
DELRECORD_CODE = 2
RV_DATA_WAIT = 10523
RV_NOT_EXECUTED = -1
RV_ASYNCH_EXEC = -2
DEVICE_SAVE_FLAG_TABLE = 1
DEVICE_SAVE_FLAG_MAIN = 2
PK_MSG_ID = b'\x70\x6B'
DK_MSG_ID = b'\x64\x6B'
PK_KEY = 'khggd54865SNJHGF'


'''
Created on 12/ott/2014

@author: Matteo
'''


class TCPServerHandler(SocketServer.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

#     def __init__(self):
#         super(ServerHandler,self).__init__()
#         self.stopped  = True

    def stop(self):
        self.stopped = True
        if self.request is not None:
            try:
                self.request.close()
                self.request = None
            except:
                traceback.print_exc()

    def handle(self):
        self.stopped = False
        keyv = '{}:{}'.format(*self.client_address)
        threading.currentThread().name = ("TCPServerHandler")
        print(keyv+" connected")
        self.request.setblocking(0)
        olddata = b''
        serv = self.server.s
        serv.setclienthandler(self.client_address, self)
        wlist = []
        remain = b''
        disconnectat = 0
        parser = RoughParser()
        while not serv.stopped and not self.stopped:
            try:
                ready = select.select([self.request], wlist, [], 0.5)
                if disconnectat > 0 and time.time() >= disconnectat:
                    break
                if ready[0]:
                    data = self.request.recv(4096)
                    if len(data) > 0:
                        print("RTCP ["+keyv+"/"+str(len(data))+"] <-"+tohexs(data))
                        data = olddata+data
                        while True:
                            dictout = parser.parse(
                                serv.getclientinfo(self.client_address), data)
                            rv = dictout['idxout']
                            if 'disconnecttimer' in dictout:
                                disconnectat = dictout['disconnecttimer']
                            if 'reply' in dictout:
                                remain += dictout['reply']
                                del dictout['reply']
                            if rv and rv > 0:
                                tp = dictout['type']
                                if tp == b"mfz" or tp == b"cry":
                                    serv.setclientinfo(
                                        self.client_address, dictout)
                                data = data[rv:]
                                if len(data):
                                    continue
                            elif rv == RoughParser.DISCARD_BUFFER:
                                data = b''
                            elif rv == RoughParser.UNRECOGNIZED:
                                event.EventManager.fire(
                                    eventname='RawDataReceived', hp=self.client_address, data=data)
                                data = b''
                            break
                        olddata = data
                    else:
                        raise Exception("Readline failed: connection closed?")
                if ready[1] or len(wlist) == 0:

                    if len(remain) == 0:
                        remain = serv.dowrite(self.client_address)
                    if len(remain) > 0:
                        print("Sending packet to %s:%d" % self.client_address)
                        nb = self.request.send(remain)
                        print("Sent")
                        # if tp=="cry":
                        #    print("STCP ["+keyv+"/"+str(len(remain))+"/"+str(nb)+"] <-"+remain.encode('hex'))
                        remain = remain[nb:]
                        wlist = [self.request]
                    else:
                        wlist = []
            except:
                traceback.print_exc()
                break
        print(keyv+" DISCONNECTED")
        serv.unsetclientinfo(self.client_address)
        print(keyv+" DELETED")
        self.stop()


class EthSender(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self):
        pass

    @abc.abstractmethod
    def stop(self):
        pass

    @abc.abstractmethod
    def send_packet(self, addr, packet):
        """Retrieve data from the input source and return an object."""
        return -1


class SendBufferTimer(object):
    ACTION_FAILED = -1
    ACTION_OK = -2
    stringall = string.lowercase if sys.version_info < (
        3, 0) else string.ascii_lowercase + string.digits
    SERIAL = 0

    @staticmethod
    def get_serial():
        serial = SendBufferTimer.SERIAL
        SendBufferTimer.SERIAL += 1
        return serial

    @staticmethod
    def generatestring(ln):
        return ''.join(random.sample(SendBufferTimer.stringall, ln))

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
            print("K=%s Computed CRC %08X vs %s" %
                  (b2s(key), valasci, tohexs(data[6:10])))
            if valasci == struct.unpack('>i', data[6:10])[0]:
                cry = AES.new(s2b(key), AES.MODE_ECB)
                msg = cry.decrypt(data[42:])
                print("Decrypted MSG %s" % b2s(msg))
                jsono = json.loads(msg[0:msg.rfind(b'}')+1])
                return {'msg': jsono, 'convid': b2s(data[10:42])}
        except:
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
                print("exitv = "+str(exitv))
                if exitv is not None and exitv != RV_DATA_WAIT:
                    self.set_finished(exitv)
            return rv
        except:
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
            print("Timeout in action Retry!")
        else:
            print("Timeout in action fail!")
            self.set_finished(None)

    def has_failed(self):
        return self.status == SendBufferTimer.ACTION_FAILED

    def has_succeeded(self):
        return self.status == SendBufferTimer.ACTION_OK

    def schedule(self):
        if self.action is not None and self.timeout is not None and self.timeout > 0:
            self.timer = threading.Timer(self.timeout, self.manage_timeout, ())
            self.timer.start()
            print("Scheduling timeouttimer "+str(self.timeout))
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
                convid = SendBufferTimer.generatestring(32)
            if 'serial' in jsono and jsono['serial'] is None:
                jsono['serial'] = SendBufferTimer.get_serial()
            if 'key' in jsono and jsono['key'] is None:
                jsono['key'] = SendBufferTimer.generatestring(16)
            msg = s2b(json.dumps(jsono))
            print("Encrypting with %s MSG %s" % (b2s(key), b2s(msg)))
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
        except:
            traceback.print_exc()
            return b''


class TCPClient(EthSender):
    def __init__(self, timeo):
        super(TCPClient, self).__init__()
        self.timeout = timeo

    def stop(self):
        pass

    def send_packet(self, addr, packet):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect the socket to the port where the server is listening
        try:
            sock.settimeout(self.timeout)
            sock.connect(addr)
            sock.sendall(bytearray(packet))
            sock.close()
            return len(packet)
        except:
            traceback.print_exc()
            return -1


class HTTPServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    RESP_UNINIT = -1
    RESP_WAIT = 0
    RESP_OK = 1

    def __init__(self, request, client_address, server):
        self.resp_status = HTTPServerHandler.RESP_UNINIT
        self.resp_val = {}
        event.EventManager.on('ActionParsed', self.schedule_response)
        SimpleHTTPServer.SimpleHTTPRequestHandler.__init__(
            self, request, client_address, server)

    def setup(self):
        SimpleHTTPServer.SimpleHTTPRequestHandler.setup(self)
        self.request.settimeout(60)

    def log(self, msg):
        print("[%s] (%s:%d) -> %s" % (self.__class__.__name__,
                                      self.client_address[0],
                                      self.client_address[1],
                                      msg))

    def schedule_response(self, randid, action, **kwargs):
        self.log("action parsed")
        if action is not None:
            if randid == self.client_address[1]:
                self.server.s.schedule_action(randid, self)
                self.log("action scheduled")
        else:
            self.resp_val = {'action': None, 'retval': None}
            self.resp_status = HTTPServerHandler.RESP_OK
            self.log("schedule_response resp OK")

    def write_response_base(self, obj):
        self.protocol_version = 'HTTP/1.1'
        if 'action' in obj and obj['action'] is not None:
            self.send_response(200, 'OK')
        else:
            self.send_response(403, 'Forbidden')
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(s2b(json.dumps(obj)))

    def write_response(self, device, action, retval):
        self.resp_val = {'action': action, 'retval': retval}
        self.resp_status = HTTPServerHandler.RESP_OK
        self.log("write_response resp OK")

    def do_GET(self):
        start_wait = time.time()
        self.log(uunq(self.path[1:]))
        self.resp_status = HTTPServerHandler.RESP_WAIT
        event.EventManager.fire(eventname='ExtInsertAction',
                                cmdline=str(self.client_address[1]) + " " +
                                uunq(self.path[1:]), action=None)
        while self.resp_status == HTTPServerHandler.RESP_WAIT and not self.server.s.stopped:
            time.sleep(0.2)
            if time.time() - start_wait > 30:
                self.resp_val = {}
                break
        self.log("write response NOW")
        self.write_response_base(self.resp_val)
        # Write the response

        # self.path = '/'
        # return SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)


class HTTPServer(threading.Thread):

    def __init__(self, tcpport):
        super(HTTPServer, self).__init__()
        self.port = tcpport
        self.server = None
        self.stopped = True
        self.actions = {}
        self.cond = threading.Condition()
        self.name = ("HTTPServer")

    def stop(self):
        if self.server is not None:
            self.cond.acquire()
            self.stopped = True
            self.actions = {}
            self.cond.release()
            self.server.shutdown()
            # self.server.socket.shutdown(SHUT_RDWR)
            # self.server.socket.close()
            self.server = None
        else:
            self.stopped = True

    def schedule_action(self, randid, client):
        if not self.stopped:
            self.cond.acquire()
            self.actions[str(randid)] = client
            self.cond.release()

    def run(self):
        event.EventManager.on('ActionDone', self.handle_action_done)
        self.stopped = False
        while not self.stopped:
            try:
                self.server = SocketServer.ThreadingTCPServer(
                    ("0.0.0.0", self.port), HTTPServerHandler)
                break
            except:
                traceback.print_exc()
                time.sleep(5)
        if self.server is not None:
            self.server.s = self
            self.server.serve_forever()

    def handle_action_done(self, device, action, retval, **kwargs):
        if not self.stopped:
            s = str(action.randomid)
            client = None
            print("Searching http client")
            self.cond.acquire()
            if s in self.actions:
                client = self.actions[s]
                del self.actions[s]
            self.cond.release()
            if client is not None:
                client.log("Client found")
                client.write_response(device, action, retval)


class TCPServer(threading.Thread):

    def __init__(self, tcpport):
        super(TCPServer, self).__init__()
        SocketServer.TCPServer.allow_reuse_address = True
        self.port = tcpport
        self.server = None
        self.stopped = True
        self.towrite = {}
        self.cond = threading.Condition()
        self.clientinfo = {}
        self.clienthandler = {}
        self.timer = None
        self.name = ("TCPServer")

    def stop(self):
        if self.server is not None:
            self.cond.acquire()
            self.stopped = True
            self.towrite = {}
            self.cond.release()
            self.clientinfo = {}
            self.clienthandler = {}
            self.server.shutdown()
            # self.server.socket.shutdown(SHUT_RDWR)
            # self.server.socket.close()
            self.server = None
            if self.timer is not None:
                self.timer.cancel()
                self.timer = None
        else:
            self.stopped = True

    def setclientinfo(self, addr, dictout):
        keyv = '{}:{}'.format(*addr)
        self.cond.acquire()
        self.clientinfo[keyv] = dictout
        self.cond.release()

    def setclienthandler(self, addr, handler):
        keyv = '{}:{}'.format(*addr)
        self.cond.acquire()
        self.clienthandler[keyv] = handler
        self.cond.release()

    def getclientinfo(self, addr):
        self.cond.acquire()
        keyv = '{}:{}'.format(*addr)
        if keyv in self.clientinfo:
            ci = self.clientinfo[keyv]
        else:
            ci = {'addr': addr}
        self.cond.release()
        return ci

    def unsetclientinfo(self, addr):
        self.cond.acquire()
        keyv = '{}:{}'.format(*addr)
        # print("02_unsetting %s" %keyv)
        if keyv in self.towrite:
            # print("02_found in towrite")
            for x in self.towrite[keyv]:
                if isinstance(x, SendBufferTimer):
                    x.set_finished(None)
                    # print("02_setfinish")
            del self.towrite[keyv]
        if keyv in self.clientinfo:
            # print("02_found in clientinfo")
            del self.clientinfo[keyv]
        if keyv in self.clienthandler:
            # print("02_found in clienthandler")
            self.clienthandler[keyv].stop()
            del self.clienthandler[keyv]
        self.cond.release()

    def handle_action_done(self, device, action, retval, **kwargs):
        if isinstance(action, ActionPing) and self.timer is not None:
            self.timer_ping_init()
        threading.currentThread().name = ("handle_action_done")
        strout = json.dumps({'action': action, 'retval': retval})+'\n'
        if device is not None and action is not None:
            lst = action.mqtt_publish_onfinish(retval)
            lst.extend(device.mqtt_publish_onfinish(action, retval))
            device.mqtt_publish_all(lst)
        self.schedulewrite(strout)

    def timer_ping_init(self):
        if self.timer is not None:
            self.timer.cancel()
        self.timer = threading.Timer(
            60, self.handle_action_done, (None, ActionPing(), 1,))
        self.timer.name = ("timerping")
        self.timer.daemon = True
        self.timer.start()

    def run(self):
        event.EventManager.on('ActionDone', self.handle_action_done)
        self.stopped = False
        self.timer_ping_init()
        while not self.stopped:
            try:
                self.server = SocketServer.ThreadingTCPServer(
                    ("0.0.0.0", self.port), TCPServerHandler)
                break
            except:
                traceback.print_exc()
                time.sleep(5)
        if self.server is not None:
            self.server.s = self
            self.server.serve_forever()

    def dowrite(self, addr):
        snd = b''
        self.cond.acquire()
        keyv = '{}:{}'.format(*addr)
        if not self.stopped and keyv in self.clientinfo and keyv in self.towrite:
            while len(snd) == 0 and len(self.towrite[keyv]) > 0:
                snd = self.towrite[keyv][0]
                if isinstance(snd, (bytes, str)):
                    snd = s2b(self.towrite[keyv].pop(0))
                    # print("01_1")
                elif snd.timer is not None:  # dobbiamo aspettare la risposta
                    snd = b''
                    # print("01_2")
                    break
                elif snd.has_succeeded() or snd.has_failed():
                    if "sender" in self.clientinfo[keyv]:
                        del self.clientinfo[keyv]['sender']
                    if snd.has_failed():
                        self.clientinfo[keyv]['disconnecttimer'] = time.time()
                    self.towrite[keyv].pop(0)
                    snd = b''
                    # print("01_3")
                else:  # dobbiamo ancora spedire il pacchetto o c'e gia stato un timeout ma dobbiamo fare altri tentativi
                    snd.clientinfo = self.clientinfo[keyv]
                    self.clientinfo[keyv]['sender'] = snd
                    snd = snd.schedule()
                    # print("01_4")

        self.cond.release()
        return snd

    def innerschedule(self, keyv, w):
        if keyv not in self.towrite:
            self.towrite[keyv] = []
        if isinstance(w, list):
            self.towrite[keyv].extend(w)
        else:
            self.towrite[keyv].append(w)

    def get_connected_clients(self):
        lst = dict()
        for _, v in self.clientinfo.items():
            if 'device' in v:
                keyv = '{}:{}'.format(*(v['hp']))
                lst[keyv] = v['device']
        return lst

    def schedulewrite(self, w):
        exitv = False
        if not self.stopped and self.server is not None:
            self.cond.acquire()

            if not isinstance(w, SendBufferTimer):
                for keyv, v in self.clientinfo.items():
                    if v['type'] == b'mfz':
                        self.innerschedule(keyv, w)
                        exitv = True
            else:
                keyv = '{}:{}'.format(*(w.addr))
                if keyv not in self.clientinfo:
                    for keyv, v in self.clientinfo.items():
                        if 'mac' in v and v['mac'] == w.mac:
                            self.innerschedule(keyv, w)
                            exitv = True
                            break
                else:
                    exitv = True
                    self.innerschedule(keyv, w)

            self.cond.release()
        return exitv


class RoughParser(object):
    DISCARD_BUFFER = -2000
    UNRECOGNIZED = -3000
    STILL_WAIT = -1000

    def __init__(self, reply=None):
        # self.pk = AES.new(PK_KEY, AES.MODE_ECB)
        pass

    def parse(self, clinfo, data):
        if isinstance(clinfo, dict):
            returnv = clinfo
        else:
            returnv = {'addr': clinfo}

        hp = returnv['addr']
        if len(data) > 6 and data[0:1] == b'@':
            returnv['type'] = b'mfz'
            idx = data.find(b'\n')
            if idx < 0:
                if len(data) >= 200:
                    returnv['idxout'] = RoughParser.DISCARD_BUFFER
                else:
                    returnv['idxout'] = RoughParser.STILL_WAIT
            else:
                print("R ["+hp[0]+":"+str(hp[1])+"] <-"+b2s(data))
                event.EventManager.fire(eventname='ExtInsertAction', hp=hp,
                                        cmdline=b2s(data[1:]), action=None)
                returnv['idxout'] = idx+1
        elif len(data) > 7 and data[0:2] == MAGIC:
            msgid = data[4:6]
            ln = struct.unpack('>H', data[2:4])[0]
            print("Detected Magic with ln %d and id %s" % (ln, b2s(msgid)))
            if len(data) >= ln:
                returnv['type'] = b'cry' if msgid == PK_MSG_ID or msgid == DK_MSG_ID else b'orv'
                returnv['idxout'] = ln
                contentmsg = data[0:ln]
                if msgid == PK_MSG_ID:
                    outv = SendBufferTimer.handle_incoming_data(contentmsg)
                    if outv is not None:
                        obj = outv['msg']
                        if obj['cmd'] == 0:
                            name = obj['hardwareVersion']
                            # obj['serial']
                            dictout = {'serial': 0, 'cmd': 0,
                                       'key': None, 'status': 0}
                            returnv['name'] = name.replace(' ', '_')
                            returnv['reply'] = SendBufferTimer.get_send_bytes(
                                dictout, None, typemsg=b"pk")
                            returnv['key'] = dictout['key']
                elif msgid == DK_MSG_ID:
                    if 'sender' in clinfo:
                        outv = clinfo['sender'].handle_incoming_data2(
                            contentmsg)
                    else:
                        outv = SendBufferTimer.handle_incoming_data(
                            contentmsg, returnv['key'])
                    if outv is not None:
                        obj = outv['msg']
                        if obj['cmd'] == 6:
                            returnv['hp'] = hp
                            returnv['localIp'] = obj['localIp']
                            returnv['localPort'] = obj['localPort']
                            returnv['password'] = obj['password']
                            returnv['mac'] = tohexs(obj['uid'])
                            returnv['convid'] = outv['convid']
                            dictout = {
                                'serial': obj['serial'], 'cmd': 6, 'status': 0}
                            returnv['reply'] = SendBufferTimer.get_send_bytes(
                                dictout, outv['convid'], key=returnv['key'], typemsg=b"dk")
                            dev = DeviceCT10(hp=hp,
                                             mac=returnv['mac'],
                                             name=returnv['name'] +
                                             '_'+obj['uid'],
                                             key=returnv['key'],
                                             password=obj['password'],
                                             deviceid=SendBufferTimer.generatestring(
                                                 32),
                                             clientsessionid=SendBufferTimer.generatestring(
                                                 32),
                                             hp2=(obj['localIp'], obj['localPort']))
                            returnv['device'] = dev
                            act = ActionDiscovery()
                            act.hosts[obj['uid']] = dev
                            event.EventManager.fire(eventname='ActionDiscovery',
                                                    device=dev, action=act, retval=1)
                        elif obj['cmd'] == 116 or obj['cmd'] == 32:
                            dictout = {'serial': obj['serial'],
                                       'cmd': obj['cmd'], 'status': 0, 'uid': obj['uid']}
                            returnv['reply'] = SendBufferTimer.get_send_bytes(
                                dictout, outv['convid'], key=returnv['key'], typemsg=b"dk")
                            returnv['disconnecttimer'] = time.time()+3*60
                else:
                    if msgid == STATECHANGE_EXT_ID or msgid == DISCOVERY_ID:
                        event.EventManager.fire(eventname='ExtChangeState', hp=hp, mac=DeviceUDP.mac_from_data(
                            data), newstate="1" if data[-1:] == b'\x01' else "0")
                    returnv['idxout'] = RoughParser.UNRECOGNIZED
            else:
                returnv['idxout'] = RoughParser.STILL_WAIT
        else:
            returnv['idxout'] = RoughParser.UNRECOGNIZED
        return returnv


class EthBuffCont(object):
    def __init__(self, ad, d):
        self.data = d
        self.addr = ad


class ActionExecutor(threading.Thread):
    def __init__(self, *args, **kwargs):
        super(ActionExecutor, self).__init__(*args, **kwargs)
        self.udpmanager = None
        self.stopped_ev = threading.Event()
        self.stopped_ev.set()
        self.asynch_action = None
        self.asynch_action_l = None
        self.action_list_l = None
        self.action_list = []
        self.stopped = True
        self.tcpserver = None
        self.httpserver = None
        self.asynch_action_rv = RV_NOT_EXECUTED
        self.prime_hp = ('', 80)
        self.prime_code = ''
        self.prime_pass = ''
        self.prime_port2 = 0
        self.name = ("ActionExecutor")

    def configure(self, options):
        self.prime_hp = (options.prime_host, options.prime_port)
        self.prime_code = options.prime_code
        self.prime_pass = options.prime_pass
        self.prime_port2 = options.prime_port2
        if self.action_list_l is None:
            self.action_list_l = threading.Condition()
            self.asynch_action_l = threading.Condition()
            self.udpmanager = UdpManager(options)
            self.udpmanager.configure()
            self.tcpserver = TCPServer(options.tcpport)
            self.httpserver = HTTPServer(options.httpport)
            self.start()
            self.tcpserver.start()
            self.httpserver.start()

    def notify_asynch_action_done(self, act, rv):
        self.asynch_action_l.acquire()
        if act == self.asynch_action or act is None:
            self.asynch_action = None
            self.asynch_action_rv = rv
            self.asynch_action_l.notify_all()
            # print("WE "+str(act)+"/"+str(rv))
        else:
            # print("NE "+str(act)+"/"+str(rv)+"/"+str(self.asynch_action))
            rv = None
        self.asynch_action_l.release()
        return rv

    def wait_asynch_action_done(self, act):
        self.asynch_action_l.acquire()
        if self.asynch_action is None:
            self.asynch_action = act
            self.asynch_action_l.wait()
        rv = self.asynch_action_rv
        self.asynch_action_l.release()
        return rv

    def stop(self):
        if not self.stopped:
            self.stopped = True
            self.notify_asynch_action_done(None, None)
            self.stopped_ev.wait()
        if self.tcpserver is not None:
            print("Stopping TCP Server")
            self.tcpserver.stop()
            self.tcpserver = None
        if self.httpserver is not None:
            print("Stopping TCP Server")
            self.httpserver.stop()
            self.httpserver = None
        if self.udpmanager is not None:
            print("Stopping UDPManager")
            self.udpmanager.stop()
            self.udpmanager = None

    def insert_action(self, action, pos=-1):
        self.action_list_l.acquire()
        if pos < 0:
            if isinstance(action, list):
                self.action_list.extend(action)
            else:
                self.action_list.append(action)
        else:
            self.action_list.insert(pos, action)
        self.action_list_l.notifyAll()
        self.action_list_l.release()

    def action_list_len(self):
        self.action_list_l.acquire()
        ln = len(self.action_list)
        self.action_list_l.release()
        return ln

    def run(self):
        self.stopped_ev.clear()
        self.stopped = False
        retval = None
        while not self.stopped:

            while not self.stopped:
                self.action_list_l.acquire()
                # print("ecco00 "+str(len(self.action_list)))
                # print("ecco00 "+str(self.action_list))
                if len(self.action_list):
                    act = self.action_list[0]
                else:
                    act = None
                self.action_list_l.release()
                if act is not None:
                    print("Runing action "+str(act))
                    retval = act.run(self)
                    if retval == RV_ASYNCH_EXEC:
                        retval = self.wait_asynch_action_done(act)
                    print("Action "+str(act)+" run ("+str(retval)+")")
                    if retval is None or retval > 0:
                        self.action_list_l.acquire()
                        if self.stopped:
                            del self.action_list[:]
                        else:
                            self.action_list.remove(act)
                        self.action_list_l.release()
                else:
                    break
            self.action_list_l.acquire()
            self.action_list_l.wait(1)
            self.action_list_l.release()
        self.action_list_l.acquire()
        self.action_list = []
        self.action_list_l.release()
        self.stopped_ev.set()


class ListenerTh(threading.Thread, EthSender):

    def send_packet(self, addr, packet):
        try:
            return self.socket.sendto(bytearray(packet), addr)
        except:
            traceback.print_exc()
            return -1

    def __init__(self, port, *args, **kwargs):
        super(ListenerTh, self).__init__(*args, **kwargs)
        self.port = port
        self.stopped_ev = threading.Event()
        self.stopped_ev.set()
        self.preparse = RoughParser()
        self.socket = None
        self.stopped = True
        self.name = ("ListenerTh")

    def stop(self):
        if self.socket:
            self.stopped = True
            self.socket.sendto(bytearray(b'a'), ('127.0.0.1', self.port))
            self.stopped_ev.wait()
            self.socket.close()
            self.socket = None

    def run(self):
        """ Listen on socket. """
        self.stopped_ev.clear()
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for opt in [socket.SO_BROADCAST, socket.SO_REUSEADDR]:
                self.socket.setsockopt(socket.SOL_SOCKET, opt, 1)
            self.socket.bind(('', self.port))

            self.stopped = False
            while not self.stopped:
                try:
                    print('enterrecv')
                    data, addr = self.socket.recvfrom(1024)
                    print('1) recv %d (%s:%d) '%(0 if not data else len(data),'unkn' if not addr else addr[0],0 if not addr else addr[1]))
                    if data is not None and len(data) and self.preparse.parse(addr, data if data[0:1] != b'@' else data+b'\n')['idxout'] == RoughParser.UNRECOGNIZED:
                        event.EventManager.fire(
                            eventname='RawDataReceived', hp=addr, data=data)
                    print('exitrecv')
                except:
                    traceback.print_exc()
                    break
        except:
            traceback.print_exc()
        self.stopped_ev.set()


class UdpManager(object):
    def __init__(self, options):
        self.port = options.port
        self.retry = options.retry
        self.timeout = options.timeout
        self.broadcast_address = options.broadcast
        self.remote = options.remote
        self.listener = None
        self.sender = None
        self.buffer = {}
        self.buffer_l = None

    def add_to_buffer(self, hp, data, **kwargs):
        rx = re.compile(MAGIC+b'(.{2}).{2}.*'+MAC_START)
        self.buffer_l.acquire()
        # print("unsplit R <-"+data.encode('hex'))
        control = {}
        while True:
            m = re.search(rx, data)
            if m:
                st = m.start()
                ln = struct.unpack('>H', m.group(1))[0]
                # print("st = {} ln = {}".format(st,ln))
                off = st+ln
                if off <= len(data):
                    sect = data[st:off]
                    data = data[off:]
                    keyv = UdpManager.keyfind(hp, sect)
                    if keyv not in control:
                        control[keyv] = 1
                        self.buffer[keyv] = EthBuffCont(hp, sect)
                        print("R ["+keyv+"] <-"+tohexs(sect))
                else:
                    break
            else:
                break
        self.buffer_l.notifyAll()
        self.buffer_l.release()

    def _udp_transact(self, hp, payload, handler, action, timeout=-1, **kwargs):
        """ Complete a UDP transaction.
        UDP is stateless and not guaranteed, so we have to
        take some mitigation steps:
        - Send payload multiple times.
        - Wait for awhile to receive response.
        :param payload: Payload to send.
        :param handler: Response handler.
        :param args: Arguments to pass to response handler.
        :param broadcast: Send a broadcast instead.
        :param timeout: Timeout in seconds.
        """
        u = self
        keyv = UdpManager.keyfind(hp, payload)
        u.buffer_l.acquire()

        host = hp[0]
        broadcast = host is None or (len(host) > 4 and host[-4:] == '.255')
        if broadcast:
            u.buffer.clear()
        elif keyv in u.buffer:
            del u.buffer[keyv]
        u.buffer_l.release()
        if timeout is None or timeout < 0:
            timeout = u.timeout

        if broadcast or u.remote:
            host = u.broadcast_address
        retval = None
        hp2 = (host, u.port if not u.remote or hp[1] <= 0 else hp[1])
        for dd in range(u.retry):
            if len(payload) > 0 and retval != RV_DATA_WAIT:
                try:
                    self.sender.send_packet(hp2, payload)
                    print("S [{}:{}] -> {}".format(hp2[0],
                                                   hp2[1], tohexs(payload)))
                except:
                    traceback.print_exc()
                    return None
            if handler is None:
                return 5
            elif broadcast:
                # print('broadc')
                time.sleep(timeout)
                break
            else:
                # print('no broadc')
                u.buffer_l.acquire()
                # print('acquired')
                buffcont = u.buffer.get(keyv, None)
                if buffcont is None:
                    now = time.time()
                    once = False
                    while time.time() < now+timeout or not once:
                        # print("waiting")
                        u.buffer_l.wait(timeout)
                        # print("waiting f")
                        once = True
                        buffcont = u.buffer.get(keyv, None)
                        if buffcont is not None or u.listener is None:
                            break
                u.buffer_l.release()
                if u.listener is None:
                    return None
                elif buffcont:
                    retval = handler(buffcont.addr, action,
                                     buffcont.data, **kwargs)
                    # print('Handler returned '+str(retval))
                    # Return as soon as a response is received
                    if retval is not None and retval != RV_DATA_WAIT:
                        break
                    else:
                        u.buffer_l.acquire()
                        del u.buffer[keyv]
                        u.buffer_l.release()
                        if retval == RV_DATA_WAIT:
                            dd -= 1
                else:
                    retval = None
        if broadcast:
            u.buffer_l.acquire()
            retval = handler(None, action, u.buffer, **kwargs)
            u.buffer_l.release()
        return retval

    @staticmethod
    def keyfind(addr, data):
        mac = DeviceUDP.mac_from_data(data)
        return tohexs(mac) if mac else "{}:{}".format(*addr)

    def configure(self):
        if self.buffer_l is None:
            self.buffer_l = threading.Condition()
            self.listener = ListenerTh(self.port)
            self.listener.start()
            self.sender = self.listener if not self.remote else TCPClient(
                self.timeout)
            event.EventManager.on('RawDataReceived', self.add_to_buffer)

    def stop(self):
        if self.listener is not None:
            print("Stopping Listener Thread")
            self.listener.stop()
            print("Listener Thread Stopped")
            self.listener = None
        if self.sender is not None:
            print("Stopping Sender")
            self.sender.stop()
            print("Sender Stopped")


def class_forname(kls):
    parts = kls.split('.')
    module = ".".join(parts[:-1])
    m = __import__(module)
    for comp in parts[1:]:
        m = getattr(m, comp, None)
        if m is None:
            break
    return m


class Device(object):
    epoch = datetime.utcfromtimestamp(0)
    dictionary = dict()

    def process_asynch_state_change(self, state):
        pass

    def connect_devices(self, device_map):
        pass

    def state_value_conv(self, s):
        return s

    def mqtt_publish_onfinish(self, action, retval):
        return []

    def mqtt_set_broker(self, hp):
        self.mqtt_stop()
        self.mqtt_start(hp)

    def mqtt_stop(self):
        if self.mqtt_client is not None:
            try:
                self.mqtt_client.loop_stop()
                self.mqtt_client.disconnect()
            except:
                traceback.print_exc()

    def mqtt_topic(self, prefix, suffix):
        return str(prefix+'/'+self.__class__.__name__[6:].lower()+"/"+self.name+"/"+suffix)

    def mqtt_sub(self, topic):
        i = topic.rfind("/")
        if i >= 0 and i < len(topic)-1:
            return topic[i+1:]
        else:
            return ""

    def mqtt_subscribe_topics(self):
        return [(self.mqtt_topic("cmnd", "#"), 0,)]

    def mqtt_publish_onstart(self):
        return []  # lista di dict con topic msg e options(retain, qos)

    def mqtt_on_subscribe(self, client, userdata, mid, granted_qos):
        print(self.name+" subscribed: "+str(mid)+" "+str(granted_qos))

    def mqtt_on_publish(self, client, userdata, mid):
        print(self.name+" pub mid: "+str(mid))

    def mqtt_on_connect(self, client, userdata, flags, rc):
        print(self.name+" CONNACK received with code %d." % (rc))
        self.mqtt_publish_all(self.mqtt_publish_onstart())
        lsttopic = self.mqtt_subscribe_topics()
        client.subscribe(lsttopic)

    def mqtt_on_message(self, client, userdata, msg):
        print(self.name+" MSG "+msg.topic +
              " ("+str(msg.qos)+")-> "+b2s(msg.payload))

    def mqtt_publish_all(self, lsttopic):
        if self.mqtt_client:
            for p in lsttopic:
                self.mqtt_client.publish(p["topic"], p["msg"], **p["options"])

    def mqtt_start(self, hp):
        if hp is not None:
            client = paho.Client()
            client.on_publish = self.mqtt_on_publish
            client.on_connect = self.mqtt_on_connect
            client.on_subscribe = self.mqtt_on_subscribe
            client.on_message = self.mqtt_on_message
            print("mqtt_start (%s:%d)" % hp)
            client.connect_async(hp[0], port=hp[1])
            client.loop_start()
            self.mqtt_client = client

    @staticmethod
    def dictionary_write(el):
        words = SubElement(el, "dictionary")

        for w, lst in Device.dictionary.items():
            word = SubElement(words, "word", {"name": w})
            for s in lst:
                v = SubElement(word, 'v')
                v.text = s

    @staticmethod
    def dictionary_parse(root):
        try:
            root1 = root.getElementsByTagName("dictionary")[0]
            d433s = root1.getElementsByTagName("word")
            for d433 in d433s:
                try:
                    nm = d433.attributes['name'].value
                    irs = d433.getElementsByTagName("v")
                    terms = list()
                    Device.dictionary.update({nm: terms})
                    for ir in irs:
                        irc = ir.childNodes[0].nodeValue
                        if len(irc):
                            terms.append(irc)
                except:
                    traceback.print_exc()
        except:
            traceback.print_exc()

    def __eq__(self, other):
        """Override the default Equals behavior"""
        if isinstance(other, Device):
            return self.mac == other.mac
        else:
            return False

    @staticmethod
    def unix_time_millis(dt):
        return long((dt - Device.epoch).total_seconds() * 1000)

    @staticmethod
    def load(fn):
        xmldoc = minidom.parse(fn)
        items = xmldoc.getElementsByTagName('device')
        Device.dictionary_parse(xmldoc)
        print("Dictionary has %d items" % len(Device.dictionary))
        devices = {}
        for item in items:
            try:
                dev = Device.parse(item)
                if dev is not None:
                    devices[dev.name] = dev
            except:
                traceback.print_exc()
                pass
        return devices

    def do_presend_operations(self, action, actionexec):
        if isinstance(self, ManTimerManager):
            return ManTimerManager.do_presend_operations(self, action, actionexec)
        return 1

    def do_postsend_operations(self, action, actionexec):
        pass

    def prepare_additional_file(self, root, flag):
        pass

    def send_action(self, actionexec, action, pay):
        return None

    def get_action_payload(self, action):
        return ''

    def on_stop(self):
        self.mqtt_stop()

    @staticmethod
    def __save(save_devices, save_filename, flag=0):
        if flag & DEVICE_SAVE_FLAG_TABLE:
            save_filename += ".tmp.xml"
        root = Element('orvpy')
        Device.dictionary_write(root)
        devs = SubElement(root, "devices")
        for _, d in save_devices.copy().items():
            if flag & DEVICE_SAVE_FLAG_TABLE:
                d.prepare_additional_file(devs, flag)
            else:
                d.xml_element(devs, flag)
        with open(save_filename, "w") as text_file:
            text_file.write(Device.xml_prettify(root))

    @staticmethod
    def save(save_devices, save_filename, flag=DEVICE_SAVE_FLAG_MAIN | DEVICE_SAVE_FLAG_TABLE):
        if (flag & DEVICE_SAVE_FLAG_MAIN):
            Device.__save(save_devices, save_filename, DEVICE_SAVE_FLAG_MAIN)
        if (flag & DEVICE_SAVE_FLAG_TABLE):
            Device.__save(save_devices, save_filename, DEVICE_SAVE_FLAG_TABLE)

    def __str__(self, *args, **kwargs):
        """localtime   = time.localtime(self.subscribe_time)
        timeString  = time.strftime("%Y%m%d %H%M%S", localtime)
        return self.host+"("+self.__class__.__name__+": "+self.name+");"+self.mac+";"+timeString
        """
        return self.__class__.__name__+"("+self.name+")"

    @staticmethod
    def parse(root):
        cls = class_forname("orvibo.action."+root.attributes['type'].value)
        return None if cls is None else cls(root=root)

    @staticmethod
    def xml_prettify(elem):
        """Return a pretty-printed XML string for the Element.
        """
        rough_string = ElementTree.tostring(elem, 'utf-8')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ")

    def default_name(self):
        return 'dev_'+tohexs(self.mac)

    def __init__(self, hp=('', 0), mac='', root=None, name='', **kw):
        if root is None:
            self.host = hp[0]
            self.port = hp[1]
            self.mac = mac
            self.name = self.default_name() if not len(name) else name
            self.offlimit = 60
        else:
            self.host = root.attributes['host'].value
            self.port = int(root.attributes['port'].value)
            self.mac = bfromhex(root.attributes['mac'].value)
            self.name = root.attributes['name'].value
            try:
                self.offlimit = int(root.attributes['offlimit'].value)
            except:
                traceback.print_exc()
                self.offlimit = 60
        self.timers = None
        self.offt = 0
        self.mqtt_client = None

    def copy_extra_from(self, already_saved_device):
        self.timers = already_saved_device.timers
        self.port = already_saved_device.port
        self.host = already_saved_device.host
        self.offlimit = already_saved_device.offlimit
        self.mqtt_client = already_saved_device.mqtt_client

    def to_dict(self):
        # a = datetime(1900,1,1,0,0,0)
        # b = a + timedelta(seconds=self.sec1900)
        # b.strftime('%d/%m/%Y %H:%M:%S')
        return {
            "host": str(self.host),
            "port": str(self.port),
            "offlimit": str(self.offlimit),
            "mac": tohexs(self.mac),
            "type": self.__class__.__name__,
            "mytime": str(Device.unix_time_millis(datetime.now())),
            "name": self.name
        }

    def to_json(self):
        rv = self.to_dict()
        rv.update({
            'offt': str(int(self.offt)),
            'timers': [] if self.timers is None else self.timers,
        })
        return rv

    def __xml_basic(self, root):
        return SubElement(root, "device", self.to_dict())

    def xml_element(self, root, flag=0):
        return self.__xml_basic(root)


class DeviceUDP(Device):
    TIMEZONE_NOT_SET = 9000
    TIMEZONE_NONE = 70000
    OFF_AFTER_ON_NONE = 70000

    @staticmethod
    def mac_from_data(data):
        idx = data.find(MAC_START)
        if idx >= 0 and idx+6 <= len(data):
            return data[idx:idx+6]
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
                    print("Unknown device type %s %s" %
                          (keyv, tohexs(data[31:37])))
                    continue
                dev = typed(hp=buffcont.addr, mac=data[7:13],
                            sec1900=struct.unpack('<I', data[37:41])[0])
                print("Discovered device %s" % dev)
                hosts[keyv] = dev
                print("ln = "+str(len(hosts))+" h = "+str(keyv))
        return hosts

    @staticmethod
    def discovery(actionexec, timeout=5, **kwargs):
        return actionexec.udpmanager._udp_transact(
            action=None,
            hp=(None, 0),
            payload=MAGIC + DISCOVERY_LEN + DISCOVERY_ID,
            handler=DeviceUDP.discovery_handler,
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
    def get_ver_flag(device, table, defv):
        stable = str(table)
        if device and isinstance(device, DeviceUDP) and \
                device.tablever is not None and stable in device.tablever:
            return str(device.tablever[stable]['flgn'])
        else:
            return defv

    @staticmethod
    def ip2string(ip):
        ipp = ip.split('.')
        if len(ipp) == 4:
            ipr = ''
            for i in ipp:
                try:
                    ipr += struct.pack('<B', int(i))
                except:
                    traceback.print_exc()
                    ipr += b'\x01'
            return ipr
        else:
            return b'\x0A\x00\x00\x01'

    def parse_table1(self, data):
        start = 28
        ln = len(data)
        self.tablever = {}
        while start+8 <= ln:
            '''print("allv = "+data[start+2:start+8].encode('hex'))'''
            vern = struct.unpack('<H', data[start+2:start+4])[0]
            tabn = struct.unpack('<H', data[start+4:start+6])[0]
            flgn = struct.unpack('<H', data[start+6:start+8])[0]
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
            lenrec = struct.unpack('<H', data[start:start+2])[0]
            rec = data[start:start+2+lenrec]
            self.parse_timer_record(rec)
            start += 2+lenrec

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
        return actionexec.udpmanager._udp_transact(action=action, hp=(self.host, self.port), payload=pay, handler=self.receive_handler, timeout=action.get_timeout())

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
            record = pay[30:30+lenrec]

            if action.name is None:
                nm = None
            elif len(action.name) > 16:
                nm = action.name[0:16]
            else:
                nm = action.name.ljust(16)
            if nm is not None:
                record = record[0:40]+s2b(nm)+record[56:]
            if action.ip is not None:
                record = record[0:118]+s2b(DeviceUDP.ip2string(action.ip)+DeviceUDP.ip2string(
                    action.gateway)+DeviceUDP.ip2string(action.nmask))+b'\x00\x01'+record[132:]
            if action.timezone is not None:
                record = record[0:132]+(b'\x01\x00' if action.timezone ==
                                        DeviceUDP.TIMEZONE_NOT_SET else b'\x00'+struct.pack('<b', action.timezone))+record[134:]
            if action.timer_off_after_on is not None:
                record = record[0:134]+(b'\x00\xff' if action.timer_off_after_on <=
                                        0 else b'\x01\x00')+struct.pack('<H', action.timer_off_after_on)+record[138:]
            return record

# concetto di handler dopo send_action rimane ma  ha come parametri rv (valore di ritorno e data che dipende dall'azione')
# l'handler esegue quello che deve con il data controllando rv. ritorna il valore che deve in vase ad rv (valore ok 0)'
    def get_action_payload(self, action):
        if isinstance(action, ActionSubscribe):
            return MAGIC + SUBSCRIBE_LEN + SUBSCRIBE_ID + self.mac \
                + PADDING_1 + self.mac_reversed + PADDING_1
        elif isinstance(action, ActionStatechange):
            newst = self.state_value_conv(action.newstate)
            return MAGIC + STATECHANGE_LEN + STATECHANGE_ID + self.mac + PADDING_1\
                + PADDING_2+(b'\x01' if newst != "0" else b'\x00')
        elif isinstance(action, ActionViewtable):
            return MAGIC + VIEW_TABLE_LEN + VIEW_TABLE_ID + self.mac + PADDING_1\
                + PADDING_2+struct.pack('<B', action.tablenum)+b'\x00' + \
                struct.pack('<B', action.vflag)+PADDING_2
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
                return MAGIC+struct.pack('>H', len(pay)+4)+pay
        return Device.get_action_payload(self, action)

    def __init__(self, hp=('', 0), mac='', root=None, timeout=DEFAULT_RESUBSCRIPTION_TIMEOUT, name='', sec1900=0, lsa_timeout=DEFAULT_RESUBSCRIPTION_STIMEOUT, **kw):
        Device.__init__(self, hp, mac, root, name)
        if root is None:
            self.subscribe_time = 0
            self.resubscription_timeout = timeout
            self.last_subs_action_timeout = lsa_timeout
            self.sec1900 = int(((datetime.now()-datetime(1900, 1, 1, 0, 0, 0, 0)).total_seconds() -
                                (datetime.utcnow()-datetime.now()).total_seconds()-sec1900)*1000)
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
        return now-self.subscribe_time >= self.resubscription_timeout or now-self.last_subs_action >= self.last_subs_action_timeout

    def subs_action(self):
        self.last_subs_action = int(time.time())

    def get_reversed_mac(self):
        ba = bytearray(self.mac)
        ba.reverse()
        self.mac_reversed = bytes(ba)


class DeviceS20(DeviceUDP):
    def __init__(self, hp=('', 0), mac='', root=None, timeout=DEFAULT_RESUBSCRIPTION_TIMEOUT, name='', sec1900=0, lsa_timeout=DEFAULT_RESUBSCRIPTION_STIMEOUT):
        DeviceUDP.__init__(self, hp, mac, root, timeout,
                           name, sec1900, lsa_timeout)
        self.state = ""
        # if root is None:
        #    self.state = -1
        # else:
        #    self.state = int(root.attributes['state'].value)

    def process_asynch_state_change(self, state):
        self.state = b2s(state)

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
        if isinstance(action, ActionStatechange):
            actionexec.insert_action(ActionSubscribe(self), 1)
        else:
            DeviceUDP.do_postsend_operations(self, action, actionexec)

    def copy_extra_from(self, already_saved_device):
        DeviceUDP.copy_extra_from(self, already_saved_device)
        self.state = already_saved_device.state

    def mqtt_on_message(self, client, userdata, msg):
        Device.mqtt_on_message(self, client, userdata, msg)
        sub = self.mqtt_sub(msg.topic)
        try:
            if sub == "power":
                i = int(msg.payload)
                if i == 0 or (i == -1 and self.state == "1"):
                    event.EventManager.fire(eventname='ExtInsertAction', hp=(
                        self.host, self.port), cmdline="", action=ActionStateoff(self))
                elif i == 1 or (i == -1 and self.state == "0"):
                    event.EventManager.fire(eventname='ExtInsertAction', hp=(
                        self.host, self.port), cmdline="", action=ActionStateon(self))
        except:
            traceback.print_exc()

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
        return [dict(topic=self.mqtt_topic("stat", "power"), msg="-1" if self.state != "0" and self.state != "1" else str(self.state), options=dict(retain=True))]

    def mqtt_publish_onstart(self):
        return self.mqtt_power_state()

    """
    def __repr__(self, *args, **kwargs):
        rr = super(Device,self).__repr__(self, *args, **kwargs)
        return rr+";"+self.state
    """


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
            rv = threading.Timer((d-now).total_seconds(),
                                 self.exec_timer, (t,))
            rv.name = ("timer"+str(t["code"]))
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
                    dt = date(2016, 1, 4+i)
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
                                dt = date(2016, 1, 4+i)
                                day = dt.strftime('%a')
                                if day in printable_l:
                                    rep |= (1 << i)
                        t['rep'] = 0 if rep == 128 else rep
                    except:
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
            except:
                traceback.print_exc()
        return out


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
                except:
                    pass
            self.ir_xml_device_node_parse(root, self.d433, "d433")
            self.ir_xml_device_node_parse(root, self.dir, "dir")
            self.sh_xml_device_node_parse(root, self.sh, "sh")

    def schedule_action(self, topic, convert, *args):
        event.EventManager.fire(eventname='ExtInsertAction', hp=(self.host, self.port), cmdline="",
                                action=ActionBackup(self, topic, convert))

    def send_action(self, actionexec, action, pay):
        if isinstance(action, ActionStatechange):
            return action.exec_handler(1, None)
        else:
            return Device.send_action(self, actionexec, action, pay)

    def do_presend_operations(self, action, actionexec):
        if isinstance(action, ActionStatechange):
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
                    if idx == self.backupstate+1:
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
                        except:
                            traceback.print_exc()
        lst2 = sorted(self.sh, key=cmp_to_key(IrManager.sh_comparer))
        for nm in lst2:
            d433l = self.sh[nm]
            idx += 1
            if idx == self.backupstate+1:
                self.backupstate += 1
                outl = [{'remote': '', 'key': '@'+nm}]
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
                out.append("@"+nm+":"+ir)
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
                    out.append(nm+":"+irnm+":"+self.ir_encode(tpl[0]))
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
                            if irnm in Device.dictionary:
                                irnma = Device.dictionary[irnm]
                                for x in irnma:
                                    if len(x):
                                        lst[nm].update(
                                            {x: (ircdec, '', iratt)})
                    except:
                        pass
            except:
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
                    except:
                        pass
            except:
                pass

    def ir_xml_device_node_write(self, root, lst, dname):
        d433s = SubElement(root, dname+"s", {})
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
            return int(v1.group(2))-int(v2.group(2))
        elif it1 > it2:
            return 1
        elif it2 > it1:
            return -1
        else:
            return 0

    def sh_xml_device_node_write(self, root, lst, dname):
        d433s = SubElement(root, dname+"s", {})
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

    def mqtt_publish_sh(self, lst2, topic):
        lst = lst2.keys()
        return [dict(topic=self.mqtt_topic("stat", topic), msg=json.dumps(lst), options=dict(retain=True))]

    def mqtt_publish_onstart(self):
        out = self.mqtt_publish_dir(self.dir, "remotes")
        out.extend(self.mqtt_publish_dir(self.d433, "r433s"))
        out.extend(self.mqtt_publish_sh(self.sh, "shortcuts"))
        return out

    def mqtt_on_message(self, client, userdata, msg):
        Device.mqtt_on_message(self, client, userdata, msg)
        sub = self.mqtt_sub(msg.topic)
        try:
            if sub == "backup":
                if len(msg.payload):
                    try:
                        out = json.loads(msg.payload)
                    except:
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
                print("topic "+msg.topic+" ["+b2s(msg.payload)+"]")
                learnk = json.loads(msg.payload)
                keyall = []
                for d in learnk:
                    ksing = ('' if d['key'][0] == '@' or d['key'][0]
                             == '$' else (d["remote"]+':'))+d["key"]
                    # print("KSING "+ksing+" "+str(type(ksing)))
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
        except:
            traceback.print_exc()


class DeviceVirtual(Device):
    def target_xml_device_node_parse(self, root, lst):
        d433s = root.getElementsByTagName('target')
        for d433 in d433s:
            try:
                lst.append(d433.childNodes[0].nodeValue)
            except:
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
                        print("Scheduling "+actcmd)
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
        print("D is "+d+" Real Dev is "+str(d2))
        return d2

    def states_xml_device_node_parse(self, root, lst, nicks):
        d433s = root.getElementsByTagName('state')
        for d433 in d433s:
            try:
                nm = d433.attributes['value'].value
                try:
                    nicks[nm] = d433.attributes['nick'].value
                except:
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
                    except:
                        traceback.print_exc()
            except:
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
            except:
                traceback.print_exc()
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
            print("Searching upnp devices")
            devs = upnpclient.discover(timeout=5)
            print("Found "+str(len(devs))+" upnp devices")
            rc = {"RenderingControl": DeviceUpnpIRRC,
                  "MainTVAgent2": DeviceUpnpIRTA2}
            for d in devs:
                u = upar(d.location)
                for k, v in rc.items():
                    if k in d.service_map:
                        print("Found "+k+" at "+d.location)
                        hp = (u.hostname, u.port)
                        m = '{}:{}:'.format(*hp)+k
                        out[m] = v(hp=hp,
                                   mac=m,
                                   name='',
                                   location=d.location,
                                   deviceobj=d)
        except:
            traceback.print_exc()
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
        except:
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
            except:
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
            except:
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
                    print(self.name+" sending "+pay[0])
                    if not self.remote.control(pay[0]):
                        rv = 5
                        self.destroy_device()
                    else:
                        rv = 1
            except:
                traceback.print_exc()
                self.destroy_device()
                rv = None
            return action.exec_handler(rv, None)
        else:
            return IrManager.send_action(self, actionexec, action, pay)


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

        # print("LOC "+self.upnp_drc_location)
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
            except:
                traceback.print_exc()
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
                # print("JJJ "+key+" "+str(self.upnp_drc_dev.dir))
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
                except:
                    traceback.print_exc()
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
                if s in Device.dictionary:
                    irnma = Device.dictionary[s]
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
                            except:
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
            except:
                traceback.print_exc()
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
                                print("Change channel rv "+str(vv))
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
                                print("Change source rv "+str(vv))
                                rv = 127
                        else:
                            rv = 255
            except:
                traceback.print_exc()
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
                except:
                    traceback.print_exc()
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
            except:
                traceback.print_exc()
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

        print('Parsed %d channels' % len(channels))
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
                if s in Device.dictionary:
                    irnma = Device.dictionary[s]
                    for x in irnma:
                        if len(x):
                            dc.update({x: (s, '', dc[s][2])})
            self.dir[self.remote_name] = dc

    def get_dir(self, rem, key):
        if self.init_device():
            # print("KKK "+key+" "+rem+str(self.dir))
            if rem in self.dir:
                # print("UUU "+key+" "+rem)
                mo = re.search("^([^0-9\\+\\-]+)([0-9]*)([\\+\\-]?)$", key)
                if mo is not None:
                    fp = mo.group(1)+("+"*len(mo.group(3)))
                    if fp in self.dir[rem]:
                        p = mo.group(2)
                        return (key, int(p) if len(p) else 1, {"type": DeviceUpnpIR.RC_KEY})
                mo = re.search("^([^#\\+\\-]+)([\\+\\-]?)#([0-9]+)$", key)
                # print("DDDD "+key+" "+rem)
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
                except:
                    traceback.print_exc()
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
                    print("Calling method upnp "+k+" out "+str(out))
                    return self.states[k]
            except:
                print("Action Set"+k+" args "+str(self.a['Set'+k].argsdef_in))
                self.destroy_device()
                traceback.print_exc()
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
                    print(self.name+" Upnp State "+k+" = "+str(st))
                except:
                    traceback.print_exc()
        if rv >= 500:
            return rv-500
        else:
            return None


class DevicePrimelan(Device):
    # 0: doppio pulsante
    # 2: On off slider
    # 1: slider 0-100

    def state_value_conv(self, s):
        try:
            realv = int(s)
        except:
            realv = 0
        if realv == 0:
            return "0"
        elif realv >= 1000:
            if self.subtype == 1:
                try:
                    ost = int(self.oldstate)
                except:
                    ost = 0
                try:
                    st = int(self.state)
                except:
                    st = 0
                if st:
                    return str(st)
                elif ost:
                    return str(ost)
                else:
                    return "50"
            else:
                return "1"
        else:
            return s

    def get_action_payload(self, action):
        if isinstance(action, ActionStatechange):
            return self.state_value_conv(action.newstate)
        else:
            return Device.get_action_payload(self, action)

    crc16_table = [
        0x0000, 0xc0c1, 0xc181, 0x0140, 0xc301, 0x03c0, 0x0280, 0xc241,
        0xc601, 0x06c0, 0x0780, 0xc741, 0x0500, 0xc5c1, 0xc481, 0x0440,
        0xcc01, 0x0cc0, 0x0d80, 0xcd41, 0x0f00, 0xcfc1, 0xce81, 0x0e40,
        0x0a00, 0xcac1, 0xcb81, 0x0b40, 0xc901, 0x09c0, 0x0880, 0xc841,
        0xd801, 0x18c0, 0x1980, 0xd941, 0x1b00, 0xdbc1, 0xda81, 0x1a40,
        0x1e00, 0xdec1, 0xdf81, 0x1f40, 0xdd01, 0x1dc0, 0x1c80, 0xdc41,
        0x1400, 0xd4c1, 0xd581, 0x1540, 0xd701, 0x17c0, 0x1680, 0xd641,
        0xd201, 0x12c0, 0x1380, 0xd341, 0x1100, 0xd1c1, 0xd081, 0x1040,
        0xf001, 0x30c0, 0x3180, 0xf141, 0x3300, 0xf3c1, 0xf281, 0x3240,
        0x3600, 0xf6c1, 0xf781, 0x3740, 0xf501, 0x35c0, 0x3480, 0xf441,
        0x3c00, 0xfcc1, 0xfd81, 0x3d40, 0xff01, 0x3fc0, 0x3e80, 0xfe41,
        0xfa01, 0x3ac0, 0x3b80, 0xfb41, 0x3900, 0xf9c1, 0xf881, 0x3840,
        0x2800, 0xe8c1, 0xe981, 0x2940, 0xEB01, 0x2bc0, 0x2a80, 0xea41,
        0xee01, 0x2ec0, 0x2f80, 0xef41, 0x2d00, 0xedc1, 0xec81, 0x2c40,
        0xe401, 0x24c0, 0x2580, 0xe541, 0x2700, 0xe7c1, 0xe681, 0x2640,
        0x2200, 0xe2c1, 0xe381, 0x2340, 0xe101, 0x21c0, 0x2080, 0xe041,
        0xa001, 0x60c0, 0x6180, 0xa141, 0x6300, 0xa3c1, 0xa281, 0x6240,
        0x6600, 0xa6c1, 0xa781, 0x6740, 0xa501, 0x65c0, 0x6480, 0xa441,
        0x6c00, 0xacc1, 0xad81, 0x6d40, 0xaf01, 0x6fc0, 0x6e80, 0xae41,
        0xaa01, 0x6ac0, 0x6b80, 0xab41, 0x6900, 0xa9c1, 0xa881, 0x6840,
        0x7800, 0xb8c1, 0xb981, 0x7940, 0xbb01, 0x7bc0, 0x7a80, 0xba41,
        0xbe01, 0x7ec0, 0x7f80, 0xbf41, 0x7d00, 0xbdc1, 0xbc81, 0x7c40,
        0xb401, 0x74c0, 0x7580, 0xb541, 0x7700, 0xb7c1, 0xb681, 0x7640,
        0x7200, 0xb2c1, 0xb381, 0x7340, 0xb101, 0x71c0, 0x7080, 0xb041,
        0x5000, 0x90c1, 0x9181, 0x5140, 0x9301, 0x53c0, 0x5280, 0x9241,
        0x9601, 0x56c0, 0x5780, 0x9741, 0x5500, 0x95c1, 0x9481, 0x5440,
        0x9c01, 0x5cc0, 0x5d80, 0x9d41, 0x5f00, 0x9fc1, 0x9e81, 0x5e40,
        0x5a00, 0x9ac1, 0x9b81, 0x5b40, 0x9901, 0x59c0, 0x5880, 0x9841,
        0x8801, 0x48c0, 0x4980, 0x8941, 0x4b00, 0x8bc1, 0x8a81, 0x4a40,
        0x4e00, 0x8ec1, 0x8f81, 0x4f40, 0x8d01, 0x4dc0, 0x4c80, 0x8c41,
        0x4400, 0x84c1, 0x8581, 0x4540, 0x8701, 0x47c0, 0x4680, 0x8641,
        0x8201, 0x42c0, 0x4380, 0x8341, 0x4100, 0x81c1, 0x8081, 0x4040
    ]

    @staticmethod
    def crc16(ba):
        return reduce(lambda x, y: ((x >> 8) & 0xff) ^ DevicePrimelan.crc16_table[(x ^ y) & 0xff], ba, 0)

    @staticmethod
    def discovery(hp, passw, codu, port2, timeout=10):
        try:
            r = requests.post('http://{}:{}/cgi-bin/web.cgi'.format(*hp),
                              data={'pass': passw, 'code': codu, 'mod': 'auth'}, timeout=timeout)
            txt = r.content.decode('utf-8')
            doc = minidom.parseString(txt)
            divs = doc.getElementsByTagName('div')
            tk = ''
            qindex = ''
            for div in divs:
                tk = div.attributes['tk'].value
                qindex = div.attributes['qindex'].value
            print('received '+txt+" tk = "+tk+" qindex = "+qindex)
            r = requests.post('http://{}:{}/cgi-bin/web.cgi'.format(*hp),
                              data={'tk': tk, 'qindex': qindex, 'mod': 'cmd'}, timeout=timeout)
            lst = r.json()['cmd']
            out = {}
            print(lst)
            for d in lst:
                idv = d['id']
                dev = DevicePrimelan(hp=hp,
                                     mac=DevicePrimelan.generate_mac(
                                         hp[0], idv),
                                     name=d['lb'], idv=idv, typev=d['t'], tk=tk, qindex=qindex, state=d['st'],
                                     passw=passw, port2=port2)
                out['{}:{}'.format(*hp)+':'+idv] = dev
            return out
        except:
            traceback.print_exc()
            return {}

    @staticmethod
    def generate_name_nick(nick):
        nick = nick.strip().lower()
        name = nick.replace(' ', '_')
        return (name, nick)

    @staticmethod
    def generate_mac(ip, idv):
        lst = ip.split('.')
        id2 = int(idv)
        lst.append((id2 >> 8) & 0xFF)
        lst.append(id2 & 0xFF)
        o = map(lambda x: chr(int(x)), lst)
        return ''.join(o)

    def pkt_state(self, newstate):
        pre = b'\x50\x53\x00\x00\x1a\x00\x00\x00\x2a\x00\x00\x00\x50\x50'
        out = b'\x01\x00\x1a\x00\x00\x00'
        if newstate < 0:
            onoff = 0x4000
            newstate = -newstate
        else:
            onoff = 0x30E0
        aesc = b'\x08\x00\x00\x00\x69\x00\x00\x00'+struct.pack("<H", onoff)+struct.pack(
            "<B", int(self.id))+b'\x00'+struct.pack("<B", int(newstate))+b'\x00\x02\x02'
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        aesc2 = cipher.encrypt(aesc)
        crc = DevicePrimelan.crc16(bytearray(out+aesc2))
        return pre+struct.pack("<H", crc)+out+aesc2

    def change_state_http(self, pay, timeout):
        r = requests.post('http://{}:{}/cgi-bin/web.cgi'.format(self.host, self.port),
                          data={'tk': self.tk, 'qindex': self.qindex, 'mod': 'do_cmd', 'par': self.id, 'act': pay}, timeout=timeout)
        return 1 if r.status_code == 200 else r.status_code

    def change_state_tcp(self, state, timeout):
        t = TCPClient(timeout)
        return 1 if t.send_packet((self.host, self.port2), self.pkt_state(state)) > 0 else None

    def __init__(self, hp=('', 0), mac='', root=None, name='', idv=0, typev=0, tk='', qindex=0, passw='', port2=6004, state=0):
        nn = DevicePrimelan.generate_name_nick(name)
        nick = nn[1]
        name = nn[0]
        Device.__init__(self, hp, mac, root, name)
        self.oldstate = "0"
        if root is not None:
            self.id = root.attributes['id'].value
            self.subtype = int(root.attributes['subtype'].value)
            self.tk = root.attributes['tk'].value
            self.qindex = root.attributes['qindex'].value
            self.nick = root.attributes['nick'].value
            self.passw = root.attributes['passw'].value
            self.port2 = int(root.attributes['port2'].value)
            self.state = "0"
        else:
            self.id = idv
            self.subtype = int(typev)
            self.tk = tk
            self.qindex = qindex
            self.state = str(state)
            self.nick = nick
            self.passw = passw
            self.port2 = port2

        self.key = s2b(self.passw)+(b'\x00'*(16-len(self.passw)))
        self.iv = reduce(lambda x, y: x+struct.pack("<B",
                                                    y[1] ^ y[0]), enumerate(self.key), b'')

    def to_dict(self):
        rv = Device.to_dict(self)
        rv.update({
            'tk': self.tk,
            'id': self.id,
            'qindex': self.qindex,
            'subtype': str(self.subtype),
            'passw': self.passw,
            'port2': str(self.port2),
            'nick': self.nick})
        return rv

    def to_json(self):
        rv = Device.to_json(self)
        rv.update({'state': self.state,
                   'oldstate': self.oldstate})
        return rv

    def send_action(self, actionexec, action, pay):
        if isinstance(action, ActionStatechange):
            timeout = action.get_timeout()
            if timeout is None or timeout < 0:
                timeout = actionexec.udpmanager.timeout
            if timeout < 0:
                timeout = None
            try:
                state = int(pay)
                rv = self.change_state_tcp(state, timeout)
                if rv == 1:
                    st = int(self.state)
                    if st > 0 and st <= 100:
                        self.oldstate = self.state
                    self.state = pay
            except:
                traceback.print_exc()
                rv = None
            return action.exec_handler(rv, self.state)
        else:
            return Device.send_action(self, actionexec, action, pay)


class DeviceRM(IrManager, ManTimerManager):

    def inner_init(self):
        try:
            self.inner = broadlink.rm(
                (self.host, self.port), bytearray(self.mac), 0x27c2)
            if not self.inner.auth():
                self.inner = None
        except:
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
                    print("S(%s:%d)-> %s" %
                          (self.inner.host+(tohexs(pay[0]),)))
                    response = self.inner.send_data(pay[0])
                    if response is None:
                        rv = None
                    else:
                        rv = response[0x22] | (response[0x23] << 8)
            except:
                traceback.print_exc()
                rv = None
            if rv is None or rv != 0:
                # Forzo futura riconnessione
                print("Blackbeam %s error: will try to reconnect" % self.name)
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
            self.clientSessionId = SendBufferTimer.generatestring(32)
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
            # print("HERE1 "+str(self.dir))
            # print("HERE2 "+str(self.sh))
            # self.dir_file_min(self.dir)
            # self.sh_file_min(self.sh)

    def get_action_payload(self, action):
        if isinstance(action, ActionLearnir):
            if len(action.irdata):
                fk = action.irdata[action.irdata.find(
                    ':')+1:].translate(None, '!@#$/\+-_')
                if len(fk) < 2:
                    fk = SendBufferTimer.generatestring(5)
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
                plen = struct.pack('>H', len(irc)+26)
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
            '<'+('H'*((len(irdata[0])-16)/2)), irdata[0], 16))
        return {'key': irdata[1], 'remote': remote, 'a': irenc}

    def get_from_arduraw(self, msg):
        tpl = (0, 0, len(msg['a'])*2+16, 0, 0, 0, 0, len(msg['a'])*2)
        out = struct.pack('<'+('H'*len(tpl)), *tpl)
        out += struct.pack('<'+('H'*len(msg['a'])), *tuple(msg['a']))
        return (out, msg['key'], {})


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
        if device is None or isinstance(device, Device):
            self.device = device
        else:
            raise TypeError('Invalid device argument')

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
            # print("non va be "+str(0 if self.device is None else 1)+" "+str(now-self.device.offt))
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
        device = DeviceUDP(hp=("255.255.255.255", 0), mac=b"")
        self.php = (primelanhost, primelanport)
        self.ppasw = primelanpassw
        self.pcodu = primelancodu
        self.pport2 = primelanport2
        self.hosts = {}
        super(ActionDiscovery, self).__init__(device)
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
        device = DeviceUDP(hp=("255.255.255.255", 0), mac=b"")
        self.hosts = {}
        super(ActionDevicedl, self).__init__(device)

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
        print("Please press "+self.irname)
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
        except:
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
        if isinstance(self.device, IrManager):
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
        if isinstance(self.device, IrManager):
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
        if isinstance(self.device, IrManager):
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
            except:
                traceback.print_exc()
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
        if isinstance(self.device, IrManager):
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
                            if irnm in Device.dictionary:
                                irnma = Device.dictionary[irnm]
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
        if isinstance(self.device, IrManager):
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
                    except:
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
                    except:
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
            except:
                traceback.print_exc()
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
        super(ActionViewtable3, self).__init__(
            device, "3", DeviceUDP.get_ver_flag(device, "3", "2"))


class ActionViewtable4(ActionViewtable):

    def __init__(self, device):
        super(ActionViewtable4, self).__init__(
            device, "4", DeviceUDP.get_ver_flag(device, "4", "23"))


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
            except:
                try:
                    do = int(datev)
                    ho = int(timev)
                    self.datetime = datetime.now()+timedelta(days=do, seconds=ho)
                except:
                    self.datetime = None

        self.rep = 0 if rep is None else int(rep)
        self.timerid = None if timerid is None else int(timerid)
        if isinstance(device, DeviceS20):
            if len(args) > 0:
                self.action = None if args[0] is None else int(args[0])
            else:
                self.action = 1
        else:
            self.action = ' '.join(args)

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
            except:
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
                if isinstance(d, DeviceUDP):
                    dudptot += 1
                    if now-d.offt > d.offlimit:
                        if d.tablever:
                            for k, _ in d.tablever.copy().items():
                                if k != "1":
                                    kls = class_forname(
                                        'orvibo.action.ActionViewtable'+k)
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
            self.out = DeviceUDP.loadtables(fn, self.device.name)
        except:
            traceback.print_exc()
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
            print("timer "+str(t))
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
