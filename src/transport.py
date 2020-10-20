import sys
import traceback
import threading
import logging
from util import init_logger, tohexs, s2b, uunq
from parser import RoughParser
import select
import socket
import time
import abc
import event
import json
from device.devicect10 import SendBufferTimer
from action import ActionPing, RV_DATA_WAIT


_LOGGER = init_logger(__name__, level=logging.DEBUG)


if sys.version_info < (3, 0):
    import SocketServer
    import SimpleHTTPServer
else:
    long = int
    import socketserver as SocketServer
    import http.server as SimpleHTTPServer


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
            except: # noqa: E722
                traceback.print_exc()

    def handle(self):
        self.stopped = False
        keyv = '{}:{}'.format(*self.client_address)
        threading.currentThread().name = ("TCPServerHandler")
        _LOGGER.info(keyv+" connected")
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
                        _LOGGER.info("RTCP ["+keyv+"/"+str(len(data))+"] <-"+tohexs(data))
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
                            break
                        olddata = data
                    else:
                        raise Exception("Readline failed: connection closed?")
                if ready[1] or len(wlist) == 0:

                    if len(remain) == 0:
                        remain = serv.dowrite(self.client_address)
                    if len(remain) > 0:
                        _LOGGER.info("Sending packet to %s:%d" % self.client_address)
                        nb = self.request.send(remain)
                        _LOGGER.info("Sent")
                        # if tp=="cry":
                        #    _LOGGER.info("STCP ["+keyv+"/"+str(len(remain))+"/"+str(nb)+"] <-"+remain.encode('hex'))
                        remain = remain[nb:]
                        wlist = [self.request]
                    else:
                        wlist = []
            except: # noqa: E722
                traceback.print_exc()
                break
        _LOGGER.info(keyv+" DISCONNECTED")
        serv.unsetclientinfo(self.client_address)
        _LOGGER.info(keyv+" DELETED")
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
        except: # noqa: E722
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
        _LOGGER.info(f"[{self.__class__.__name__}] ({self.client_address[0]}:{self.client_address[1]}) -> {msg}")

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
            except: # noqa: E722
                traceback.print_exc()
                time.sleep(5)
        if self.server is not None:
            self.server.s = self
            self.server.serve_forever()

    def handle_action_done(self, device, action, retval, **kwargs):
        if not self.stopped:
            s = str(action.randomid)
            client = None
            _LOGGER.info("Searching http client")
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
        # _LOGGER.info("02_unsetting %s" %keyv)
        if keyv in self.towrite:
            # _LOGGER.info("02_found in towrite")
            for x in self.towrite[keyv]:
                if isinstance(x, SendBufferTimer):
                    x.set_finished(None)
                    # _LOGGER.info("02_setfinish")
            del self.towrite[keyv]
        if keyv in self.clientinfo:
            # _LOGGER.info("02_found in clientinfo")
            del self.clientinfo[keyv]
        if keyv in self.clienthandler:
            # _LOGGER.info("02_found in clienthandler")
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
            except: # noqa: E722
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
                    # _LOGGER.info("01_1")
                elif snd.timer is not None:  # dobbiamo aspettare la risposta
                    snd = b''
                    # _LOGGER.info("01_2")
                    break
                elif snd.has_succeeded() or snd.has_failed():
                    if "sender" in self.clientinfo[keyv]:
                        del self.clientinfo[keyv]['sender']
                    if snd.has_failed():
                        self.clientinfo[keyv]['disconnecttimer'] = time.time()
                    self.towrite[keyv].pop(0)
                    snd = b''
                    # _LOGGER.info("01_3")
                else:  # dobbiamo ancora spedire il pacchetto o c'e gia stato un timeout ma dobbiamo fare altri tentativi
                    snd.clientinfo = self.clientinfo[keyv]
                    self.clientinfo[keyv]['sender'] = snd
                    snd = snd.schedule()
                    # _LOGGER.info("01_4")

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


class EthBuffCont(object):
    def __init__(self, ad, d):
        self.data = d
        self.addr = ad


class ListenerTh(threading.Thread, EthSender):

    def send_packet(self, addr, packet):
        try:
            return self.socket.sendto(bytearray(packet), addr)
        except: # noqa: E722
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
                    _LOGGER.info('enterrecv')
                    data, addr = self.socket.recvfrom(1024)
                    _LOGGER.info('1) recv %d (%s:%d) ' % (0 if not data else len(data), 'unkn' if not addr else addr[0], 0 if not addr else addr[1]))
                    if data is not None and len(data):
                        self.preparse.parse(addr, data if data[0:1] != b'@' else data+b'\n')['idxout']
                    _LOGGER.info('exitrecv')
                except: # noqa: E722
                    traceback.print_exc()
                    break
        except: # noqa: E722
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

    def add_to_buffer(self, key, hp, data, **kwargs):
        self.buffer_l.acquire()
        self.buffer[key] = EthBuffCont(hp, data)
        self.buffer_l.notifyAll()
        self.buffer_l.release()

    def _udp_transact(self, hp, payload, handler, action, keyfind, timeout=-1, **kwargs):
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
        keyv = keyfind(hp, payload)
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
                    _LOGGER.info(f"S [{hp[0]}:{hp[1]}] -> {tohexs(payload)}")
                except: # noqa: E722
                    traceback.print_exc()
                    return None
            if handler is None:
                return 5
            elif broadcast:
                # _LOGGER.info('broadc')
                time.sleep(timeout)
                break
            else:
                # _LOGGER.info('no broadc')
                u.buffer_l.acquire()
                # _LOGGER.info('acquired')
                buffcont = u.buffer.get(keyv, None)
                if buffcont is None:
                    now = time.time()
                    once = False
                    while time.time() < now+timeout or not once:
                        # _LOGGER.info("waiting")
                        u.buffer_l.wait(timeout)
                        # _LOGGER.info("waiting f")
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
                    # _LOGGER.info('Handler returned '+str(retval))
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
            _LOGGER.info("Stopping Listener Thread")
            self.listener.stop()
            _LOGGER.info("Listener Thread Stopped")
            self.listener = None
        if self.sender is not None:
            _LOGGER.info("Stopping Sender")
            self.sender.stop()
            _LOGGER.info("Sender Stopped")
