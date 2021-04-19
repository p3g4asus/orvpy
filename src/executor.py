import logging
import threading

from action import RV_ASYNCH_EXEC, RV_NOT_EXECUTED
from transport import HTTPServer, TCPServer, UdpManager
from util import init_logger

_LOGGER = init_logger(__name__, level=logging.DEBUG)


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
        self.mqtt_host = ''
        self.mqtt_port = 0
        self.name = ("ActionExecutor")

    def configure(self, options):
        self.prime_hp = (options.prime_host, options.prime_port)
        self.prime_code = options.prime_code
        self.prime_pass = options.prime_pass
        self.prime_port2 = options.prime_port2
        self.mqtt_host = options.mqtt_host
        self.mqtt_port = options.mqtt_port
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
            # _LOGGER.info("WE "+str(act)+"/"+str(rv))
        else:
            # _LOGGER.info("NE "+str(act)+"/"+str(rv)+"/"+str(self.asynch_action))
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
            _LOGGER.info("Stopping TCP Server")
            self.tcpserver.stop()
            self.tcpserver = None
        if self.httpserver is not None:
            _LOGGER.info("Stopping TCP Server")
            self.httpserver.stop()
            self.httpserver = None
        if self.udpmanager is not None:
            _LOGGER.info("Stopping UDPManager")
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
                # _LOGGER.info("ecco00 "+str(len(self.action_list)))
                # _LOGGER.info("ecco00 "+str(self.action_list))
                if len(self.action_list):
                    act = self.action_list[0]
                else:
                    act = None
                self.action_list_l.release()
                if act is not None:
                    _LOGGER.info(
                        f"Running action {act} dev={None if not act.device else id(act.device)}")
                    retval = act.run(self)
                    if retval == RV_ASYNCH_EXEC:
                        retval = self.wait_asynch_action_done(act)
                    _LOGGER.info("Action " + str(act) +
                                 " run (" + str(retval) + ")")
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
