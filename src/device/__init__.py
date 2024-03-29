import glob
import importlib
import inspect
import logging
import re
import sys
import traceback
from datetime import datetime
from os.path import basename, dirname, isfile, join, splitext
from xml.dom import minidom
from xml.etree import ElementTree
from xml.etree.ElementTree import Element, SubElement

from device.mantimermanager import ManTimerManager
from dictionary import dictionary_parse, dictionary_write
from util import b2s, bfromhex, init_logger, s2b, tohexs

DEVICE_SAVE_FLAG_TABLE = 1
DEVICE_SAVE_FLAG_MAIN = 2


_LOGGER = init_logger(__name__, level=logging.DEBUG)


if sys.version_info >= (3, 0):
    long = int


class Device(object):
    epoch = datetime.utcfromtimestamp(0)
    GET_STATE_ACTION = '-999'

    def process_asynch_state_change(self, state, device_connected=None):
        pass

    def connect_devices(self, device_map):
        pass

    def state_value_conv(self, s):
        return s

    def mqtt_publish_onfinish(self, action, retval):
        return []

    def parse_action_timer_args(self, args):
        return ' '.join(args)

    def mqtt_stop(self):
        if self.mqtt_client:
            for topic, _ in self.mqtt_subscribe_topics():
                self.mqtt_client.unsubscribe(topic)

    def mqtt_topic(self, prefix, suffix):
        return str(prefix + '/' + self.__class__.__name__[6:].lower() + "/" + self.name + "/" + suffix)

    def mqtt_sub(self, topic):
        mo = re.search(r"^[^/]+/" + self.__class__.__name__[6:].lower() + "/" + self.name + r"/([^/]+)$", topic)
        return mo.group(1) if mo else ''

    def mqtt_subscribe_topics(self):
        return []

    def mqtt_publish_onstart(self):
        return []  # lista di dict con topic msg e options(retain, qos)

    def mqtt_on_subscribe(self, client, userdata, mid, granted_qos):
        pass

    def mqtt_on_publish(self, client, userdata, mid):
        _LOGGER.info(self.name + " pub mid: " + str(mid))

    def mqtt_on_connect(self, client, userdata, flags, rc):
        _LOGGER.info(self.name + " CONNACK received with code %d." % (rc))
        self.mqtt_publish_all(self.mqtt_publish_onstart())
        lsttopic = self.mqtt_subscribe_topics()
        if lsttopic and self.mqtt_userdata:
            self.mqtt_userdata.mqtt_subscribe(client, userdata, self, lsttopic)

    def mqtt_on_message(self, client, userdata, msg):
        if msg.topic.startswith(f"cmnd/{self.__class__.__name__[6:].lower()}/{self.name}/") or self.mqtt_subscribe_topics():
            _LOGGER.info(
                f"{self.name} MSG {msg.topic} ({msg.qos})-> {b2s(msg.payload)}")

    def mqtt_publish_all(self, lsttopic):
        if self.mqtt_client:
            for p in lsttopic:
                retain = p["options"].get('retain', False)
                if not retain or self.mqtt_topic_retain.get(p["topic"], None) != p["msg"]:
                    _LOGGER.info(f"{self.name} publishing {p['topic']} -> {p['msg']}")
                    self.mqtt_client.publish(
                        p["topic"], p["msg"], **p["options"])
                    if retain:
                        self.mqtt_topic_retain[p["topic"]] = p["msg"]

    def mqtt_start(self, client, userdata):
        self.mqtt_client = client
        self.mqtt_userdata = userdata
        self.mqtt_on_connect(client, userdata, 0, 0)

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
        dictionary = dictionary_parse(xmldoc)
        _LOGGER.info(f"Dictionary has {len(dictionary)} items")
        devices = {}
        modules = glob.glob(join(dirname(__file__), "*.py"))
        pls = [splitext(basename(f))[0] for f in modules if isfile(f)]
        classes = dict()
        for x in pls:
            if not x.startswith('__'):
                m = importlib.import_module(f"device.{x}")
                clsmembers = inspect.getmembers(m, inspect.isclass)
                classes.update({cla[0]: cla[1] for cla in clsmembers})
        for item in items:
            try:
                clname = item.attributes['type'].value
                if clname in classes:
                    dev = classes[clname](root=item)
                    devices[dev.name] = dev
            except:  # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")
                pass
        _LOGGER.info(f"Device number is {len(devices)}")
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
        pass

    @staticmethod
    def __save(save_devices, save_filename, flag=0):
        if flag & DEVICE_SAVE_FLAG_TABLE:
            save_filename += ".tmp.xml"
        root = Element('orvpy')
        dictionary_write(root)
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
        return self.__class__.__name__ + "(" + self.name + ")"

    @staticmethod
    def xml_prettify(elem):
        """Return a pretty-printed XML string for the Element.
        """
        rough_string = ElementTree.tostring(elem, 'utf-8')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ")

    def default_name(self):
        return 'dev_' + tohexs(self.mac)

    def __init__(self, hp=('', 0), mac='', root=None, name='', **kw):
        if root is None:
            self.host = hp[0]
            self.port = hp[1]
            self.mac = s2b(mac)
            self.name = self.default_name() if not len(name) else name
            self.offlimit = 60
        else:
            self.host = root.attributes['host'].value
            self.port = int(root.attributes['port'].value)
            self.mac = bfromhex(root.attributes['mac'].value)
            self.name = root.attributes['name'].value
            try:
                self.offlimit = int(root.attributes['offlimit'].value)
            except:  # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")
                self.offlimit = 60
        self.timers = None
        self.offt = 0
        self.mqtt_client = None
        self.mqtt_userdata = None
        self.mqtt_topic_retain = dict()
        self.homeassistant = ''

    def set_homeassistant(self, h):
        self.homeassistant = h

    def copy_extra_from(self, already_saved_device):
        self.timers = already_saved_device.timers
        self.port = already_saved_device.port
        self.host = already_saved_device.host
        self.offlimit = already_saved_device.offlimit

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
