import logging
import sys
import traceback
from datetime import datetime
from xml.dom import minidom
from xml.etree import ElementTree
from xml.etree.ElementTree import Element, SubElement

import paho.mqtt.client as paho
from device.mantimermanager import ManTimerManager
from util import b2s, bfromhex, class_forname, init_logger, s2b, tohexs

DEVICE_SAVE_FLAG_TABLE = 1
DEVICE_SAVE_FLAG_MAIN = 2


_LOGGER = init_logger(__name__, level=logging.DEBUG)


if sys.version_info >= (3, 0):
    long = int


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

    def parse_action_timer_args(self, args):
        return ' '.join(args)

    def mqtt_set_broker(self, hp):
        self.mqtt_stop()
        self.mqtt_start(hp)

    def mqtt_stop(self):
        if self.mqtt_client is not None:
            try:
                self.mqtt_client.loop_stop()
                self.mqtt_client.disconnect()
            except: # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")

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
        _LOGGER.info(self.name+" subscribed: "+str(mid)+" "+str(granted_qos))

    def mqtt_on_publish(self, client, userdata, mid):
        _LOGGER.info(self.name+" pub mid: "+str(mid))

    def mqtt_on_connect(self, client, userdata, flags, rc):
        _LOGGER.info(self.name+" CONNACK received with code %d." % (rc))
        self.mqtt_publish_all(self.mqtt_publish_onstart())
        lsttopic = self.mqtt_subscribe_topics()
        client.subscribe(lsttopic)

    def mqtt_on_message(self, client, userdata, msg):
        _LOGGER.info(f"{self.name} MSG {msg.topic} ({msg.qos})-> {b2s(msg.payload)}")

    def mqtt_publish_all(self, lsttopic):
        if self.mqtt_client:
            for p in lsttopic:
                retain = p["options"].get('retain', False)
                if not retain or self.mqtt_topic_retain.get(p["topic"], None) != p["msg"]:
                    self.mqtt_client.publish(p["topic"], p["msg"], **p["options"])
                    if retain:
                        self.mqtt_topic_retain[p["topic"]] = p["msg"]

    def mqtt_start(self, hp):
        if hp is not None and self.mqtt_client is None:
            client = paho.Client()
            client.on_publish = self.mqtt_on_publish
            client.on_connect = self.mqtt_on_connect
            client.on_subscribe = self.mqtt_on_subscribe
            client.on_message = self.mqtt_on_message
            _LOGGER.info(f"{self.name} mqtt_start ({hp[0]}:{hp[1]})")
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
                except: # noqa: E722
                    _LOGGER.warning(f"{traceback.format_exc()}")
        except: # noqa: E722
            _LOGGER.warning(f"{traceback.format_exc()}")

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
        _LOGGER.info("Dictionary has %d items" % len(Device.dictionary))
        devices = {}
        for item in items:
            try:
                dev = Device.parse(item)
                if dev is not None:
                    devices[dev.name] = dev
            except: # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")
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
        cls = class_forname("action."+root.attributes['type'].value)
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
            except: # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")
                self.offlimit = 60
        self.timers = None
        self.offt = 0
        self.mqtt_client = None
        self.mqtt_topic_retain = dict()

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
