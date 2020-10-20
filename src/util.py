import binascii
import json
import logging
import random
import string
import sys
import traceback
import urllib
from _collections_abc import dict_values

if sys.version_info >= (3, 0):
    long = int
    from _collections_abc import dict_keys

STRINGS = string.lowercase if sys.version_info < (
        3, 0) else string.ascii_lowercase + string.digits


def generatestring(ln):
    return ''.join(random.sample(STRINGS, ln))


def class_forname(kls):
    parts = kls.split('.')
    module = ".".join(parts[:-1])
    m = __import__(module)
    for comp in parts[1:]:
        m = getattr(m, comp, None)
        if m is None:
            break
    return m


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


_loglevel = logging.WARNING
_LOGGERS = dict()


def init_logger(name, level=None):
    global _LOGGERS
    global _loglevel
    idx = name.find('.')
    if idx > 0:
        nmref = name[0:idx]
    else:
        nmref = name
    loggerobj = _LOGGERS.get(nmref, None)
    if level is not None and level != _loglevel:
        _loglevel = level
        for _, log in _LOGGERS.items():
            # print(f'Resetting level {nn} level {_loglevel}')
            log['lo'].setLevel(_loglevel)
            log['ha'].setLevel(_loglevel)
    # print(f'Init logger {nmref} level {_loglevel}')
    if loggerobj:
        return logging.getLogger(name) if nmref != name else loggerobj
    _LOGGER = logging.getLogger(nmref)
    _LOGGER.setLevel(_loglevel)
    _LOGGER.propagate = False
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(_loglevel)
    _LOGGERS[nmref] = dict(lo=_LOGGER, ha=handler)
    # if platform == 'android':
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # else:
    #    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    _LOGGER.addHandler(handler)
    return logging.getLogger(name) if nmref != name else _LOGGER
