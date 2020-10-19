import logging
import sys

from logging.handlers import SocketHandler

_loglevel = logging.WARNING
_LOGGERS = dict()
_socket_handler = None


def init_logger(name, level=None, hp=None):
    global _LOGGERS
    global _loglevel
    global _socket_handler
    idx = name.find('.')
    if idx > 0:
        nmref = name[0:idx]
    else:
        nmref = name
    loggerobj = _LOGGERS.get(nmref, None)
    if hp is not None and _socket_handler is None:
        _socket_handler = SocketHandler(*hp)
        _socket_handler.setLevel(_loglevel)
        for _, log in _LOGGERS.items():
            log['lo'].addHandler(_socket_handler)
    if level is not None and level != _loglevel:
        _loglevel = level
        if _socket_handler:
            _socket_handler.setLevel(_loglevel)
        for _, log in _LOGGERS.items():
            # print(f'Resetting level {nn} level {_loglevel}')
            log['lo'].setLevel(_loglevel)
            log['ha'].setLevel(_loglevel)
    # print(f'Init logger {nmref} level {_loglevel}')
    _LOGGER = logging.getLogger(nmref)
    if loggerobj:
        return logging.getLogger(name) if nmref != name else _LOGGER
    _LOGGER.setLevel(_loglevel)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(_loglevel)
    _LOGGERS[nmref] = dict(lo=_LOGGER, ha=handler)
    # if platform == 'android':
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # else:
    #    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    _LOGGER.addHandler(handler)
    if _socket_handler is not None:
        _LOGGER.addHandler(_socket_handler)
    return logging.getLogger(name) if nmref != name else _LOGGER
