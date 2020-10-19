import logging
import sys

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
