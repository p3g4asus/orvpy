import logging
import traceback
from xml.etree.ElementTree import SubElement

from util import init_logger

_LOGGER = init_logger(__name__, level=logging.DEBUG)
DICTIONARY = dict()


def dictionary_write(el):
    words = SubElement(el, "dictionary")

    for w, lst in DICTIONARY.items():
        word = SubElement(words, "word", {"name": w})
        for s in lst:
            v = SubElement(word, 'v')
            v.text = s


def dictionary_parse(root):
    global DICTIONARY
    try:
        root1 = root.getElementsByTagName("dictionary")[0]
        d433s = root1.getElementsByTagName("word")
        for d433 in d433s:
            try:
                nm = d433.attributes['name'].value
                irs = d433.getElementsByTagName("v")
                terms = list()
                DICTIONARY.update({nm: terms})
                for ir in irs:
                    irc = ir.childNodes[0].nodeValue
                    if len(irc):
                        terms.append(irc)
            except:  # noqa: E722
                _LOGGER.warning(f"{traceback.format_exc()}")
    except:  # noqa: E722
        _LOGGER.warning(f"{traceback.format_exc()}")
    return DICTIONARY
