import binascii
import struct
import logging
from util import init_logger

_LOGGER = init_logger(__name__, level=logging.DEBUG)


def pronto2lirc(pronto):
    codes = [int(binascii.hexlify(pronto[i:i + 2]), 16)
             for i in range(0, len(pronto), 2)]
    # print 'cod = %d %d' % (len(codes),(codes[2] + codes[3]))

    if codes[0]:
        raise ValueError('Pronto code should start with 0000')
    if len(codes) != 4 + 2 * (codes[2] + codes[3]):
        raise ValueError('Number of pulse widths does not match the preamble')

    frequency = 1 / (codes[1] * 0.241246)
    _LOGGER.info(f"Freq {frequency}")
    return [int(round(code / frequency)) for code in codes[4:]]


def lirc2broadlink(pulses):
    if isinstance(pulses, bytes):
        pulses = [int(i) for i in pulses.split(',')]
    if len(pulses) % 2:
        pulses.append(pulses[-1])
    array = bytearray()

    for pulse in pulses:
        pulse = int(round(pulse * 269.0 / 8192.0))  # 32.84ms units

        if pulse < 256:
            array += bytearray(struct.pack('>B', pulse))  # big endian (1-byte)
        else:
            array += bytearray([0x00])  # indicate next number is 2-bytes
            # big endian (2-bytes)
            array += bytearray(struct.pack('>H',
                                           pulse if pulse <= 65535 else 65535))

    packet = bytearray([0x26, 0x00])  # 0x26 = IR, 0x00 = no repeats
    packet += bytearray(struct.pack('<H', len(array))
                        )  # little endian byte count
    packet += array
    packet += bytearray([0x0d, 0x05])  # IR terminator

    # Add 0s to make ultimate packet size a multiple of 16 for 128-bit AES encryption.
    # rm.send_data() adds 4-byte header (02 00 00 00)
    remainder = (len(packet) + 4) % 16
    if remainder:
        packet += bytearray(16 - remainder)

    return packet


def broadlink2lirc(packet):
    if packet[0] != b'\x26':
        packet = binascii.unhexlify(packet)
    arrsz = struct.unpack('<H', packet[2:4])[0]
    lircarr = list()
    i = 4
    while i - 4 < arrsz:
        pul = struct.unpack('>B', packet[i:i + 1])[0]
        i += 1
        if pul == 0:
            pul = struct.unpack('>H', packet[i:i + 2])[0]
            i += 2
        lircarr.append(int(round(pul * 8192.0 / 269.0)))

    return lircarr


def printbroadlink(packet):
    _LOGGER.info(binascii.hexlify(packet))
