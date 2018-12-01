import binascii
import struct

def pronto2lirc(pronto):
    codes = [long(binascii.hexlify(pronto[i:i+2]), 16) for i in xrange(0, len(pronto), 2)]
    #print 'cod = %d %d' % (len(codes),(codes[2] + codes[3]))

    if codes[0]:
        raise ValueError('Pronto code should start with 0000')
    if len(codes) != 4 + 2 * (codes[2] + codes[3]):
        raise ValueError('Number of pulse widths does not match the preamble')

    frequency = 1 / (codes[1] * 0.241246)
    print "Freq %f" % frequency
    return [int(round(code / frequency)) for code in codes[4:]]

def lirc2broadlink(pulses):
    if isinstance(pulses, basestring):
        pulses = [int(i) for i in pulses.split(',')]
    if len(pulses)%2:
        pulses.append(pulses[-1])
    array = bytearray()

    for pulse in pulses:
        pulse = int(round(pulse * 269.0 / 8192.0))  # 32.84ms units

        if pulse < 256:
            array += bytearray(struct.pack('>B', pulse))  # big endian (1-byte)
        else:
            array += bytearray([0x00])  # indicate next number is 2-bytes
            array += bytearray(struct.pack('>H', pulse if pulse<=65535 else 65535))  # big endian (2-bytes)

    packet = bytearray([0x26, 0x00])  # 0x26 = IR, 0x00 = no repeats
    packet += bytearray(struct.pack('<H', len(array)))  # little endian byte count
    packet += array
    packet += bytearray([0x0d, 0x05])  # IR terminator

    # Add 0s to make ultimate packet size a multiple of 16 for 128-bit AES encryption.
    remainder = (len(packet) + 4) % 16  # rm.send_data() adds 4-byte header (02 00 00 00)
    if remainder:
        packet += bytearray(16 - remainder)

    return packet

def broadlink2lirc(packet):
    if packet[0]!='\x26':
        packet = packet.decode('hex')
    arrsz = struct.unpack('<H',packet[2:4])[0]
    lircarr = list()
    i = 4
    while i-4<arrsz:
        pul = struct.unpack('>B',packet[i:i+1])[0]
        i+=1
        if pul==0:
            pul = struct.unpack('>H',packet[i:i+2])[0]
            i+=2
        lircarr.append(int(round(pul*8192.0/269.0)))

    return lircarr

def printbroadlink(packet):
    print str(packet).encode('hex')