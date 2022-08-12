#
# ./osimodel/transport/icmp.py
# Eduardo Banderas Alba
# 2022-08
#
# Disassemble icmp packet
#
from osimodel.layer                   import *
from utils.utils                      import tohex


class icmp(Layer):

  _HEADER_LEN    = 8
  _unpack_format = '!BBHHH'



  __type       = None  #1 byte
  __code       = None  #1 byte
  __seq_number = None  #2 bytes
  __checksum   = None  #2 bytes
  __id         = None  #2 bytes

  __types_codes = {
    0x03: {    #type: destination unreachable
      #codes
      0x00:	'Destination network unreachable',
      0x01:	'Destination host unreachable',
      0x02:	'Destination protocol unreachable',
      0x03:	'Destination port unreachable',
      0x04:	'Fragmentation required, and DF set',
      0x05:	'Source route failed',
      0x06:	'Destination network unknown',
      0x07:	'Destination host unknown',
      0x08:	'Source host isolated',
      0x09:	'Network administratively prohibited',
      0x0A:	'Host administratively prohibited',
      0x0B:	'Network unreachable for Type Of Service',
      0x0C:	'Host unreachable for Type of Service',
      0x0D:	'Administratively prohibited'
    },
    0x05: {    #type: redirect message
      #codes
      0x00:	'Redirect Datagram for the Network',
      0x01:	'Redirect Datagram for the Host',
      0x02:	'Redirect Datagram for the Type of Service & network',
      0x03:	'Redirect Datagram for the Type of Service & host'
    },
    0x0B: {    #type: time exceeded
      #codes
      0x00: 'TTL expired',
      0x01: 'Fragment reassembly time exceeded'
    },
    0x0C: {    #type: parameter problem
      0x00: 'Pointer indicates the error',
      0x01: 'Missing a required option',
      0x02: 'Bad length'
    },
    0x00: { 0x00: 'Echo reply' },                              #type: echo reply (used for ping/tracert)
    0x04: { 0x00: 'Traffic congestion control' },              #type: source quench
    0x06: { None: '' },                                        #type: alternate host address - deprecated
    0x08: { 0x00: 'Echo request' },                            #ŧype: echo request
    0x09: { 0x00: 'Router Advertisement' },                    #type: router advertisement
    0x0A: { 0x00: 'Router discovery/selection/solicitation' }, #type: router solicitation
    0x0D: { 0x00: 'Timestamp Request' },                       #type: timestamp request
    0x0E: { 0x00: 'Timestamp Reply' },                         #type: timestamp reply
    0x0f: { 0x00: 'Information Request' },                     #type: information request
    0x10: { 0x00: 'Information Reply' },                       #type: information reply
    0x11: { 0x00: 'Address Mask Request' },                    #type: address mask request
    0x12: { 0x00: 'Address Mask Reply' },                      #type: address mask reply
    0x1E: { 0x00: 'Information Request' },
    0x1F: { None: 'Datagram Conversion Error' },
    0x20: { None: 'Mobile Host Redirect' },
    0x21: { None: 'Where-Are-You' },
    0x22: { None: 'Here-I-Am' },
    0x23: { None: 'Mobile Registration Request' },
    0x24: { None: 'Mobile Registration Reply' },
    0x25: { None: 'Domain Name Request' },
    0x26: { None: 'Domain Name Reply' },
    0x27: { None: 'SKIP Algorithm Discovery Protocol' },       #type: SKIP Algorithm
    0x28: { None: 'Photuris (Firefly) security protocol' },    #type: Photuris protocol
    0x29: { None: 'ICMP for experimental mobility protocols such as Seamoby' },
    #0x01: { None: 'Reserved' },                               #type: reserved
    #0x02: { None: 'Reserved' },                               #type: reserved
    #0x07: { None: 'Reserved' },                               #ŧype: reserved
    #0x13: { None: 'Reserved for security' },                  #type: reserved for security
    #0x14: { None: 'Reserved for robustness experiment' },     #type: 20 through 29
    #0x2A: { None: 'Reserved' }                                #type: 42 through 255
  }
  __types_codes_reserved = [ 0x01, 0x02, 0x07 ] + list(range(0x13, 0x1E)) + list(range(0x2A, 0x100))

  def __init__(self, raw, verbose=False):
    self.__properties = [ 'type', 'code', 'checksum',
                          'id', 'seq_number', 'pktmessage' ]
    super().__init__(raw, verbose)
  #__init__

  def _header(self):
    self.type, self.code, self.checksum, self.id, self.seq_number = self.pktheader

    if self.type not in self.__types_codes_reserved:
      self.pktmessage = self.__types_codes[self.type][self.code]
  #_header

  def _data(self):
    pass
  #_data

  def format():
    def fget(self):
      if not self.verbose:
        msg = ''
        if hasattr(self, '_module'):
          msg = f'{self._module.format}'

        return msg

      return f'id: {self.id} msg: {self.pktmessage} seq: {self.seq_number} checksum: {self.checksum}'

    return locals()
  #end definition format property

  def seq_number():
    doc = "The seq_number property."
    def fget(self):
      return self.__seq_number

    def fset(self, v):
      self.__seq_number = v

    def fdel(self):
      del self.__seq_number

    return locals()
  #end definition seq_number property

  def checksum():
    doc = "The checksum property."
    def fget(self):
      return self.__checksum

    def fset(self, v):
      self.__checksum = v

    def fdel(self):
      del self.__checksum

    return locals()
  #end definition checksum property

  def id():
    doc = "The id property."
    def fget(self):
      return self.__id

    def fset(self, v):
      self.__id = v

    def fdel(self):
      del self.__id

    return locals()
  #end definition id property

  def type():
    doc = "The type property."
    def fget(self):
      return self.__type

    def fset(self, v):
      self.__type = v

    def fdel(self):
      del self.__type

    return locals()
  #end definition type property

  def code():
    doc = "The code property."
    def fget(self):
      return self.__code

    def fset(self, v):
      self.__code = v

    def fdel(self):
      del self.__code

    return locals()
  #end definition code property

  def pktmessage():
    doc = "The pktmessage property."
    def fget(self):
      return self.__pktmessage

    def fset(self, v):
      self.__pktmessage = v

    def fdel(self):
      del self.__pktmessage

    return locals()
  #end definition pktmessage property

  format     = property(**format())
  seq_number = property(**seq_number())
  checksum   = property(**checksum())
  id         = property(**id())
  type       = property(**type())
  code       = property(**code())
  pktmessage = property(**pktmessage())
#class icmp


class icmpException(LayerException):
  pass
#class icmpException
