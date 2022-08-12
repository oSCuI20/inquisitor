#
# ./osimodel/transport/tcp.py
# Eduardo Banderas Alba
# 2022-08
#
# Disassemble tcp packet
#
from osimodel.layer                   import *
from utils.utils                      import tohex


class tcp(Layer):

  _HEADER_LEN    = 20
  _unpack_format = '!HHLLHHHH'

  __states = {
    'URG': 0x20,
    'ACK': 0x10,
    'PSH': 0x08,
    'RST': 0x04,
    'SYN': 0x02,
    'FIN': 0x01
  }

  __src = None  #2 bytes
  __dst = None  #2 bytes
  __seq_number             = None  #4 bytes
  __acknowledgement_number = None  #4 bytes
  __header_length          = None  #4 Bits
  __reserved               = None  #6 Bits
  __stateful       = {}
  __window_size    = None    #2 bytes
  __checksum       = None    #2 bytes
  __urgent_pointer = None    #2 bytes
  __options        = None    #4 bytes

  __protocol = None
  __support  = {
    80:  'http',
    443: 'https',
    20:  'ftp',
    21:  'ftp',
    53:  'dns'
  }

  def __init__(self, raw, verbose=False):
    self.__properties = [ 'src', 'dst', 'seq_number', 'checksum',
                          'acknowledgement_number', 'header_length', 'window_size',
                          'stateful', 'pktdata' ]
    super().__init__(raw, verbose)
  #__init__

  def _header(self):
    self.src, \
    self.dst, \
    self.seq_number, \
    self.acknowledgement_number, \
    doff_reserved_state, \
    self.window_size, \
    self.checksum, \
    self.urgent = self.pktheader

    self.header_length = (doff_reserved_state >> 12) * 4
    self.stateful      = doff_reserved_state - ((doff_reserved_state >> 10) << 10)

    self.protocol = (self.src, self.dst)

    # the range of tcp header is 20-60 bytes.
    if self._HEADER_LEN < self.header_length:
      self.pktdata = self.pktdata[self.header_length - self._HEADER_LEN:]
  #_header

  def _data(self):
    if self.protocol:
      mod = None
      if self.protocol in self.APPLICATION:
        mod = f'{self.PATHLIB}.application.{self.protocol}'

      self._load_module(mod, self.protocol)
  #_data

  def protocol():
    def fget(self):
      return self.__protocol

    def fset(self, v):
      for p in v:
        if not self.__protocol:
          self.__protocol = self.__support.get(p)
      #endfor

    def fdel(self):
      del self.__protocol

    return locals()
  #end definition protocol property

  def format():
    def fget(self):
      if not self.verbose:
        msg = ''
        if hasattr(self, '_module'):
          msg = f'{self._module.format}'

        return msg

      mbit = ''

      mbit += 'U' if self.stateful['urg'] else 'u'
      mbit += 'A' if self.stateful['ack'] else 'a'
      mbit += 'P' if self.stateful['psh'] else 'p'
      mbit += 'R' if self.stateful['rst'] else 'r'
      mbit += 'S' if self.stateful['syn'] else 's'
      mbit += 'F' if self.stateful['fin'] else 'f'

      return f'[{mbit}] seq: {self.seq_number} wsize: {self.window_size} checksum: {self.checksum}' + \
             f'' if not hasattr(self, '_module') else f'{self._module.format}'

    return locals()
  #end definition format property

  def src():
    doc = "The src property."
    def fget(self):
      return self.__src

    def fset(self, v):
      self.__src = v

    def fdel(self):
      del self.__src

    return locals()
  #end definition src property

  def dst():
    doc = "The dst property."
    def fget(self):
      return self.__dst

    def fset(self, v):
      self.__dst = v

    def fdel(self):
      del self.__dst

    return locals()
  #end definition dst property

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

  def acknowledgement_number():
    doc = "The acknowledgement_number property."
    def fget(self):
      return self.__acknowledgement_number

    def fset(self, v):
      self.__acknowledgement_number = v

    def fdel(self):
      del self.__acknowledgement_number

    return locals()
  #end definition acknowledgement_number property

  def header_length():
    doc = "The header_length property."
    def fget(self):
      return self.__header_length

    def fset(self, v):
      self.__header_length = v

    def fdel(self):
      del self.__header_length

    return locals()
  #end definition header_length property

  def window_size():
    doc = "The window_size property."
    def fget(self):
      return self.__window_size

    def fset(self, v):
      self.__window_size = v

    def fdel(self):
      del self.__window_size

    return locals()
  #end definition window_size property

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

  def stateful():
    doc = "The stateful property."
    def fget(self):
      return self.__stateful

    def fset(self, v):
      self.__stateful = {
        'urg': bool(v & self.__states['URG']),
        'ack': bool(v & self.__states['ACK']),
        'psh': bool(v & self.__states['PSH']),
        'rst': bool(v & self.__states['RST']),
        'syn': bool(v & self.__states['SYN']),
        'fin': bool(v & self.__states['FIN'])
      }

    def fdel(self):
      del self.__stateful

    return locals()
  #end definition syn property

  protocol               = property(**protocol())
  format                 = property(**format())
  src                    = property(**src())
  dst                    = property(**dst())
  seq_number             = property(**seq_number())
  acknowledgement_number = property(**acknowledgement_number())
  header_length          = property(**header_length())
  window_size            = property(**window_size())
  checksum               = property(**checksum())
  stateful               = property(**stateful())
#class tcp


class tcpException(LayerException):
  pass
#class tcpException
