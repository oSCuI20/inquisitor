#
# ./osimodel/application/dhcp.py
# Eduardo Banderas Alba
# 2022-08
#
from osimodel.layer                   import *
from utils.utils                      import tohex


class dhcp(ApplicationLayer):

  __operation_codes = {
    0x01: 'Request',
    0x02: 'Reply'
  }

  _PACKET_LEN    = 44
  _unpack_format = '!BBBBLHH 4s 4s 4s 4s 16s'

  __op    = None      # 1 byte
  __htype = None      # 1 byte
  __hlen  = None      # 1 byte
  __hops  = None      # 1 byte
  __xid   = None      # 4 bytes
  __secs  = None      # 2 bytes
  __flags = None      # 2 bytes
  __ciaddr = None     # 4 bytes
  __yiaddr = None     # 4 bytes
  __siaddr = None     # 4 bytes
  __giaddr = None     # 4 bytes
  __chaddr = None     # 16 bytes
  __sname  = None     # 64 bytes (optional)
  __file   = None     # 128 bytes (optional)
  __options = None    # Variable

  def __init__(self, raw, verbose=False):
    super().__init__(raw, verbose)
  #__init__

  def _data(self):
    self.op, \
    self.htype, \
    self.hlen, \
    self.hops, \
    self.xid, \
    self.secs, \
    self.flags, \
    self.ciaddr, \
    self.yiaddr, \
    self.siaddr, \
    self.giaddr, \
    self.chaddr = self.unpack(self._unpack_format, self.pktdata[:self._PACKET_LEN])
  #_data

  def format():
    def fget(self):
      operation_code = self.__operation_codes.get(self.op)
      request_from   = ':'.join(map(tohex, self.chaddr[0:self.hlen]))
      return f'BOOTP/DHCP {operation_code} from {request_from} {self.ciaddr} {self.yiaddr} {self.siaddr} {self.giaddr}'

    return locals()
  #end definition format property

  def op():
    doc = "The op property."
    def fget(self):
      return self.__op

    def fset(self, v):
      self.__op = v

    def fdel(self):
      del self.__op

    return locals()
  #end definition op property

  def htype():
    doc = "The htype property."
    def fget(self):
      return self.__htype

    def fset(self, v):
      self.__htype = v

    def fdel(self):
      del self.__htype

    return locals()
  #end definition htype property

  def hlen():
    doc = "The hlen property."
    def fget(self):
      return self.__hlen

    def fset(self, v):
      self.__hlen = v

    def fdel(self):
      del self.__hlen

    return locals()
  #end definition hlen property

  def hops():
    doc = "The hops property."
    def fget(self):
      return self.__hops

    def fset(self, v):
      self.__hops = v

    def fdel(self):
      del self.__hops

    return locals()
  #end definition hops property

  def xid():
    doc = "The xid property."
    def fget(self):
      return self.__xid

    def fset(self, v):
      self.__xid = v

    def fdel(self):
      del self.__xid

    return locals()
  #end definition xid property

  def secs():
    doc = "The secs property."
    def fget(self):
      return self.__secs

    def fset(self, v):
      self.__secs = v

    def fdel(self):
      del self.__secs

    return locals()
  #end definition secs property

  def flags():
    doc = "The flags property."
    def fget(self):
      return self.__flags

    def fset(self, v):
      self.__flags = v

    def fdel(self):
      del self.__flags

    return locals()
  #end definition flags property

  def ciaddr():
    doc = "The ciaddr property."
    def fget(self):
      return self.__ciaddr

    def fset(self, v):
      self.__ciaddr = v

    def fdel(self):
      del self.__ciaddr

    return locals()
  #end definition ciaddr property

  def yiaddr():
    doc = "The yiaddr property."
    def fget(self):
      return self.__yiaddr

    def fset(self, v):
      self.__yiaddr = v

    def fdel(self):
      del self.__yiaddr

    return locals()
  #end definition yiaddr property

  def siaddr():
    doc = "The siaddr property."
    def fget(self):
      return self.__siaddr

    def fset(self, v):
      self.__siaddr = v

    def fdel(self):
      del self.__siaddr

    return locals()
  #end definition siaddr property

  def giaddr():
    doc = "The giaddr property."
    def fget(self):
      return self.__giaddr

    def fset(self, v):
      self.__giaddr = v

    def fdel(self):
      del self.__giaddr

    return locals()
  #end definition giaddr property

  def chaddr():
    doc = "The chaddr property."
    def fget(self):
      return self.__chaddr

    def fset(self, v):
      self.__chaddr = v

    def fdel(self):
      del self.__chaddr

    return locals()
  #end definition chaddr property

  format = property(**format())
  op     = property(**op())
  htype  = property(**htype())
  hops   = property(**hops())
  xid    = property(**xid())
  secs   = property(**secs())
  flags  = property(**flags())
  ciaddr = property(**ciaddr())
  yiaddr = property(**yiaddr())
  siaddr = property(**siaddr())
  giaddr = property(**giaddr())
  chaddr = property(**chaddr())
#class dhcp
