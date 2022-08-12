#
# ./osimodel/datalink/arp.py
# Eduardo Banderas Alba
# 2022-08
#
# arp packages
#
from osimodel.layer                   import *
from utils.utils                      import tohex


class arp(Layer):

  _HEADER_LEN    = 28
  _unpack_format = '!HHBBH 6s 4s 6s 4s'

  __IP_LEN  = 4
  __MAC_LEN = 6

  __htype = None    #2 bytes  hardware type
  __ptype = None    #2 bytes  protocol type
  __hlen  = None    #1 byte   hardware length
  __plen  = None    #1 byte   protocol length
  __op    = None    #2 bytes  op code
  __sha   = None    #6 bytes  sender hardware address
  __spa   = None    #4 bytes  sender protocol address
  __tha   = None    #6 bytes  target hardware address
  __tpa   = None    #4 bytes  target protocol address

  __opmode = {
    0x01: 'ARP Request',
    0x02: 'ARP Reply'
  }

  def __init__(self, raw, verbose=False):
    self.__properties = [ 'htype', 'ptype', 'hlen', 'plen',
                          'op', 'opmode', 'sha', 'spa', 'tha', 'tpa',
                          'format', 'pktdata' ]
    super().__init__(raw, verbose)
  #__init__

  def _header(self):
    self.htype, \
    self.ptype, \
    self.hlen, \
    self.plen, \
    self.op, \
    self.sha, \
    self.spa, \
    self.tha, \
    self.tpa = self.pktheader

  def _data(self):
    pass

  def format():
    def fget(self):
      if not self.verbose:
        msg = ''
        if hasattr(self, '_module'):
          msg = f'{self._module.format}'

        return msg

      return f'{self.opmode} {self.sha} ({self.spa}) -> {self.tha} ({self.tpa})'

    return locals()
  #end definition format property

  def opmode():
    doc = "The opmode property."
    def fget(self):
      return self.__opmode.get(self.op)

    return locals()
  #end definition opmode property

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

  def ptype():
    doc = "The ptype property."
    def fget(self):
      return self.__ptype

    def fset(self, v):
      self.__ptype = v

    def fdel(self):
      del self.__ptype

    return locals()
  #end definition ptype property

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

  def plen():
    doc = "The plen property."
    def fget(self):
      return self.__plen

    def fset(self, v):
      self.__plen = v

    def fdel(self):
      del self.__plen

    return locals()
  #end definition plen property

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

  def sha():
    doc = "The sha property."
    def fget(self):
      return self.__sha

    def fset(self, v):
      if not isinstance(v, bytes):
        raise ARPException(f'ERROR: sha is not bytes type {type(v)}')

      if len(v) != self.__MAC_LEN:
        raise ARPException(f'ERROR: sha should be {self.__MAC_LEN} bytes')

      self.__sha = ':'.join(map(tohex, v))

    def fdel(self):
      del self.__sha

    return locals()
  #end definition sha property

  def spa():
    doc = "The spa property."
    def fget(self):
      return self.__spa

    def fset(self, v):
      if not isinstance(v, bytes):
        raise ARPException(f'ERROR: spa is not bytes type {type(v)}')

      if len(v) != self.__IP_LEN:
        raise ARPException(f'ERROR: spa should be {self.__IPLEN} bytes')

      self.__spa = '.'.join(map(str, v))

    def fdel(self):
      del self.__spa

    return locals()
  #end definition spa property

  def tha():
    doc = "The tha property."
    def fget(self):
      return self.__tha

    def fset(self, v):
      if not isinstance(v, bytes):
        raise ARPException(f'ERROR: tha is not bytes type {type(v)}')

      if len(v) != self.__MAC_LEN:
        raise ARPException(f'ERROR: tha should be {self.__MAC_LEN} bytes')

      self.__tha = ':'.join(map(tohex, v))

    def fdel(self):
      del self.__tha

    return locals()
  #end definition tha property

  def tpa():
    doc = "The tpa property."
    def fget(self):
      return self.__tpa

    def fset(self, v):
      if not isinstance(v, bytes):
        raise ARPException(f'ERROR: tpa is not bytes type {type(v)}')

      if len(v) != self.__IP_LEN:
        raise ARPException(f'ERROR: tpa should be {self.__IP_LEN} bytes')

      self.__tpa = '.'.join(map(str, v))

    def fdel(self):
      del self.__tpa

    return locals()
  #end definition tpa property

  format = property(**format())
  opmode = property(**opmode())
  htype  = property(**htype())
  ptype  = property(**ptype())
  hlen   = property(**hlen())
  plen   = property(**plen())
  op     = property(**op())
  sha    = property(**sha())
  spa    = property(**spa())
  tha    = property(**tha())
  tpa    = property(**tpa())
#class arp

class ARPException(LayerException):
  pass
#class EthernetException
