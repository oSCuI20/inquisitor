# -*- coding: utf-8 -*-
#
# ./traffic.py
# Eduardo Banderas Alba
# 2022-08
#
# Info about device selected
#
import socket, fcntl, struct, os


class Device(object):
  """
    Info about device
  """

  __ipaddr    = None
  __netmask   = None
  __hwaddr    = None
  __interface = None
  __io = {
    'ipaddr' : 0x8915,
    'hwaddr' : 0x8927,
    'netmask': 0x891b
  }

  def __init__(self, device=None):
    self.sock      = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    self.interface = device
    if not self.interface:
      self.__auto_interface()

    self.hwaddr = fcntl.ioctl(
      self.sock.fileno(), self.__io['hwaddr'], struct.pack('256s', self.interface.encode())
    )[18:24]
    self.ipaddr = fcntl.ioctl(
      self.sock.fileno(), self.__io['ipaddr'], struct.pack('256s', self.interface.encode())
    )[20:24]
    self.netmask = fcntl.ioctl(
      self.sock.fileno(), self.__io['netmask'], struct.pack('256s', self.interface.encode())
    )[20:24]
  #__init__

  def __auto_interface(self):
    path  = '/sys/class/net'
    state = 'operstate'
    interfaces = os.listdir(path)

    for iface in interfaces:
      if iface == 'lo':    continue   # ignore loopback

      p = f'{path}/{iface}/{state}'
      if os.path.isfile(p) and not self.interface:
        with open(p, 'r') as f:
          netstatus = f.read().strip()

        if netstatus == 'up':
          self.interface = iface
      #endif
    #endfor

    if not self.interface:
      DeviceException('ERROR: there are not any interface active')
  #__auto_interface

  #Properties
  def interface():
    doc = "The interface property."
    def fget(self):
      return self.__interface

    def fset(self, v):
      self.__interface = v

    def fdel(self):
      del self.__interface

    return locals()

  interface = property(**interface())
  #end definition interface property

  def hwaddr():
    doc = "The hwaddr property."
    def fget(self):
      return self.__hwaddr

    def fset(self, v):
      self.__hwaddr = v.hex(':')

    def fdel(self):
      del self.__hwaddr

    return locals()

  hwaddr = property(**hwaddr())
  #end definition hwaddr property

  def netmask():
    doc = "The netmask property."
    def fget(self):
      return self.__netmask

    def fset(self, v):
      self.__netmask = socket.inet_ntoa(v)

    def fdel(self):
      del self.__netmask

    return locals()

  netmask = property(**netmask())
  #end definition netmask property

  def ipaddr():
    doc = "The ipaddr property."
    def fget(self):
      return self.__ipaddr

    def fset(self, v):
      self.__ipaddr = socket.inet_ntoa(v)

    def fdel(self):
      del self.__ipaddr

    return locals()

  ipaddr = property(**ipaddr())
  #end definition ipaddr property
#class Device


class DeviceException(Exception):
  def __init__(self, msg):      self.msg = msg
  def __str__(self):            return repr(self.msg)
#class deviceException
