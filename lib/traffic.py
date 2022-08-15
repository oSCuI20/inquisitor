# -*- coding: utf-8 -*-
#
# ./traffic.py
# Eduardo Banderas Alba
# 2022-08
#
# Objeto para la captura y envío de tráfico
# Requiere root
#
import sys, os

from struct import pack
from time   import sleep

from utils.utils import *
from lib.pcap    import *
from osimodel.datalink.ethernet import Ethernet


class traffic(object):

  __pcap    = None
  __bpf     = None
  __pkthdr  = None
  __stats   = None
  __verbose = False

  _device  = None
  _snaplen = c_int(65535)
  _promisc = True
  _limit   = c_int(-1)    # counter
  _timeout = c_int(1)  # milliseconds => 1s
  _errbuf  = PCAP_ERRORBUF
  _filter  = b''

  def __init__(self, **kwargs):
    """
      :param device
      :param snaplen default 65535
      :param promisc default True
      :param timeout default 1s
      :param limit   default -1
      :param filter  default ''
      :param verbose default False
    """
    for key, value in kwargs.items():
      if isinstance(value, str):
        value = value.encode()

      self.__setattr__(key, value)
    #endfor

    self.__initialize()
  #__init__

  def __initialize(self):
    self.__handle()

    self.__bpf     = bpf_program()
    self.__stat    = stat()
    self.__pkthdr  = POINTER(pkthdr)()
    self.__pktdata = POINTER(c_ubyte * self._snaplen.value)()

    self.terminate = False
  #__initialize

  def __handle(self):
    if hasattr(self, 'handle'):
      return

    self.handle = pcap_open_live(self.device, self._snaplen,
                                             self._promisc, self._timeout, self._errbuf)

    if not self.handle:
      raise trafficException(f'ERROR: handle, {pcap_geterr(self.handle)}')

    if pcap_can_set_rfmon(self.handle) == 1:
      raise trafficException(f'ERROR: Can\'t set interface in monitor mode, {self.__pcap.pcap_geterr()}')

    pcap_setnonblock(self.handle, 1, self._errbuf)
  #__handle

  def stop(self):
    self.terminate = True
    if hasattr(self, 'handle') and self.handle:
      if pcap_stats(self.handle, byref(self.__stat)) == 0:
        self.__logger(f'\nPackets received: {self.__stat.ps_recv}' +
                      f'\nPackets dropped: {self.__stat.ps_ifdrop}')

      pcap_close(self.handle)

    self.handle = None
  #stop

  def capture(self, queue=None):
    counter = 0

    while self.limit.value == -1 or counter < self.limit.value:
      if self.terminate:
        break

      if pcap_next_ex(self.handle, byref(self.__pkthdr),
                                    byref(self.__pktdata)) == 1:
        caplen = self.__pkthdr.contents.caplen
        packet = Ethernet(
          pack('B' * caplen, *self.__pktdata.contents[:caplen]),
          self.verbose
        )
        self.__logger(packet, queue)

        counter += 1

      sleep(0.1)
    #endwhile
  #capture

  def setFilter(self, filter=None):
    if filter:
      self.filter = filter

    if self.filter:
      if pcap_compile(self.handle, byref(self.__bpf), self.filter, 1, 0xFFFFFF) < 0:
        raise trafficException(f'ERROR: {pcap_geterr(self.handle)}')

      if pcap_setfilter(self.handle, byref(self.__bpf)) < 0:
        raise trafficException(f'ERROR: {pcap_geterr(self.handle)}')
    #endif
  #setFilter

  def sendpacket(self, raw_packets, queue=None):
    if not isinstance(raw_packets, tuple):
      raise trafficException('ERROR: raw should be tuple. For every tuple sending packet, 1 tuple = 1 raw packet')

    restore = None

    while True:
      if self.terminate:
        break

      if not queue.empty():
        restore = queue.get()

        if restore:
          raw_packets = restore
      #endif

      for raw in raw_packets:
        if pcap_sendpacket(self.handle, raw, len(raw)) != 0:
          self.__logger(f'error sending packet: {pcap_geterr(self.handle)}', queue)

        sleep(0.1)
      #endfor

      if restore:
        restore = None
        queue.task_done()

      sleep(0.5)
    #endwhile
  #sendpacket

  def __logger(self, msg, queue=None):
    if self.verbose and not queue:
      logger(f'-- {msg}')

    if queue:
      queue.put(msg)
      sleep(0)
  #__logger

  #Properties
  def device():
    doc = 'The device property'
    def fget(self):
      return self._device

    def fset(self, v):


      self._device = v

    def fdel(self):
      del self._device

    return locals()
  #end definition device property

  def filter():
    doc = 'The filter property'
    def fget(self):
      return self._filter

    def fset(self, v):
      if not isinstance(v, bytes) and not isinstance(v, str):
        raise trafficException(f'filter type should be bytes or str, {type(v)}')

      if isinstance(v, bytes):      self._filter = v
      if isinstance(v, str):        self._filter = v.encode('UTF-8')

    def fdel(self):
      del self._filter

    return locals()
  #end definition device property

  def snaplen():
    doc = 'The snaplen property'
    def fget(self):
      return self._snaplen

    def fset(self, v):
      self._snaplen = v

    def fdel(self):
      del self._snaplen

    return locals()
  #end definition snaplen property

  def promisc():
    doc = 'The promisc property'
    def fget(self):
      return self._promisc

    def fset(self, v):
      self._promisc = v

    def fdel(self):
      del self._promisc

    return locals()
  #end definition promisc property

  def timeout():
    doc = 'The timeout property'
    def fget(self):
      return self._timeout

    def fset(self, v):
      if not isinstance(v, int):
        raise trafficException(f'timeout type should be int, {type(v)}')

      self._timeout = ctypes.c_int(v)

    def fdel(self):
      del self._timeout

    return locals()
  #end definition timeout property

  def limit():
    doc = 'The limit property'
    def fget(self):
      return self._limit

    def fset(self, v):
      if not isinstance(v, int):
        raise trafficException(f'limit type should be int,, {type(v)}')

      self._limit = ctypes.c_int(v)

    def fdel(self):
      del self._limit

    return locals()
  #end definition limit property

  def verbose():
    doc = 'The verbose property'
    def fget(self):
      return self.__verbose

    def fset(self, v):
      if not isinstance(v, bool):
        raise trafficException(f'verbose type should be boolean, {type(v)}')

      self.__verbose = v

    def fdel(self):
      del self.__verbose

    return locals()
  #end definition verbose property

  def terminate():
    doc = 'The terminate property'
    def fget(self):
      return self.__terminate

    def fset(self, v):
      if not isinstance(v, bool):
        raise trafficException(f'terminate type should be boolean, {type(v)}')

      self.__terminate = v

    def fdel(self):
      del self.__terminate

    return locals()
  #end definition terminate property

  device  = property(**device())
  filter  = property(**filter())
  snaplen = property(**snaplen())
  promisc = property(**promisc())
  timeout = property(**timeout())
  limit   = property(**limit())
  verbose = property(**verbose())
  termiante = property(**terminate())
#class traffic


class trafficException(Exception):
  def __init__(self, msg):      self.msg = msg
  def __str__(self):            return repr(self.msg)
#class trafficException
