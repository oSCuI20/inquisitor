# -*- coding: utf-8 -*-
#
# ./osi-model/layer.py
# Eduardo Banderas Alba
# 2022-08
#
# datalink layer
#
import struct
import importlib

from time               import time

from osimodel.constants import Constants
from inquisitor         import args

APPLICATION_LAYER_FILTERS = args.application_filters

class Layer(Constants):

  _HEADER_LEN    = 0
  _unpack_format = None

  def __init__(self, raw, verbose=False):
    self.pktlen    = len(raw)
    self.pktheader = raw[:self._HEADER_LEN]
    self.pktdata   = raw[self._HEADER_LEN:]
    self.verbose   = verbose

    self.__properties = []

    self._header()
    self._data()
  #__init__

  def __str__(self):
    result = { self.__class__.__name__: dict(self) }

    if hasattr(self, '_module'):
      mod = self._module

      while hasattr(mod, '_module'):
        result[mod.__class__.__name__] = dict(mod)
        mod = mod._module
      #endwhile

      result[mod.__class__.__name__] = dict(mod)
    #endif

    return repr(result)
  #__str__

  def __iter__(self):
    for k in self.__properties:
      if not hasattr(self, k):
        continue

      yield (k, getattr(self, k))
  #__iter__

  def _load_module(self, path, module):
    if path and self.pktdata:
      if module not in self.__properties:
        self.__properties.append(module)

      obj = getattr(importlib.import_module(path), module)
      self._module = obj(self.pktdata, self.verbose)

      if issubclass(self._module.__class__, ApplicationLayer):
        self._module.dst = self.dst
        self._module.src = self.src

      self.__setattr__(module, dict(self._module))
  #_load_module

  def time():
    doc = 'The time property.'
    def fget(self):
      t = time()
      return f'{t:6f}'

    return locals()
  #end definition time property

  def verbose():
    doc = 'The verbose property.'
    def fget(self):
      return self._verbose

    def fset(self, v):
      self._verbose = v

    def fdel(self):
      del self._verbose

    return locals()
  #end definition verbose property

  def pktdata():
    doc = "The pktdata property."
    def fget(self):
      return self.__pktdata

    def fset(self, v):
      if not isinstance(v, bytes):
        raise LayerException(f'ERROR: pktdata is not bytes type {type(v)}')

      self.__pktdata = v

    def fdel(self):
      del self.__pktdata

    return locals()
  #end definition pktdata property

  def pktheader():
    doc = "The pktheader property."
    def fget(self):
      return self.__pktheader

    def fset(self, v):
      if not isinstance(v, bytes):
        raise LayerException(f'ERROR: pktheader is not bytes type {type(v)}')

      if len(v) != self._HEADER_LEN:
        raise LayerException(f'ERROR: pktheader should be {self._HEADER_LEN} bytes')

      self.__pktheader = struct.unpack(self._unpack_format, v)

    def fdel(self):
      del self.__pktheader

    return locals()
  #end definition pktheader property

  def pktlen():
    doc = "The pktlen property."
    def fget(self):
      return self.__pktlen

    def fset(self, v):
      self.__pktlen = v

    def fdel(self):
      del self.__pktlen

    return locals()
  #end definition pktlen property

  time      = property(**time())
  verbose   = property(**verbose())
  pktdata   = property(**pktdata())
  pktheader = property(**pktheader())
  pktlen    = property(**pktlen())
#class Layer


class LayerException(Exception):
  def __init__(self, msg):      self.msg = msg
  def __str__(self):            return repr(self.msg)
#class LayerException


class ApplicationLayer(object):

  unpack      = struct.unpack
  unpack_from = struct.unpack_from

  __pktdata = None

  def __init__(self, raw, verbose=False):
    self.__properties = [ 'data' ]

    self.pktdata = raw
    self.verbose = verbose
    self.filter  = args.application_filters

    self._data()
  #__init__

  def __iter__(self):
    for k in self.__properties:
      if not hasattr(self, k):
        continue

      yield (k, getattr(self, k))
  #__iter__

  def _data(self):
    try:
      self.data = self.pktdata.decode()
    except:
      self.data = ''
  #_data

  def format():
    def fget(self):
      if not self.verbose:
          return ''

      return f'length {len(self.pktdata)}' + \
             f'\n{self.data}' if self.data and self.verbose else f''

    return locals()
  #end definition format property

  def verbose():
    doc = 'The verbose property.'
    def fget(self):
      return self._verbose

    def fset(self, v):
      self._verbose = v

    def fdel(self):
      del self._verbose

    return locals()
  #end definition verbose property

  def pktdata():
    doc = "The pktdata property."
    def fget(self):
      return self.__pktdata

    def fset(self, v):
      if not isinstance(v, bytes):
        raise LayerException(f'ERROR: pktdata is not bytes type {type(v)}')

      self.__pktdata = v

    def fdel(self):
      del self.__pktdata

    return locals()
  #end definition pktdata property

  format  = property(**format())
  pktdata = property(**pktdata())
  verbose = property(**verbose())
#class ApplicationLayer


class ApplicationException(Exception):
  def __init__(self, msg):      self.msg = msg
  def __str__(self):            return repr(self.msg)
#class ApplicationException
