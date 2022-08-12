#
# ./osimodel/transport/igmp.py
# Eduardo Banderas Alba
# 2022-08
#
# Disassemble igmp packet
#
from osimodel.layer                   import *
from utils.utils                      import tohex


class igmp(Layer):

  _HEADER_LEN    = 8
  _unpack_format = '!BBHL'

  __type = None
  __max_resp_time = None
  __checksum = None
  __group_address = None

  def _header(self):
    self.type, \
    self.max_resp_time, \
    self.checksum, \
    self.group_address = self.pktheader
  #_header

  def _data(self):
    pass

  def format():
    def fget(self):
      if not self.verbose:
        msg = ''
        if hasattr(self, '_module'):
          msg = f'{self._module.format}'

        return msg

    return locals()
  #end definition format property

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

  def max_resp_time():
    doc = "The max_resp_time property."
    def fget(self):
      return self.__max_resp_time

    def fset(self, v):
      self.__max_resp_time = v

    def fdel(self):
      del self.__max_resp_time

    return locals()
  #end definition max_resp_time property

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

  def group_address():
    doc = "The group_address property."
    def fget(self):
      return self.__group_address

    def fset(self, v):
      self.__group_address = v

    def fdel(self):
      del self.__group_address

    return locals()
  #end definition group_address property

  format        = property(**format())
  type          = property(**type())
  max_resp_time = property(**max_resp_time())
  checksum      = property(**checksum())
  group_address = property(**group_address())
#class igmp

class igmpException(Exception):
  pass
#class igmpException
