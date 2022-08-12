#
# ./osimodel/application/dns.py
# Eduardo Banderas Alba
# 2022-08
#
from osimodel.layer                   import *
from utils.utils                      import tohex


class dns(ApplicationLayer):

  __operation_codes = {
    0x00: 'Query',
    0x01: 'IQuery',
    0x02: 'Status',
    0x03: 'Reserved',
    0x04: 'Notify',
    0x05: 'Update'
  }

  __response_codes = {
    0x00: 'No error',
    0x01: 'Format error',
    0x02: 'Server failure',
    0x03: 'Name error',
    0x04: 'Not implement',
    0x05: 'Refused',
    0x06: 'YX Domain',
    0x07: 'YX RR Set',
    0x08: 'NX RR Set',
    0x09: 'Not auth',
    0x0A: 'Not zone'
  }

  __qresponse = {
    0x00: 'Query',
    0x01: 'Response'
  }

  __dns_query_types = {
      0x0001: 'A',
      0x0002: 'NS',
      0x0003: 'MD',
      0x0004: 'MF',
      0x0005: 'CNAME',
      0x0006: 'SOA',
      0x0007: 'MB',
      0x0008: 'MG',
      0x0009: 'MR',
      0x000a: 'NULL',
      0x000b: 'WKS',
      0x000c: 'PTR',
      0x000d: 'HINFO',
      0x000e: 'MINFO',
      0x000f: 'MX',
      0x0010: 'TXT',
      0x0011: 'RP',
      0x0012: 'AFSDB',
      0x0013: 'X25',
      0x0014: 'ISDN',
      0x0015: 'RT',
      0x0016: 'NSAP',
      0x0017: 'NSAPPTR',
      0x0018: 'SIG',
      0x0019: 'KEY',
      0x001a: 'PX',
      0x001b: 'GPOS',
      0x001c: 'AAAA',
      0x001d: 'LOC',
      0x001e: 'NXT',
      0x001f: 'EID',
      0x0020: 'NIMLOC',
      0x0021: 'SRV',
      0x0022: 'ATMA',
      0x0023: 'NAPTR',
      0x0024: 'KX',
      0x0025: 'CERT',
      0x0026: 'A6',
      0x0027: 'DNAME',
      0x0028: 'SINK',
      0x0029: 'OPT',
      0x002B: 'DS',
      0x002E: 'RRSIG',
      0x002F: 'NSEC',
      0x0030: 'DNSKEY',
      0x0031: 'DHCID',
      0x0064: 'UINFO',
      0x0065: 'UID',
      0x0066: 'GID',
      0x0067: 'UNSPEC',
      0x00f8: 'ADDRS',
      0x00f9: 'TKEY',
      0x00fa: 'TSIG',
      0x00fb: 'IXFR',
      0x00fc: 'AXFR',
      0x00fd: 'MAILB',
      0x00fe: 'MAILA',
      0x00ff: 'ANY',
      0xff01: 'WINS',
      0xff02: 'WINSR'
  }
  __dns_query_classes = {
      0x0001: 'INTERNET',
      0x0002: 'CSNET',
      0x0003: 'CHAOS',
      0x0004: 'HESIOD',
      0x00fe: 'NONE',
      0x00ff: 'ALL',
      0x00ff: 'ANY'

  }

  _PACKET_LEN    = 12
  _unpack_format = '!HHHHHH'

  __identifier      = None       # 2 bytes
                                 # 2 bytes
  __query_response  = None       # 1 bit
  __code            = None       # 4 bit
  __auth_answer     = None       # 1 bit
  __truncation_flag = None       # 1 bit
  __recursion_desired   = None   # 1 bit
  __recursion_available = None   # 1 bit
  __zero          = None         # 3 bit
  __rcode         = None         # 4 bit

  __qdcount = None  # 2 bytes
  __ancount = None  # 2 bytes
  __nscount = None  # 2 bytes
  __arcount = None  # 2 bytes

  __sections = []  # decode data

  def __init__(self, raw, verbose=False):
    self.__sections = []
    super().__init__(raw, verbose)
  #__init__

  def _data(self):
    self.identifier, \
    flags_codes, \
    self.qdcount, \
    self.ancount, \
    self.nscount, \
    self.arcount = self.unpack(self._unpack_format, self.pktdata[:self._PACKET_LEN])

    self.query_response      = flags_codes >> 8
    self.code                = flags_codes >> 8
    self.auth_answer         = flags_codes >> 8
    self.truncation_flag     = flags_codes >> 8
    self.recursion_desired   = flags_codes >> 8
    self.recursion_available = flags_codes & 0xff
    self.zero                = flags_codes & 0xff
    self.rcode               = flags_codes & 0xff

    if self.rcode == 0x00 and self.query_response in [0x00, 0x01]: #client query
      self.question()
  #_data

  def question(self):
    pktdata = self.pktdata[self._PACKET_LEN:]
    offset  = 0

    for n in range(self.qdcount):
      qname, offset = self.labels(pktdata, offset)
      qtype, qclass, qdata, offset = self.resolution(pktdata, offset)
      section = {
        'qname': qname,
        'qtype': qtype,
        'qclass': qclass,
        'qdata': qdata
      }

      offset += 4

      self.__sections.append(section)
  #question

  def resolution(self, msg, offset):
    qtype, qclass, qdata = ('', '', '')
    if self.query_response == 0x01:
      while msg[offset] != 0xc0:
        offset +=1

      offset += 2

      qtype, qclass, bytesfin, ttl, next_step = self.unpack_from('!H H H H H', msg, offset)
      offset += 10

      if qtype == 0x01:         # type A
        pass
        #qdata = '{0}.{1}.{2}.{3}'.format(*self.unpack_from('!BBBB', msg, offset))

      if qtype == 0x05:          # type CNAME
        pass
        #test=self.unpack_from('!10s', msg, offset)
        #print(test)
        #qdata = '{0}.{1}.{2}.{3}'.format(*self.unpack_from('!BBBB', msg, offset))
      offset += next_step

    return qtype, qclass, qdata, offset
  #resolution

  def labels(self, msg, offset):
    out = []

    while True:
      length, = self.unpack_from('!B', msg, offset)

      if (length & 0xc0) == 0xc0:
        p, = self.unpack_from('!H', msg, offset)
        offset += 2
        out += labels(msg, p & 0x3ff)
        return  out, offset

      if (length & 0xc0) != 0x00:
        raise ApplicationException('enconding')

      offset += 1

      if length == 0:
        return out, offset

      out.append(*self.unpack_from('!%ds' % length, msg, offset))
      offset += length
    #endwhile
  #labels

  def __decode(self, string):
    return string.decode()
  #decode

  def format():
    def fget(self):
      data = ''
      for section in self.__sections:
        dn = '.'.join(map(self.__decode, section['qname']))
        data = f'{dn}'

        if self.query_response == 0x01:
          data += f' type {self.__dns_query_types.get(section["qtype"])}'
          data += f' {section["qdata"]}'

        data += ', '
      #endfor

      return f'DNS: {self.identifier} ' + \
             f'{self.__qresponse.get(self.query_response)} ' + \
             f'{data.strip(", ")}'

    return locals()
  #end definition format property

  def identifier():
    def fget(self):
      return self.__identifier

    def fset(self, v):
      self.__identifier = hex(v)

    def fdel(self):
      del self.__identifier

    return locals()
  #end definition identifier property

  def query_response():
    def fget(self):
      return self.__query_response

    def fset(self, v):
      self.__query_response = 1 if v & 0b10000000 else 0

    def fdel(self):
      del self.__query_response

    return locals()
  #end definition query_response property

  def code():
    def fget(self):
      return self.__code

    def fset(self, v):
      self.__code = (v - (self.query_response << 7)) >> 3

    def fdel(self):
      del self.__code

    return locals()
  #end definition code property

  def auth_answer():
    def fget(self):
      return self.__auth_answer

    def fset(self, v):
      self.__auth_answer = 1 if v & 0b100 else 0

    def fdel(self):
      del self.__auth_answer

    return locals()
  #end definition auth_answer property

  def truncation_flag():
    def fget(self):
      return self.__truncation_flag

    def fset(self, v):
      self.__truncation_flag =  1 if v & 0b10 else 0

    def fdel(self):
      del self.__truncation_flag

    return locals()
  #end definition truncation_flag property

  def recursion_desired():
    def fget(self):
      return self.__recursion_desired

    def fset(self, v):
      self.__recursion_desired =  1 if v & 0b1 else 0

    def fdel(self):
      del self.__recursion_desired

    return locals()
  #end definition recursion_desired property

  def recursion_available():
    def fget(self):
      return self.__recursion_available

    def fset(self, v):
      self.__recursion_available = 1 if v & 0b10000000 else 0

    def fdel(self):
      del self.__recursion_available

    return locals()
  #end definition recursion_available property

  def zero():
    def fget(self):
      return self.__zero

    def fset(self, v):
      self.__zero = (v - (self.recursion_available << 7)) >> 4

    def fdel(self):
      del self.__zero

    return locals()
  #end definition zero property

  def rcode():
    def fget(self):
      return self.__rcode

    def fset(self, v):
      self.__rcode = v & 0xf

    def fdel(self):
      del self.__rcode

    return locals()
  #end definition rcode property

  def qdcount():
    def fget(self):
      return self.__qdcount

    def fset(self, v):
      self.__qdcount = v

    def fdel(self):
      del self.__qdcount

    return locals()
  #end definition qdcount property

  def ancount():
    def fget(self):
      return self.__ancount

    def fset(self, v):
      self.__ancount = v

    def fdel(self):
      del self.__ancount

    return locals()
  #end definition ancount property

  def nscount():
    def fget(self):
      return self.__nscount

    def fset(self, v):
      self.__nscount = v

    def fdel(self):
      del self.__nscount

    return locals()
  #end definition nscount property

  def arcount():
    def fget(self):
      return self.__arcount

    def fset(self, v):
      self.__arcount = v

    def fdel(self):
      del self.__arcount

    return locals()
  #end definition arcount property

  identifier          = property(**identifier())
  query_response      = property(**query_response())
  code                = property(**code())
  auth_answer         = property(**auth_answer())
  truncation_flag     = property(**truncation_flag())
  recursion_desired   = property(**recursion_desired())
  recursion_available = property(**recursion_available())
  zero                = property(**zero())
  rcode               = property(**rcode())
  qdcount             = property(**qdcount())
  ancount             = property(**ancount())
  nscount             = property(**nscount())
  arcount             = property(**arcount())
  format              = property(**format())
#class dns
