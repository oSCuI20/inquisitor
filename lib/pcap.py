# -*- coding: utf-8 -*-
#
# ./lib/pcap.py
# Eduardo Banderas Alba
# 2022-08
#
# Simple binding libpcap
#
from ctypes import POINTER, CDLL, CFUNCTYPE, Structure, create_string_buffer, byref, \
            c_void_p, c_char, c_char_p, c_int, c_uint, c_uint32, c_long, c_ulong, c_ubyte, \
            c_ushort

__LIBPCAP_SHARED_LIBRARY = '/usr/lib/x86_64-linux-gnu/libpcap.so.1.10.0'
__PCAP_ERRBUF_SIZE = 256

PCAP_ERRORBUF = create_string_buffer(__PCAP_ERRBUF_SIZE)

# map structured  to python
class pcap(Structure):
  pass
#class pcap
pcap_p = POINTER(pcap)

class pcap_dumper(Structure):
  pass
#class pcap_dumper
pcap_dumper_p = pcap_dumper

class bpf_insn(Structure):
  _fields_ = [
    ('code', c_ushort),
    ('jt',   c_ubyte),
    ('jf',   c_ubyte),
    ('k',    c_uint32)
  ]
#class bpf_insn
bpf_insn_p = POINTER(bpf_insn)

class bpf_program(Structure):
  _fields_ = [
    ('bf_len',   c_uint),
    ('bf_insns', bpf_insn_p)
  ]
#class bpf

class pkthdr(Structure):
  _fields_ = [
    ('tv_sec',  c_long),
    ('tv_usec', c_long),
    ('caplen',  c_uint),
    ('len',     c_uint)
  ]
#class pkthdr

class stat(Structure):
  _fields_ = [
    ('ps_recv', c_uint),
    ('ps_drop', c_uint),
    ('ps_ifdrop', c_uint)
  ]
#class stat


bpf_p     = POINTER(bpf_program)
pkthdr_p  = POINTER(POINTER(pkthdr))
stat_p    = POINTER(stat)

LIBPCAP = CDLL(__LIBPCAP_SHARED_LIBRARY)

pcap_create = CFUNCTYPE(pcap_p, c_char_p, c_char_p)(
  ('pcap_create', LIBPCAP), (
    (1, 'source'), (1, 'errbuf'),
))

pcap_open_live = CFUNCTYPE(pcap_p, c_char_p, c_int, c_int, c_int, c_char_p)(
  ('pcap_open_live', LIBPCAP), (
    (1, 'source'), (1, 'snaplen'), (1, 'promisc'), (1, 'timeout'), (1, 'errbuf'),
))

pcap_activate = CFUNCTYPE(c_int, pcap_p)(
  ('pcap_activate', LIBPCAP), (
    (1, 'pcap'),
))

pcap_close = CFUNCTYPE(c_int, pcap_p)(
  ('pcap_close', LIBPCAP), (
    (1, 'pcap'),
))

pcap_can_set_rfmon = CFUNCTYPE(c_void_p, pcap_p)(
  ('pcap_can_set_rfmon', LIBPCAP), (
    (1, 'pcap'),
))

pcap_setnonblock = CFUNCTYPE(c_int, pcap_p, c_int, c_char_p)(
  ('pcap_setnonblock', LIBPCAP), (
    (1, 'pcap'), (1, 'nonblock'), (1, 'errbuf'),
))

pcap_compile = CFUNCTYPE(c_int, pcap_p, bpf_p, c_char_p, c_int, c_uint32)(
  ('pcap_compile', LIBPCAP), (
    (1, 'pcap'), (1, 'prog'), (1, 'buffer'), (1, 'optimize'), (1, 'mask'),
))

pcap_setfilter = CFUNCTYPE(c_int, pcap_p, bpf_p)(
  ('pcap_setfilter', LIBPCAP), (
    (1, 'pcap'), (1, 'prog'),
))

pcap_next = CFUNCTYPE(c_char_p, pcap_p, pkthdr_p)(
  ('pcap_next', LIBPCAP), (
    (1, 'pcap'), (1, 'pktheader'),
))

pcap_next_ex = CFUNCTYPE(c_int, pcap_p, pkthdr_p, POINTER(POINTER(c_ubyte * 65535)))(
  ('pcap_next_ex', LIBPCAP), (
    (1, 'pcap'), (1, 'pktheader'), (1, 'pktdata'),
))

pcap_sendpacket = CFUNCTYPE(c_int, pcap_p, c_char_p, c_int)(
  ('pcap_sendpacket', LIBPCAP), (
    (1, 'pcap'), (1, 'buffer'), (1, 'size'),
))

pcap_stats = CFUNCTYPE(c_int, pcap_p, stat_p)(
  ('pcap_stats', LIBPCAP), (
    (1, 'pcap'), (1, 'stat'),
))

pcap_geterr = CFUNCTYPE(c_char_p, pcap_p)(
  ("pcap_geterr", LIBPCAP), (
    (1, "pcap"),
))
