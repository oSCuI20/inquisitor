# Inquisitor

ARP Poison and packet analyzer

It has two forms of use, if not indicated -dst and -target only captures network packets.

To display the information of the captured packets, the -verbose option must be used.

It automatically selects the first network interface that is up, if you want to select one you must use the -iface option

The packet analyzer has two levels of filters, the one applied to the libpcap library using pcap_compile and pcap_setfilter and another level in the application layer. This last filter is not very functional as it is only made for exercise.

By default it sets the filters to capture the ftp protocol information

```
  python3 inquisitor.py -iface <eth0> -dst <ip>;<macaddr> -target <ip>;<macaddr> -filter "port 21 or port 20"

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
    -<protocol>-filter
    -limit       default -1, set limit packet capture
    -verbose     show full result
```

Example:

```
# python3 inquisitor.py -iface enx3ce1a14a5ef7 -verbose

-- device   enx3ce1a14a5ef7 
-- ip addr  1.1.1.1  
-- netmask  255.255.255.0 
-- hwaddr   ff:ff:ff:ff:ff:ff 
-- filter   tcp port 21 or tcp port 20 

---- application layer ftp  -filter USER, PASS, STOR, 150, MKD, 257, CWD, DELE, LIST, RETR
-- Start capture data
-- 1660349701.815920 ipv4 TCP ttl: 64 src 1.1.1.1:52956 -> dst 2.2.2.2:21 [uaprSf] seq: 3922073206 wsize: 64240 checksum: 17452
-- 1660349701.927141 ipv4 TCP ttl: 45 src 2.2.2.2:21 -> dst 1.1.1.1:52956 [uAprSf] seq: 3211177591 wsize: 28960 checksum: 7389
-- 1660349702.032776 ipv4 TCP ttl: 64 src 1.1.1.1:52956 -> dst 2.2.2.2:21 [uAprsf] seq: 3922073207 wsize: 502 checksum: 17444
-- 1660349702.276925 ipv4 TCP ttl: 45 src 2.2.2.2:21 -> dst 1.1.1.1:52956 220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------
220-You are user number 1 of 10 allowed.
220-Local time is now 01:15. Server port: 21.
220-This is a private system - No anonymous login
220 You will be disconnected after 15 minutes of inactivity.
-- 1660349702.382533 ipv4 TCP ttl: 64 src 1.1.1.1:52956 -> dst 2.2.2.2:21 [uAprsf] seq: 3922073207 wsize: 501 checksum: 17444
-- 1660349702.493685 ipv4 TCP ttl: 64 src 1.1.1.1:52956 -> dst 2.2.2.2:21 USER anonymous
-- 1660349702.599259 ipv4 TCP ttl: 45 src 2.2.2.2:21 -> dst 1.1.1.1:52956 [uAprsf] seq: 3211177857 wsize: 227 checksum: 47675
-- 1660349702.710614 ipv4 TCP ttl: 45 src 2.2.2.2:21 -> dst 1.1.1.1:52956 331 User anonymous OK. Password required
-- 1660349702.816155 ipv4 TCP ttl: 64 src 1.1.1.1:52956 -> dst 2.2.2.2:21 [uAprsf] seq: 3922073223 wsize: 501 checksum: 17444
-- 1660349702.921812 ipv4 TCP ttl: 64 src 1.1.1.1:52956 -> dst 2.2.2.2:21 PASS ftp@example.com
-- 1660349703.027631 ipv4 TCP ttl: 45 src 2.2.2.2:21 -> dst 1.1.1.1:52956 [uAprsf] seq: 3211177899 wsize: 227 checksum: 47500
-- 1660349704.788370 ipv4 TCP ttl: 45 src 2.2.2.2:21 -> dst 1.1.1.1:52956 530 Login authentication failed
-- 1660349704.894131 ipv4 TCP ttl: 64 src 1.1.1.1:52956 -> dst 2.2.2.2:21 [uAprsf] seq: 3922073245 wsize: 501 checksum: 17444
-- 1660349704.999758 ipv4 TCP ttl: 64 src 1.1.1.1:52956 -> dst 2.2.2.2:21 [uAprsF] seq: 3922073245 wsize: 501 checksum: 17444
-- 1660349705.105479 ipv4 TCP ttl: 45 src 2.2.2.2:21 -> dst 1.1.1.1:52956 530 Logout.
-- 1660349705.211081 ipv4 TCP ttl: 64 src 1.1.1.1:52956 -> dst 2.2.2.2:21 [uapRsf] seq: 3922073246 wsize: 0 checksum: 40076
-- 1660349705.316999 ipv4 TCP ttl: 45 src 2.2.2.2:21 -> dst 1.1.1.1:52956 [uAprsF] seq: 3211177945 wsize: 227 checksum: 41145
-- 1660349705.422798 ipv4 TCP ttl: 64 src 1.1.1.1:52956 -> dst 2.2.2.2:21 [uapRsf] seq: 3922073246 wsize: 0 checksum: 40076
```

Using custom filter
```
# python3 inquisitor.py -iface enx3ce1a14a5ef7 -verbose -filter udp port 53

[ ... ]
-- Start capture data
-- 1660350318.206041 ipv4 UDP ttl: 64 src 1.1.1.1:47375 -> dst 3.3.3.3:53 DNS: 0x6344 Query domain-example.com
-- 1660350318.317368 ipv4 UDP ttl: 64 src 3.3.3.3:53 -> dst 1.1.1.1:47375 DNS: 0x6344 Response domain-example.com type A
-- 1660350321.689338 ipv4 UDP ttl: 64 src 1.1.1.1:46944 -> dst 3.3.3.3:53 DNS: 0x79aa Query other-domain.com
-- 1660350321.795128 ipv4 UDP ttl: 64 src 3.3.3.3:53 -> dst 1.1.1.1:46944 DNS: 0x79aa Response other-domain.com type CNAME
```
