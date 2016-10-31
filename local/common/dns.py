# coding:utf-8

from local import clogging as logging
try:
    import dnslib
except ImportError:
    import sys
    from . import packages
    logging.error(u'无法找到 dnslib，请安装 dnslib-0.8.3 以上版本，或将相应 .egg 放到 %r 文件夹！', packages)
    sys.exit(-1)

import socket
from select import select
from time import time
from local.compat import xrange, exc_clear
from . import LRUCache, isip, isipv4, isipv6
from local.GlobalConfig import GC

dns = LRUCache(256, 4*60*60)

def dns_resolve(host, dnsservers=[]):
    if isip(host):
        return [host]
    iplist = dns.get(host)
    if not iplist:
        if host.endswith('.appspot.com'):
            dns[host] = iplist = GC.IPLIST_MAP[GC.GAE_LISTNAME]
            return iplist
        if not dnsservers:
            try:
                iplist = list(set(socket.gethostbyname_ex(host)[-1]) - GC.DNS_BLACKLIST)
            except:
                pass
        else:
            iplist = dns_remote_resolve(host, dnsservers, GC.DNS_BLACKLIST, timeout=2)
        if not iplist:
            iplist = dns_remote_resolve(host, GC.DNS_SERVERS, GC.DNS_BLACKLIST, timeout=2)
        if iplist:
            if GC.LINK_PROFILE == 'ipv4':
                iplist = [ip for ip in iplist if isipv4(ip)]
            elif GC.LINK_PROFILE == 'ipv6':
                iplist = [ip for ip in iplist if isipv6(ip)]
            dns[host] = iplist = list(set(iplist))
    return iplist

def dns_remote_resolve(qname, dnsservers, blacklist, timeout):
    """
    http://gfwrev.blogspot.com/2009/11/gfwdns.html
    http://zh.wikipedia.org/wiki/域名服务器缓存污染
    http://support.microsoft.com/kb/241352
    """
    query = dnslib.DNSRecord(q=dnslib.DNSQuestion(qname))
    query_data = query.pack()
    dns_v4_servers = [x for x in dnsservers if isipv4(x)]
    dns_v6_servers = [x for x in dnsservers if isipv6(x)]
    sock_v4 = sock_v6 = None
    socks = []
    if dns_v4_servers:
        sock_v4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socks.append(sock_v4)
    if dns_v6_servers:
        sock_v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        socks.append(sock_v6)
    timeout_at = time() + timeout
    try:
        for _ in xrange(2):
            try:
                for dnsserver in dns_v4_servers:
                    sock_v4.sendto(query_data, (dnsserver, 53))
                for dnsserver in dns_v6_servers:
                    sock_v6.sendto(query_data, (dnsserver, 53))
                while time() < timeout_at:
                    ins, _, _ = select(socks, [], [], 0.1)
                    for sock in ins:
                        reply_data, _ = sock.recvfrom(512)
                        reply = dnslib.DNSRecord.parse(reply_data)
                        iplist = [str(x.rdata) for x in reply.rr if x.rtype == 1]
                        if any(x in blacklist for x in iplist):
                            logging.warning('query qname=%r reply bad iplist=%r', qname, iplist)
                        else:
                            logging.debug('query qname=%r reply iplist=%s', qname, iplist)
                            return iplist
            except socket.error as e:
                logging.warning('handle dns query=%s socket: %r', query, e)
    finally:
        for sock in socks:
            sock.close()

