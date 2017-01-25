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
from time import time, sleep
from json import _default_decoder as jsondecoder
from . import LRUCache, isip, isipv4, isipv6
from local.compat import Queue, thread
from local.GlobalConfig import GC

dns = LRUCache(128, 4*60*60)

def set_DNS(host, iporname):
    iporname = iporname or ()
    if host in dns and dns[host]:
        if isinstance(iporname, str) and iporname in GC.IPLIST_MAP:
            return iporname
        else:
            return host
    if isinstance(iporname, list):
        dns[host] = iporname
    elif iporname in GC.IPLIST_MAP:
        dns[host] = GC.IPLIST_MAP[iporname]
        return host if iporname.startswith('sni') else iporname
    elif isinstance(iporname, str) and isip(iporname):
        dns[host] = iporname,
    else:
        if not dns_resolve(host):
            return
    return host

def dns_resolve(host):
    if isip(host):
        dns[host] = iplist = [host,]
        return iplist
    if host in dns:
        iplist = dns[host]
        #避免 DNS 响应较慢时重复设置 IP
        while not iplist and iplist != 0:
            sleep(0.01)
            iplist = dns[host]
    else:
        dns[host] = None
        iplist = None
        if host.endswith('.appspot.com') or host == 'dns.google.com':
            #已经在查找 IP 时过滤 IP 版本
            dns[host] = iplist = GC.IPLIST_MAP['google_gws']
            return iplist
        iplist = dns_resolve1(host)
        if not iplist:
            iplist = dns_resolve2(host)
        if not iplist:
            iplist = dns_resolve3(host)
        if iplist:
            if GC.LINK_PROFILE == 'ipv4':
                iplist = [ip for ip in iplist if isipv4(ip)]
            elif GC.LINK_PROFILE == 'ipv6':
                iplist = [ip for ip in iplist if isipv6(ip)]
            dns[host] = iplist = list(set(iplist))
        else:
            dns[host] = 0
    return iplist

from local.HTTPUtil import ssl_connection_cache, http_gws

class dns_params():
    ssl = True
    host = 'dns.google.com'
    port = 443
    command = 'GET'
    headers = {'Host': host, 'User-Agent': 'GotoX Agent'}
    DNSServerPath = '/resolve?name=%s&type=%s&random_padding=%s'

    __slots__ = 'path', 'url'

    def __init__(self, qname, qtype):
        npadding = 412 - len(qname) - len(str(qtype))
        self.path = self.DNSServerPath % (qname, qtype, 'x'*npadding)
        self.url = 'https://%s%s' % (self.host, self.path)

def dns_over_https_resolve(qname, qtype, queobj):
    '''
    此函数功能实现仅限于解析为 A 、AAAA 记录
    https://developers.google.com/speed/public-dns/docs/dns-over-https
    '''

    def address_string(response):
        if hasattr(response, 'xip'):
            return response.xip[0]
        else:
            return ''

    CNAME = 5
    NOERROR = 0
    retry = 2
    timeout = 1.5
    iplist = []
    params = dns_params(qname, qtype)
    cache_key = 'google_gws:443'
    for i in range(retry):
        response = None
        noerror = True
        try:
            response = http_gws.request(params, headers=params.headers, connection_cache_key=cache_key, timeout=timeout)
            if response.status == 200:
                reply = jsondecoder.decode(response.read().decode())
                if reply['Status'] == NOERROR:
                    cnames = []
                    for answer in reply['Answer']:
                        response_type = answer['type']
                        data = answer['data']
                        if response_type == qtype:
                            iplist.append(data)
                        elif response_type == CNAME:
                            cnames.append(data[:-1])
                    if cnames:
                        queobjc = Queue.Queue()
                        for cname in cnames:
                            thread.start_new_thread(dns_over_https_resolve, (cname, qtype, queobjc))
                        for cname in cnames:
                            iplist += queobjc.get()
                    if not iplist:
                        logging.warning('%s dns_over_https_resolve %r 失败：未登记域名', address_string(response), qname)
                else:
                    #重试
                    continue
                break
        except Exception as e:
            noerror = False
            logging.warning('%s dns_over_https_resolve %r 失败：%r', address_string(response), qname, e)
        finally:
            if response:
                response.close()
                if noerror:
                    #放入套接字缓存
                    if GC.GAE_KEEPALIVE:
                        ssl_connection_cache[cache_key].append((time(), response.sock))
                    else:
                        #干扰严重时考虑不复用 google 链接
                        response.sock.close()
    queobj.put(iplist)

def _dns_over_https(qname):
    A = 1
    AAAA = 28
    n = 0
    iplist = []
    queobj = Queue.Queue()
    if '4' in GC.LINK_PROFILE:
        thread.start_new_thread(dns_over_https_resolve, (qname, A, queobj))
        n += 1
    if '6' in GC.LINK_PROFILE:
        thread.start_new_thread(dns_over_https_resolve, (qname, AAAA, queobj))
        n += 1
    for i in range(n):
        iplist += queobj.get()
    return iplist

def _dns_remote_resolve(qname, dnsservers, blacklist, timeout):
    '''
    http://gfwrev.blogspot.com/2009/11/gfwdns.html
    http://zh.wikipedia.org/wiki/域名服务器缓存污染
    http://support.microsoft.com/kb/241352
    '''
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
        for _ in range(2):
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

def dns_system_resolve(host):
    try:
        iplist = list(set(socket.gethostbyname_ex(host)[-1]) - GC.DNS_BLACKLIST)
    except Exception:
        iplist = None
    #logging.test('dns_system_resolve %s = %s', host, iplist)
    return iplist

def dns_remote_resolve(host):
    iplist = _dns_remote_resolve(host, GC.DNS_SERVERS, GC.DNS_BLACKLIST, timeout=2)
    #logging.test('dns_system_resolve %s = %s', host, iplist)
    return iplist

def dns_over_https(host):
    iplist = _dns_over_https(host) if GC.DNS_OVER_HTTPS else None
    logging.test('dns_over_https %s = %s', host, iplist)
    return iplist

#设置使用 DNS 的优先级别
if GC.DNS_PRIORITY[0] == 'system':
    dns_resolve1 = dns_system_resolve
elif GC.DNS_PRIORITY[0] == 'remote':
    dns_resolve1 = dns_remote_resolve
else:
    dns_resolve1 = dns_over_https
if GC.DNS_PRIORITY[1] == 'system':
    dns_resolve2 = dns_system_resolve
elif GC.DNS_PRIORITY[1] == 'remote':
    dns_resolve2 = dns_remote_resolve
else:
    dns_resolve2 = dns_over_https
if GC.DNS_PRIORITY[2] == 'system':
    dns_resolve3 = dns_system_resolve
elif GC.DNS_PRIORITY[2] == 'remote':
    dns_resolve3 = dns_remote_resolve
else:
    dns_resolve3 = dns_over_https
