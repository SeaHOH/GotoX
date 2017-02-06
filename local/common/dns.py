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
from json.decoder import JSONDecoder
from . import LRUCache, isip, isipv4, isipv6, classlist
from local.compat import Queue, thread
from local.GlobalConfig import GC

jsondecoder = JSONDecoder()
dns = LRUCache(GC.DNS_CACHE_ENTRIES, GC.DNS_CACHE_EXPIRATION)

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
        if host.endswith('.appspot.com'):
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
            dns.set(host, 0, 300)
    return iplist

dnshostalias = 'dns.over.https'
dns_resolve_cache_key = GC.DNS_OVER_HTTPS_LIST + ':443'

from local.HTTPUtil import ssl_connection_cache, http_gws

def address_string(item):
   return item.xip[0] if hasattr(item, 'xip') else ''

class dns_params():
    ssl = True
    host = 'dns.google.com'
    port = 443
    command = 'GET'
    headers = {'Host': host, 'User-Agent': 'GotoX Agent'}
    DNSServerPath = '/resolve?name=%s&type=%s&random_padding=%s'
    Url = 'https://%s/resolve?name=%%s&type=%%s' % host
    host = dnshostalias

    __slots__ = 'path', 'url'

    def __init__(self, qname, qtype):
        # 512 - 20(IP) - 20(TCP) - (100 + qname + qtype)(请求数据)
        npadding = 372 - len(qname) - len(str(qtype))
        self.path = self.DNSServerPath % (qname, qtype, 'x'*npadding)
        self.url = self.Url % (qname, qtype)

def dns_over_https_resolve(qname, qtype, queobj):
    '''
    此函数功能实现仅限于解析为 A、AAAA 记录
    https://developers.google.com/speed/public-dns/docs/dns-over-https
    '''

    def https_resolve(queobj):
        response = None
        noerror = True
        iplist = classlist()
        try:
            response = http_gws.request(params, headers=params.headers, connection_cache_key=dns_resolve_cache_key, timeout=timeout)
            if response and response.status == 200:
                reply = jsondecoder.decode(response.read().decode())
                # NOERROR = 0
                if reply and reply['Status'] == 0:
                    for answer in reply['Answer']:
                        if answer['type'] == qtype:
                            iplist.append(answer['data'])
                iplist.xip = response.xip
        except Exception as e:
            noerror = False
            logging.warning('%s dns_over_https_resolve %r 失败：%r', address_string(response), qname, e)
        finally:
            if response:
                response.close()
                if noerror:
                    if GC.GAE_KEEPALIVE:
                        ssl_connection_cache[dns_resolve_cache_key].append((time(), response.sock))
                    else:
                        response.sock.close()
        queobj.put(iplist)

    threads = max(min((GC.LINK_WINDOW - 1), 3), 1)
    timeout = 1.5

    if dnshostalias not in dns:
        dns.set(dnshostalias, GC.IPLIST_MAP[GC.DNS_OVER_HTTPS_LIST], 24 * 3600)
    
    params = dns_params(qname, qtype)
    queobjt = Queue.Queue()
    for _ in range(threads):
        thread.start_new_thread(https_resolve, (queobjt,))
    for _ in range(threads):
        iplist = queobjt.get()
        if iplist: break
    queobj.put(iplist)

def _dns_over_https(qname):
    A = 1
    AAAA = 28
    n = 0
    xips = []
    iplist = classlist()
    queobj = Queue.Queue()
    if '4' in GC.LINK_PROFILE:
        thread.start_new_thread(dns_over_https_resolve, (qname, A, queobj))
        n += 1
    if '6' in GC.LINK_PROFILE:
        thread.start_new_thread(dns_over_https_resolve, (qname, AAAA, queobj))
        n += 1
    for _ in range(n):
        result = queobj.get()
        if hasattr(result, 'xip'):
            xips.append(result.xip[0])
        iplist += result
    iplist.xip = '｜'.join(xips), None
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
                        reply_data, xip = sock.recvfrom(512)
                        reply = dnslib.DNSRecord.parse(reply_data)
                        iplist = classlist(str(x.rdata) for x in reply.rr if x.rtype == 1)
                        if any(x in blacklist for x in iplist):
                            logging.warning('query qname=%r reply bad iplist=%r', qname, iplist)
                        else:
                            logging.debug('query qname=%r reply iplist=%s', qname, iplist)
                            iplist.xip = xip
                            return iplist
            except socket.error as e:
                logging.warning('handle dns query=%s socket: %r', query, e)
    finally:
        for sock in socks:
            sock.close()

def dns_system_resolve(host):
    now = time()
    try:
        iplist = list(set(socket.gethostbyname_ex(host)[-1]) - GC.DNS_BLACKLIST)
    except Exception:
        iplist = None
    cost = int((time() - now) * 1000)
    logging.test('dns_system_resolve 已缓存：%s/%s，耗时：%s 毫秒，%s = %s',
                 len(dns), dns.max_items, cost, host, iplist or '查询失败')
    return iplist

def dns_remote_resolve(host):
    now = time()
    iplist = _dns_remote_resolve(host, GC.DNS_SERVERS, GC.DNS_BLACKLIST, timeout=2)
    cost = int((time() - now) * 1000)
    logging.test('%s dns_remote_resolve 已缓存：%s/%s，耗时：%s 毫秒，%s = %s',
                 address_string(iplist), len(dns), dns.max_items, cost, host, iplist or '查询失败')
    return iplist

def dns_over_https(host):
    now = time()
    iplist = _dns_over_https(host) if GC.DNS_OVER_HTTPS else ('', None)
    cost = int((time() - now) * 1000)
    logging.test('%s dns_over_https 已缓存：%s/%s，耗时：%s 毫秒，%s = %s',
                 address_string(iplist), len(dns), dns.max_items, cost, host, iplist or '查询失败')
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
