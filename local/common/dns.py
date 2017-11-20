# coding:utf-8

try:
    import dnslib
except ImportError:
    import sys
    from . import logging, packages
    logging.error(u'无法找到 dnslib，请安装 dnslib-0.8.3 以上版本，或将相应 .egg 放到 %r 文件夹！', packages)
    sys.exit(-1)

import socket
import threading
from select import select
from time import time, sleep
from json.decoder import JSONDecoder
from . import logging, LRUCache, isip, isipv4, isipv6, classlist
from local.compat import Queue, thread
from local.GlobalConfig import GC

jsondecoder = JSONDecoder()
dns = LRUCache(GC.DNS_CACHE_ENTRIES, GC.DNS_CACHE_EXPIRATION)
alock = threading.Lock()

def reset_dns():
    dns.clear()
    #保持链接 GAE 列表不过期
    dns.set('google_gws', GC.IPLIST_MAP['google_gws'], noexpire=True)
    dns.set('google_com', GC.IPLIST_MAP['google_com'], noexpire=True)

reset_dns()

def set_dns(host, iporname):
    #先处理正常解析
    if iporname is None:
        if dns_resolve(host):
            return host
        else:
            return
    #尝试解析可能的域名
    if isinstance(iporname, str) and iporname.find('.') > 0:
        _host = iporname.lower()
        if dns_resolve(_host):
            return _host
    #生成唯一别名
    namea = id(iporname) if isinstance(iporname, list) else iporname
    hostname = '%s|%s' % (namea, host)
    with alock:
        if hostname in dns:
            return hostname
        if isinstance(iporname, str):
            #建立规则时已经剔除了不合格字串
            if isip(iporname):
                dns[hostname] = iporname,
            elif iporname in GC.IPLIST_MAP:
                dns[hostname] = GC.IPLIST_MAP[iporname]
        elif isinstance(iporname, list):
            dns[hostname] = iporname
        else:
            raise TypeError('set_dns 第二参数类型错误：' + type(iporname))
        return hostname

def _dns_resolve(host):
    for _resolve in dns_resolves:
        iplist = _resolve(host)
        if iplist: break
    return iplist

def dns_resolve(host):
    if isip(host):
        dns[host] = iplist = [host]
        return iplist
    try:
        iplist = dns[host]
        #避免 DNS 响应较慢时重复设置 IP
        while not iplist and iplist != 0:
            sleep(0.01)
            iplist = dns[host]
    except KeyError:
        dns[host] = None
        iplist = _dns_resolve(host)
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
https_resolve_cache_key = GC.DNS_OVER_HTTPS_LIST + ':443'
https_resolve_threads = max(min((GC.LINK_WINDOW - 1), 3), 1)

from local.HTTPUtil import http_gws

def address_string(item):
   return item.xip[0] + ' ' if hasattr(item, 'xip') else ''

class dns_params:
    ssl = True
    host = 'dns.google.com'
    hostname = dnshostalias
    port = 443
    command = 'GET'
    headers = {'Host': host, 'User-Agent': 'GotoX Agent'}
    DNSServerPath = '/resolve?name=%s&type=%s&random_padding=%s'
    Url = 'https://%s/resolve?name=%%s&type=%%s' % host

    __slots__ = 'path', 'url'

    def __init__(self, qname, qtype):
        # 512 - 20(IP) - 20(TCP) - (100 + qname + qtype)(请求数据)
        npadding = 372 - len(qname) - len(str(qtype))
        self.path = self.DNSServerPath % (qname, qtype, 'x'*npadding)
        self.url = self.Url % (qname, qtype)

def _https_resolve(qname, qtype, queobj):
    '''
    此函数功能实现仅限于解析为 A、AAAA 记录
    https://developers.google.com/speed/public-dns/docs/dns-over-https
    '''

    timeout = 1.5
    params = dns_params(qname, qtype)
    response = None
    noerror = True
    iplist = classlist()
    try:
        response = http_gws.request(params, headers=params.headers, connection_cache_key=https_resolve_cache_key, getfast=timeout)
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
                    http_gws.ssl_connection_cache[https_resolve_cache_key].append((time(), response.sock))
                else:
                    response.sock.close()
    queobj.put(iplist)

def https_resolve(qname, qtype, queobj):
    if dnshostalias not in dns:
        dns.set(dnshostalias, GC.IPLIST_MAP[GC.DNS_OVER_HTTPS_LIST], 24 * 3600)

    queobjt = Queue.Queue()
    for _ in range(https_resolve_threads):
        thread.start_new_thread(_https_resolve, (qname, qtype, queobjt))
    for _ in range(https_resolve_threads):
        iplist = queobjt.get()
        if iplist: break
    queobj.put(iplist)

A = dnslib.QTYPE.A
AAAA = dnslib.QTYPE.AAAA

def _dns_over_https_resolve(qname):
    n = 0
    xips = []
    iplist = classlist()
    queobj = Queue.Queue()
    if '4' in GC.LINK_PROFILE:
        thread.start_new_thread(https_resolve, (qname, A, queobj))
        n += 1
    if '6' in GC.LINK_PROFILE:
        thread.start_new_thread(https_resolve, (qname, AAAA, queobj))
        n += 1
    for _ in range(n):
        result = queobj.get()
        if hasattr(result, 'xip'):
            xips.append(result.xip[0])
        iplist += result
    if xips:
        iplist.xip = '｜'.join(xips), None
    return iplist

qtypes = []
if '4' in GC.LINK_PROFILE:
    qtypes.append(A)
if '6' in GC.LINK_PROFILE:
    qtypes.append(AAAA)

def _dns_remote_resolve(qname, dnsservers, blacklist, timeout, qtypes=qtypes):
    '''
    http://gfwrev.blogspot.com/2009/11/gfwdns.html
    http://zh.wikipedia.org/wiki/域名服务器缓存污染
    http://support.microsoft.com/kb/241352
    '''
    query_datas = []
    for qtype in qtypes:
        query = dnslib.DNSRecord(q=dnslib.DNSQuestion(qname, qtype))
        query_datas.append(query.pack())
    dns_v4_servers = [x for x in dnsservers if isipv4(x)]
    dns_v6_servers = [x for x in dnsservers if isipv6(x)]
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
                    for query_data in query_datas:
                        sock_v4.sendto(query_data, (dnsserver, 53))
                for dnsserver in dns_v6_servers:
                    for query_data in query_datas:
                        sock_v6.sendto(query_data, (dnsserver, 53))
                while time() < timeout_at:
                    ins, _, _ = select(socks, [], [], 0.1)
                    for sock in ins:
                        reply_data, xip = sock.recvfrom(512)
                        reply = dnslib.DNSRecord.parse(reply_data)
                        #未处理 qtypes 包含 ANY 的情况
                        iplist = classlist(str(x.rdata) for x in reply.rr if x.rtype in qtypes)
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
        if '6' in GC.LINK_PROFILE:
            iplist = list(set(ipaddr[4][0] for ipaddr in socket.getaddrinfo(host, None)) - GC.DNS_BLACKLIST)
        else:
            iplist = list(set(socket.gethostbyname_ex(host)[-1]) - GC.DNS_BLACKLIST)
    except:
        iplist = None
    cost = int((time() - now) * 1000)
    logging.test('dns_system_resolve 已缓存：%s/%s，耗时：%s 毫秒，%s = %s',
                 len(dns), dns.max_items, cost, host, iplist or '查询失败')
    return iplist

def dns_remote_resolve(host):
    now = time()
    iplist = _dns_remote_resolve(host, GC.DNS_SERVERS, GC.DNS_BLACKLIST, timeout=2)
    cost = int((time() - now) * 1000)
    logging.test('%sdns_remote_resolve 已缓存：%s/%s，耗时：%s 毫秒，%s = %s',
                 address_string(iplist), len(dns), dns.max_items, cost, host, iplist or '查询失败')
    return iplist

def dns_over_https_resolve(host):
    if not GC.DNS_OVER_HTTPS:
        return
    now = time()
    iplist = _dns_over_https_resolve(host) 
    cost = int((time() - now) * 1000)
    logging.test('%sdns_over_https 已缓存：%s/%s，耗时：%s 毫秒，%s = %s',
                 address_string(iplist), len(dns), dns.max_items, cost, host, iplist or '查询失败')
    return iplist

#设置使用 DNS 的优先级别
_DNSLv = {
    'system'    : dns_system_resolve,
    'remote'    : dns_remote_resolve,
    'overhttps' : dns_over_https_resolve
    }
dns_resolves = tuple(_DNSLv[lv] for lv in GC.DNS_PRIORITY)
