# coding:utf-8

import socket
import dnslib
import logging
from select import select
from time import time, sleep
from json.decoder import JSONDecoder
from . import LRUCache, isip, isipv4, isipv6, get_wan_ipv4, classlist, spawn_loop
from local.compat import Queue, thread
from local.GlobalConfig import GC

def reset_dns():
    dns.clear()
    #保持链接 GAE 列表不过期
    dns.set('google_gws', GC.IPLIST_MAP['google_gws'], noexpire=True)
    dns.set('google_com', GC.IPLIST_MAP['google_com'], noexpire=True)
    dns.set(dnshostalias, GC.IPLIST_MAP[GC.DNS_OVER_HTTPS_LIST], noexpire=True)

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
    namea = str(id(iporname)) if isinstance(iporname, list) else iporname
    if namea.startswith(('google_', 'cdn_')):
        #host = get_main_domain(host)
        host = ''
    if '.google' in host:
        namea = 'google_' + namea
    hostname = '%s|%s' % (namea, host)
    if hostname in dns:
        return hostname
    if isinstance(iporname, str):
        if iporname in GC.IPLIST_MAP:
            dns[hostname] = GC.IPLIST_MAP[iporname]
        else:
            raise KeyError('set_dns 第二参数错误：' + iporname)
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
jsondecoder = JSONDecoder()
dns = LRUCache(GC.DNS_CACHE_ENTRIES, GC.DNS_CACHE_EXPIRATION)
reset_dns()

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
    DNSServerPath = '/resolve?name=%s&type=%s'
    _DNSServerPath =  DNSServerPath + '&ecs='
    if GC.DNS_OVER_HTTPS_ECS and GC.DNS_OVER_HTTPS_ECS != 'auto':
        DNSServerPath = _DNSServerPath + GC.DNS_OVER_HTTPS_ECS.replace('/', '%%2F')
    Url = 'https://' +  host

    __slots__ = 'path', 'url'

    def __init__(self, *qargs):
        self.path = self.DNSServerPath % qargs
        self.url = self.Url + self.path

def update_dns_params():
    if GC.DNS_OVER_HTTPS_ECS == 'auto':
        ip = get_wan_ipv4()
        if ip:
            dns_params.DNSServerPath = dns_params._DNSServerPath + ip

if GC.DNS_OVER_HTTPS_ECS == 'auto':
    spawn_loop(3600, update_dns_params)

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
            if reply and reply['Status'] == 0 and 'Answer' in reply:
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

def _dns_remote_resolve(qname, dnsservers, blacklist=[], timeout=2, qtypes=qtypes):
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
    iplist = classlist()
    _iplist = []
    xips = []
    v4_resolved = not A in qtypes
    v6_resolved = not AAAA in qtypes
    query_times = 0
    try:
        for dnsserver in dns_v4_servers:
            for query_data in query_datas:
                sock_v4.sendto(query_data, (dnsserver, 53))
                query_times += 1
        for dnsserver in dns_v6_servers:
            for query_data in query_datas:
                sock_v6.sendto(query_data, (dnsserver, 53))
                query_times += 1
    except socket.error as e:
        logging.warning('send dns query=%s socket: %r', query, e)
    while time() < timeout_at and not (v4_resolved and v6_resolved) and query_times:
        try:
            ins, _, _ = select(socks, [], [], 0.1)
            for sock in ins:
                reply_data, xip = sock.recvfrom(512)
                query_times -= 1
                reply = dnslib.DNSRecord.parse(reply_data)
                #只处理 qtypes 包含 A、AAAA 的情况
                _v4_resolved = v4_resolved
                _v6_resolved = v6_resolved
                _iplist.clear()
                for r in reply.rr:
                    if r.rtype in qtypes:
                        ip = None
                        if r.rtype == A and not v4_resolved:
                            _v4_resolved = True
                            ip = str(r.rdata)
                        elif r.rtype == AAAA and not v6_resolved:
                            _v6_resolved = True
                            ip = str(r.rdata)
                        if ip:
                            if ip in blacklist:
                                query_times += 1
                                _iplist.clear()
                                logging.warning('query qname=%r reply bad ip=%r', qname, ip)
                                break
                            _iplist.append(ip)
                if _iplist:
                    v4_resolved = _v4_resolved
                    v6_resolved = _v6_resolved
                    iplist.extend(_iplist)
                if xip[0] not in xips:
                    xips.append(xip[0])
        except socket.error as e:
            logging.warning('receive dns query=%s socket: %r', query, e)
    for sock in socks:
        sock.close()
    logging.debug('query qname=%r reply iplist=%s', qname, iplist)
    if xips:
        iplist.xip = '｜'.join(xips), None
    return iplist

def get_dnsserver_list():
    import os
    if os.name == 'nt':
        import winreg
        NameServers = []
        INTERFACES_PATH = 'SYSTEM\\CurrentControlSet\\Services\\Tcpip%s\\Parameters\\Interfaces\\'
        for v in ('', '6'):
            interfaces_path = INTERFACES_PATH % v
            interfaces = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, interfaces_path)
            sub_key_num, _, _ = winreg.QueryInfoKey(interfaces)
            for i in range(sub_key_num):
                try:
                    interface_path = interfaces_path + winreg.EnumKey(interfaces, i)
                    interface = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, interface_path)
                    NameServer, _ = winreg.QueryValueEx(interface, 'NameServer')
                    winreg.CloseKey(interface)
                    if NameServer:
                        NameServers += NameServer.split(',')
                except:
                    pass
            winreg.CloseKey(interfaces)
        return NameServers
    elif os.path.isfile('/etc/resolv.conf'):
        import re
        with open('/etc/resolv.conf', 'r') as fp:
            return re.findall(r'(?m)^nameserver\s+(\S+)', fp.read())
    else:
        import sys
        logging.warning('get_dnsserver_list 失败：不支持 "%s-%s" 平台', sys.platform, os.name)
        return []

local_dnsservers = set(ip for ip in get_dnsserver_list() if isip(ip))
if '127.0.0.1' in local_dnsservers and '::1' in local_dnsservers:
    #视为同一个本地服务器，大多数情况下这是正确地
    local_dnsservers.remove('::1')
local_dnsservers = list(local_dnsservers)
if local_dnsservers:
    logging.test('已读取系统当前 DNS 设置：%r', local_dnsservers)
else:
    logging.warning('读取系统当前 DNS 设置失败')

def dns_system_resolve(host):
    now = time()
    try:
        if '6' in GC.LINK_PROFILE:
            if local_dnsservers:
                iplist = _dns_remote_resolve(host, local_dnsservers, timeout=4)
            else:
                # getaddrinfo 作为后备，Windows 下无法并发，其它系统未知
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
    'system'   : dns_system_resolve,
    'remote'   : dns_remote_resolve,
    'overhttps': dns_over_https_resolve
    }
dns_resolves = tuple(_DNSLv[lv] for lv in GC.DNS_PRIORITY)
