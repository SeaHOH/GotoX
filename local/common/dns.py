# coding:utf-8

import queue
import socket
import dnslib
import logging
from select import select
from time import time, sleep
from threading import _start_new_thread as start_new_thread
from json.decoder import JSONDecoder
from .net import isip, isipv4, isipv6, get_wan_ipv4
from .util import LRUCache, spawn_loop
from local.GlobalConfig import GC

A = dnslib.QTYPE.A
AAAA = dnslib.QTYPE.AAAA
OPT = dnslib.QTYPE.OPT
qtypes = []
if '4' in GC.LINK_PROFILE:
    qtypes.append(A)
if '6' in GC.LINK_PROFILE:
    qtypes.append(AAAA)

def reset_dns():
    dns.clear()
    #保持链接 GAE 列表不过期
    dns.set('google_gae|', GC.IPLIST_MAP['google_gae'], expire=False)
    dns.set('google_gws|', GC.IPLIST_MAP['google_gws'], expire=False)
    dns.set(dnshostalias, GC.IPLIST_MAP[GC.DNS_OVER_HTTPS_LIST], expire=False)

def set_dns(host, iporname):
    #先处理正常解析
    if iporname is None:
        if dns_resolve(host):
            return host
        else:
            return
    #尝试解析可能的域名
    if isinstance(iporname, str) and iporname.find('.') > 0 and not iporname.startswith('cdn_'):
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

def _dns_resolve(host, qtypes=qtypes, local=GC.DNS_LOCAL_HOST):
    if local and islocal(host):
        return dns_local_resolve(host, qtypes)
    for _resolve in dns_resolves:
        iplist = _resolve(host, qtypes)
        if iplist: break
    return iplist

def dns_resolve(host, qtypes=qtypes):
    if isip(host):
        dns[host] = iplist = [host]
        return iplist
    iplist = dns.gettill(host)
    if not iplist and iplist != 0:
        dns.setpadding(host)
        iplist = _dns_resolve(host, qtypes)
        if iplist:
            dns[host] = iplist = list(set(iplist))
        else:
            dns.set(host, 0, 300)
    return iplist

dnshostalias = 'dns.over.https'
https_resolve_cache_key = GC.DNS_OVER_HTTPS_LIST + ':443'
jsondecoder = JSONDecoder()
dns = LRUCache(GC.DNS_CACHE_ENTRIES, GC.DNS_CACHE_EXPIRATION)
reset_dns()

from .region import islocal
from local.HTTPUtil import http_gws

def _address_string(xip):
    xip0, xip1 = xip[:2]
    if isipv6(xip):
        xip0 = '[%s]' % xip0
    if xip1 in (53, 443):
        return xip0
    else:
        return '%s:%s' % (xip0, xip1)

def address_string(item):
    if not hasattr(item, 'xip'):
        return ''
    xips = item.xip
    if isinstance(xips, list):
        return '｜'.join(_address_string(xip) for xip in xips) + ' '
    else:
        return _address_string(xips) + ' '

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
    iplist = list()
    for _ in range(2):
        response = None
        noerror = True
        xip = None
        try:
            response = http_gws.request(params, headers=params.headers, connection_cache_key=https_resolve_cache_key, getfast=timeout)
            if response and response.status == 200:
                reply = jsondecoder.decode(response.read().decode())
                # NOERROR = 0
                if reply and reply['Status'] == 0 and 'Answer' in reply:
                    for answer in reply['Answer']:
                        if answer['type'] == qtype:
                            iplist.append(answer['data'])
        except Exception as e:
            noerror = False
            logging.warning('%s _https_resolve %r 失败：%r', address_string(response), qname, e)
        finally:
            if response:
                response.close()
                xip = response.xip
                if noerror:
                    if GC.GAE_KEEPALIVE:
                        http_gws.ssl_connection_cache[https_resolve_cache_key].append((time(), response.sock))
                    else:
                        response.sock.close()
                    break
    queobj.put((iplist, xip))

def _dns_over_https_resolve(qname, qtypes=qtypes):
    iplist = classlist()
    xips = []
    queobj = queue.Queue()
    for qtype in qtypes:
        start_new_thread(_https_resolve, (qname, qtype, queobj))
    for qtype in qtypes:
        _iplist, xip = queobj.get()
        iplist += _iplist
        if xip and xip not in xips:
            xips.append(xip)
    if xips:
        iplist.xip = xips
    return iplist

remote_query_opt = dnslib.EDNS0(flags='do', udp_len=1024)

def _dns_remote_resolve(qname, dnsservers, blacklist=[], timeout=2, qtypes=qtypes):
    '''
    https://gfwrev.blogspot.com/2009/11/gfwdns.html
    https://zh.wikipedia.org/wiki/域名服务器缓存污染
    http://support.microsoft.com/kb/241352 (已删除)
    '''
    query_datas = []
    #ids = []
    for qtype in qtypes:
        query = dnslib.DNSRecord(q=dnslib.DNSQuestion(qname, qtype))
        query.add_ar(remote_query_opt)
        query_datas.append(query.pack())
        #ids.append(query.header.id)
    dns_v4_servers = [x for x in dnsservers if isipv4(x[0])]
    dns_v6_servers = [x for x in dnsservers if isipv6(x[0])]
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
                sock_v4.sendto(query_data, dnsserver)
                query_times += 1
        for dnsserver in dns_v6_servers:
            for query_data in query_datas:
                sock_v6.sendto(query_data, dnsserver)
                query_times += 1
    except socket.error as e:
        logging.warning('send dns query=\n%s \nsocket: %r', query, e)
    while time() < timeout_at and not (v4_resolved and v6_resolved) and query_times:
        try:
            ins, _, _ = select(socks, [], [], 0.1)
            for sock in ins:
                reply_data, xip = sock.recvfrom(remote_query_opt.edns_len)
                query_times -= 1
                reply = dnslib.DNSRecord.parse(reply_data)
                qtype = reply.q.qtype
                #id = reply.header.id
                #edns_len = 0
                #for ar in reply.ar:
                #    if ar.rtype == OPT:
                #        edns_len = ar.edns_len
                #        break
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
                            #简单处理污染，还是 DoH 简单好用，不想写得更复杂
                            if (r.rtype != qtype or  # type 不符
                                    #id not in ids or # id 不符 （现在也不用查 id）
                                    #not reply.ar or  # 缺少 OPT PSEUDOSECTION （阿里垃圾）
                                    #接收大小不等 （114 垃圾）
                                    #edns_len != remote_query_opt.edns_len or
                                    ip in blacklist): # 旧列表 + 检测后添加
                                GC.DNS_BLACKLIST.add(ip)
                                query_times += 1
                                _iplist.clear()
                                logging.warning('query qname=%r reply bad ip=%r', qname, ip)
                                break
                            _iplist.append(ip)
                if _iplist:
                    v4_resolved = _v4_resolved
                    v6_resolved = _v6_resolved
                    iplist.extend(_iplist)
                if xip not in xips:
                    xips.append(xip)
        except socket.error as e:
            logging.warning('receive dns query=\n%s \nsocket: %r', query, e)
    for sock in socks:
        sock.close()
    logging.debug('query qname=%r reply iplist=%s', qname, iplist)
    if xips:
        iplist.xip = xips
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
local_dnsservers = tuple((server, 53) for server in local_dnsservers)
if local_dnsservers:
    logging.test('已读取系统当前 DNS 设置：%r', local_dnsservers)
else:
    logging.warning('读取系统当前 DNS 设置失败')

def dns_system_resolve(host, qtypes=qtypes):
    start = time()
    try:
        if local_dnsservers:
            iplist = _dns_remote_resolve(host, local_dnsservers, timeout=2, qtypes=qtypes)
        # getaddrinfo 在 Windows 下无法并发，其它系统未知
        elif AAAA not in qtypes:
            iplist = list(set(socket.gethostbyname_ex(host)[-1]) - GC.DNS_BLACKLIST)
        elif A in qtypes:
            iplist = list(set(ipaddr[4][0] for ipaddr in socket.getaddrinfo(host, None)) - GC.DNS_BLACKLIST)
        else:
            iplist = list(set(ipaddr[4][0] for ipaddr in socket.getaddrinfo(host, None, socket.AF_INET6)) - GC.DNS_BLACKLIST)
    except:
        iplist = None
    cost = int((time() - start) * 1000)
    logging.test('%sdns_system_resolve 已缓存：%s/%s，耗时：%s 毫秒，%s = %s',
                 address_string(iplist), len(dns), dns.max_items, cost, host, iplist or '查询失败')
    return iplist

def dns_remote_resolve(host, qtypes=qtypes):
    start = time()
    iplist = _dns_remote_resolve(host, GC.DNS_SERVERS, GC.DNS_BLACKLIST, timeout=2, qtypes=qtypes)
    cost = int((time() - start) * 1000)
    logging.test('%sdns_remote_resolve 已缓存：%s/%s，耗时：%s 毫秒，%s = %s',
                 address_string(iplist), len(dns), dns.max_items, cost, host, iplist or '查询失败')
    return iplist

def dns_local_resolve(host, qtypes=qtypes):
    start = time()
    iplist = _dns_remote_resolve(host, GC.DNS_LOCAL_SERVERS, timeout=2, qtypes=qtypes)
    cost = int((time() - start) * 1000)
    logging.test('%sdns_local_resolve 已缓存：%s/%s，耗时：%s 毫秒，%s = %s',
                 address_string(iplist), len(dns), dns.max_items, cost, host, iplist or '查询失败')
    return iplist

def dns_over_https_resolve(host, qtypes=qtypes):
    if not GC.DNS_OVER_HTTPS:
        return
    start = time()
    iplist = _dns_over_https_resolve(host, qtypes=qtypes) 
    cost = int((time() - start) * 1000)
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
