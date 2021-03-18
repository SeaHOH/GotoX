# coding:utf-8

import json
import queue
import socket
import dnslib
import logging
import random
import urllib.parse as urlparse
from select import select
from time import mtime, sleep
from threading import _start_new_thread as start_new_thread
from .net import servers_2_addresses, isip, isipv4, isipv6, stop_all_forward
from .util import LRUCache, spawn_loop
from local.GlobalConfig import GC

A = dnslib.QTYPE.A
AAAA = dnslib.QTYPE.AAAA
OPT = dnslib.QTYPE.OPT
NOERROR = dnslib.RCODE.NOERROR
NXDOMAIN = dnslib.RCODE.NXDOMAIN
qtypes = []
if '4' in GC.LINK_PROFILE:
    qtypes.append(A)
if '6' in GC.LINK_PROFILE:
    qtypes.append(AAAA)

def reset_dns():
    dns.clear()
    #保持链接 GAE/GWS 列表不过期
    dns.set('google_gae|', GC.IPLIST_MAP['google_gae'], expire=False)
    dns.set('google_gws|', GC.IPLIST_MAP['google_gws'], expire=False)
    stop_all_forward()

def set_dns(host, iporname):
    #先处理正常解析
    if iporname is None:
        if dns_resolve(host):
            return host
        else:
            return
    #尝试解析可能的域名
    if isinstance(iporname, str) and \
            iporname.find('.') > 0 and \
            not iporname.startswith('cdn_'):
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
    if iplist == [NXDOMAIN]:
        return []
    return iplist

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

dns = LRUCache(GC.DNS_CACHE_ENTRIES, GC.DNS_CACHE_EXPIRATION)
reset_dns()

from .region import ipdb, islocal
from local.FilterUtil import get_action
from local.HTTPUtil import http_gws, http_nor

#待处理：IP 数据库尚未支持 IPv6 地址
def check_servers(servers, local):
    return tuple((sv, d) for sv, d in servers
                 if not ipdb or (not local and d != 53) or
                 isipv6(sv) or (sv in ipdb) is local)

dns_remote_servers = servers_2_addresses(GC.DNS_SERVERS, 53)
dns_remote_servers = check_servers(dns_remote_servers, False) or (('1.1.1.1', 53), )
dns_remote_local_servers = check_servers(dns_remote_servers, True)
dns_local_servers = servers_2_addresses(GC.DNS_LOCAL_SERVERS, 53)
dns_local_servers = (dns_remote_local_servers + 
                     check_servers(dns_local_servers, True)
                    ) or (('114.114.114.114', 53), )
dns_local_prefer = GC.DNS_LOCAL_PREFER and any(d == 53 for _, d in dns_remote_servers)
dns_time_threshold = GC.DNS_TIME_THRESHOLD / 1000

class DoHError(Exception):
    pass

class doh_params:
    ssl = True
    command = 'POST'
    headers = {
        'Accept': 'application/dns-message',
        'Content-Type': 'application/dns-message'
    }

    def __init__(self, host, port, path):
        self.host = host
        self.port = port
        self.path = path
        self.url = 'https://%s%s' % (host, path)

    def set_dns(self):
        action, target = get_action('https', self.host, self.path, self.url)
        if target and action in ('do_DIRECT', 'do_FORWARD'):
            iporname, profile = target
        else:
            iporname, profile = None, None
        if iporname is None and self.host not in dns:
            logging.warning('无法找到 DoH 域名 %r 的自定义 IP 列表，尝试使用系统 DNS 设置解析。', self.host)
            dns[self.host] = dns_system_resolve(self.host)
        self.hostname = set_dns(self.host, iporname)
        if self.hostname is None:
            logging.error('无法解析 DoH 域名：' + self.host)

doh_servers = set()
doh_servers_bad = set()
for _sv in GC.DNS_OVER_HTTPS_SERVERS:
    _sv = urlparse.urlsplit('http://' + _sv)
    doh_servers.add(doh_params(_sv.hostname.encode('idna').decode(),
                    _sv.port or 443,
                    urlparse.quote(_sv.path) or '/dns-query'))

# add 方法在最后调用以避免丢失数据
def mark_good_doh(server):
    doh_servers_bad.discard(server)
    doh_servers.add(server)

def mark_bad_doh(server):
    doh_servers.discard(server)
    doh_servers_bad.add(server)

def _https_resolve(server, qname, qtype, query_data):
    '此函数功能实现仅限于解析为 A、AAAA 记录'
    # https://developers.cloudflare.com/1.1.1.1/dns-over-https/wireformat/

    iplist = []
    xip = None
    response = None
    noerror = False
    ok = False
    http_util = http_gws if server.hostname.startswith('google') else http_nor
    connection_cache_key = '%s:%d' % (server.hostname, server.port)
    try:
        response = http_util.request(server, query_data, headers=server.headers.copy(), connection_cache_key=connection_cache_key)
        if response:
            data = response.read()
            noerror = True
            if response.status == 200:
                reply = dnslib.DNSRecord.parse(data)
                if reply:
                    if reply.header.rcode is NXDOMAIN:
                        ok = True
                        iplist.append(NXDOMAIN)
                    else:
                        ok = reply.header.rcode is NOERROR
                        for r in reply.rr:
                            if r.rtype is qtype:
                                iplist.append(str(r.rdata))
            else:
                raise DoHError((response.status, data))
    except DoHError as e:
        logging.error('%s _https_resolve %r 失败：%r',
                      address_string(response), qname, e)
    except Exception as e:
        logging.debug('%s _https_resolve %r 失败：%r',
                      address_string(response), qname, e)
    finally:
        if response:
            response.close()
            xip = response.xip
            if noerror:
                if GC.GAE_KEEPALIVE or http_util is not http_gws:
                    http_util.ssl_connection_cache[connection_cache_key].append((mtime(), response.sock))
                else:
                    response.sock.close()
        return iplist, xip, ok

def _dns_over_https_resolve(qname, qtypes=qtypes):

    def get_wire():
        return dnslib.DNSRecord(q=dnslib.DNSQuestion(qname, qtype)).pack()

    iplist = classlist()
    xips = []
    qtypes = list(qtypes)
    qtype = qtypes.pop()
    query_data = get_wire()
    while True:
        try:
            servers = random.sample(tuple(doh_servers), len(doh_servers))
            break
        except ValueError:
            pass
    if doh_servers_bad:
        servers += list(doh_servers_bad)
    for server in servers:
        while True:
            ok = False
            server.set_dns()
            if server.hostname is None:
                break
            _iplist, xip, ok = _https_resolve(server, qname, qtype, query_data)
            iplist += _iplist
            if xip and xip not in xips:
                xips.append(xip)
            if ok and qtypes:
                qtype = qtypes.pop()
                query_data = get_wire()
            else:
                break
        if ok:
            mark_good_doh(server)
            if not qtypes:
                break
        else:
            mark_bad_doh(server)
    if xips:
        iplist.xip = xips
    return iplist

remote_query_opt = dnslib.EDNS0(flags='do', udp_len=1024)  # 1232
bv4_remote = 1 << 0
bv6_remote = 1 << 1
bv4_local = 1 << 2
bv6_local = 1 << 3
allresolved = (1 << 4) - 1

def check_edns_opt(ar):
    for r in ar:
        if r.rtype is OPT:
            return r.edns_do

def _dns_udp_resolve(qname, dnsservers, timeout=2, qtypes=qtypes):
    # https://gfwrev.blogspot.com/2009/11/gfwdns.html
    # https://zh.wikipedia.org/wiki/域名服务器缓存污染
    # http://support.microsoft.com/kb/241352 (已删除)

    def get_sock(v4):
        nonlocal sock_v4, sock_v6
        if v4:
            if sock_v4 is None:
                sock_v4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                socks.append(sock_v4)
            return sock_v4
        else:
            if sock_v6 is None:
                sock_v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                socks.append(sock_v6)
            return sock_v6

    socks = []
    sock_v4 = sock_v6 = None
    query_times = 0
    iplists = {'remote': []}
    remote_resolve = dnsservers is dns_remote_servers
    if remote_resolve and dns_local_prefer:
        local_servers = dns_remote_local_servers or (random.choice(dns_local_servers), )
        iplists['local'] = []
    else:
        local_servers = ()
    if local_servers:
        dnsservers = set(dnsservers + local_servers)
    for qtype in qtypes:
        query = dnslib.DNSRecord(q=dnslib.DNSQuestion(qname, qtype))
        if remote_resolve:
            query.ar.append(remote_query_opt)
        query_data = query.pack()
        for dnsserver in dnsservers:
            sock = get_sock(isipv4(dnsserver[0]))
            try:
                sock.sendto(query_data, dnsserver)
                query_times += 1
            except socket.error as e:
                logging.warning('send dns qname=%r \nsocket: %r', qname, e)
        del query, query_data
    del dnsservers

    def is_resolved(qtype):
        if qtype is A:
            return resolved & (bv4_local if local else bv4_remote)
        elif qtype is AAAA:
            return resolved & (bv6_local if local else bv6_remote)
        return True

    time_start = mtime()
    timeout_at = time_start + timeout
    iplist = []
    xips = []
    pollution = False
    resolved = 0
    if A not in qtypes:
        resolved |= bv4_remote | bv4_local
    elif AAAA not in qtypes:
        resolved |= bv6_remote | bv6_local
    udp_len = remote_resolve and remote_query_opt.edns_len or 512
    while mtime() < timeout_at and (allresolved ^ resolved) and query_times:
        ins, _, _ = select(socks, [], [], 0.1)
        for sock in ins:
            iplist.clear()
            qtype = None
            try:
                reply_data, xip = sock.recvfrom(udp_len)
                local = xip in local_servers
                if local and pollution:
                    continue
                reply = dnslib.DNSRecord.parse(reply_data)
                qtype = reply.q.qtype
                rr_alone = len(reply.rr) == 1
                if is_resolved(qtype):
                    continue
                if remote_resolve and not local:
                    if rr_alone and (not check_edns_opt(reply.ar) or
                            mtime() - time_start < dns_time_threshold):
                        query_times += 1
                        pollution = True
                        continue
                    elif not pollution and dns_local_prefer:
                        resolved |= bv4_remote | bv6_remote
                        if is_resolved(qtype):
                            continue
                if reply.header.rcode is NOERROR:
                    for r in reply.rr:
                        if r.rtype is qtype:
                            ip = str(r.rdata)
                            #一个简单排除 IPv6 污染定式的方法，有及其微小的机率误伤正常结果
                            #虽然没办法用于 IPv4，但这只是 check_edns_opt 的后备，聊胜于无
                            if qtype is AAAA and pollution and rr_alone and \
                                    len(ip) == 15 and ip.startswith('2001::'):
                                query_times += 1
                                #iplist.clear()
                                #break
                            else:
                                iplist.append(ip)
                elif reply.header.rcode is NXDOMAIN:
                    timeout_at = 0
                    iplist.append(NXDOMAIN)
                    break
            except socket.error as e:
                logging.warning('receive dns qname=%r \nsocket: %r', qname, e)
            except dnslib.dns.DNSError as e:
                # dnslib 没有完整的支持，这里跳过一些不影响使用的解析错误
                logging.debug('receive dns qname=%r \nerror: %r', qname, e)
            finally:
                query_times -= 1
                if iplist:
                    if local:
                        resolved |= bv4_local if qtype is A else bv6_local
                        iplists['local'].extend(iplist)
                    else:
                        resolved |= bv4_remote if qtype is A else bv6_remote
                        iplists['remote'].extend(iplist)
                #大概率没有 AAAA 结果
                elif qtype is AAAA and is_resolved(A):
                    resolved |= bv6_local if local else bv6_remote
                if xip not in xips:
                    xips.append(xip)
    for sock in socks:
        sock.close()
    logging.debug('query qname=%r reply iplist=%s', qname, iplists)
    if pollution or not remote_resolve or not dns_local_prefer:
        iplist = iplists['remote']
    else:
        iplist = iplists['local']
    if xips:
        iplist = classlist(iplist)
        iplist.xip = xips
    if pollution:
        logging.warning('发现 DNS 污染, 域名: %r, 解析结果:\n%r', qname, iplists)
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
        logging.warning('get_dnsserver_list 失败：不支持 "%s-%s" 平台',
                        sys.platform, os.name)
        return []

dns_system_servers = set(ip for ip in get_dnsserver_list() if isip(ip))
if '127.0.0.1' in dns_system_servers and '::1' in dns_system_servers:
    #视为同一个本地服务器，大多数情况下这是正确地
    dns_system_servers.remove('::1')
dns_system_servers = tuple((server, 53) for server in dns_system_servers)
if dns_system_servers:
    logging.test('已读取系统当前 DNS 设置：%r', dns_system_servers)
else:
    logging.warning('读取系统当前 DNS 设置失败')

def dns_system_resolve(host, qtypes=qtypes):
    start = mtime()
    try:
        if dns_system_servers:
            iplist = _dns_udp_resolve(host, dns_system_servers, timeout=2, qtypes=qtypes)
        # getaddrinfo 在 Windows 下无法并发，其它系统未知
        else:
            if AAAA not in qtypes:
                iplist = socket.gethostbyname_ex(host)[-1]
            elif A in qtypes:
                iplist = [ipaddr[4][0] for ipaddr in socket.getaddrinfo(host, None)]
            else:
                iplist = [ipaddr[4][0] for ipaddr in socket.getaddrinfo(host, None, socket.AF_INET6)]
    except:
        iplist = None
    cost = int((mtime() - start) * 1000)
    logging.test('%sdns_system_resolve 已缓存：%s/%s，耗时：%s 毫秒，%s = %s',
                 address_string(iplist), len(dns), dns.max_items, cost, host, iplist or '查询失败')
    return iplist

def dns_remote_resolve(host, qtypes=qtypes):
    start = mtime()
    iplist = _dns_udp_resolve(host, dns_remote_servers, timeout=2, qtypes=qtypes)
    cost = int((mtime() - start) * 1000)
    logging.test('%sdns_remote_resolve 已缓存：%s/%s，耗时：%s 毫秒，%s = %s',
                 address_string(iplist), len(dns), dns.max_items, cost, host, iplist or '查询失败')
    return iplist

def dns_local_resolve(host, qtypes=qtypes):
    start = mtime()
    iplist = _dns_udp_resolve(host, dns_local_servers, timeout=2, qtypes=qtypes)
    cost = int((mtime() - start) * 1000)
    logging.test('%sdns_local_resolve 已缓存：%s/%s，耗时：%s 毫秒，%s = %s',
                 address_string(iplist), len(dns), dns.max_items, cost, host, iplist or '查询失败')
    return iplist

def dns_over_https_resolve(host, qtypes=qtypes):
    start = mtime()
    iplist = _dns_over_https_resolve(host, qtypes=qtypes) 
    cost = int((mtime() - start) * 1000)
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
