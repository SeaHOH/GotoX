# coding:utf-8

import errno
import socket
import random
import ipaddress
import logging
import OpenSSL
import urllib.request
from time import mtime
from select import select

NetWorkIOError = OSError, OpenSSL.SSL.Error
reset_errno = errno.ECONNRESET, errno.ENAMETOOLONG
if hasattr(errno, 'WSAENAMETOOLONG'):
    reset_errno += errno.WSAENAMETOOLONG,
closed_errno = errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE
bypass_errno = -1, 'timed out', *closed_errno

dchars = ['bcdfghjklmnpqrstvwxyz', 'aeiou', '0123456789']
pchars = [*(0,) * 8, *(1,) * 6, *(2,) * 1]
subds = (
    'www|img|pic|js|game|mail|static|ajax|video|lib|login|player|image|api|art|'
    'upload|download|cdnjs|cc|s|book|v|service|web|forum|bbs|news|home|wiki|it|'
    'feeds|update|blog|doc|play|read|go|info|tv|day|accounts|store|feed|docs|f|'
    'member|map|pay|support|en|log|comment|style|music|knowledge|help|buy|milk|'
    'story|media|movie|paper|photo|topic|studio|drama|study|place|group|garden|'
    'sport|fun|page|sound|term|test|kind|rate|gift|join|master|tree|a|you|show|'
    'one|other|raw|solid|funny|knife|native|cow|physical|watch|beautiful|frame|'
    'character|box|account|issue|step|reason|face|item|metal|paint|review|room|'
    'cycle|screen|structure|view|friend|notice|id|market|brief|spell|font|start'
).split('|')
gtlds = [
    *('com',) * 8,
    *('org',) * 5,
    *('net',) * 3,
    *('gov',) * 2,
    *('edu',) * 2,
    *('xyz',) * 1,
    *('info',) * 1
]
random.shuffle(pchars)
random.shuffle(subds)
random.shuffle(gtlds)

def random_hostname(wildcard_host=None):
    replace_wildcard = wildcard_host and '*' in wildcard_host
    if replace_wildcard and '{' in wildcard_host:
        try:
            a = wildcard_host.find('{')
            b = wildcard_host.find('}')
            word_length = int(wildcard_host[a + 1:b])
            wildcard_host = wildcard_host[:a] + wildcard_host[b + 1:]
        except:
            pass
    else:
        word_length = random.randint(5, 12)
    maxcl = word_length * 2 // 3 or 1
    maxcv = word_length // 2 or 1
    maxd = word_length // 6
    chars = []
    for _ in range(word_length):
        while True:
            n = random.choice(pchars)
            if n == 0 and maxcl:
                maxcl -= 1
                break
            elif n == 1 and maxcv:
                maxcv -= 1
                break
            elif n == 2 and maxd:
                maxd -= 1
                break
        chars.append(random.choice(dchars[n]))
    random.shuffle(chars)
    if word_length > 7 and not random.randrange(3):
        if replace_wildcard:
            if '-' not in wildcard_host:
                chars[random.randint(4, word_length - 4)] = '-'
        else:
            chars.insert(random.randint(4, word_length - 3), '-')
    sld = ''.join(chars)
    if replace_wildcard:
        return wildcard_host.replace('*', sld)
    else:
        subd = random.choice(subds)
        gtld = random.choice(gtlds)
        return '.'.join((subd, sld, gtld))

def isip(ip):
    if ':' in ip:
        return isipv6(ip)
    elif '.' in ip:
        return isipv4(ip)
    else:
        return False

def isipv4(ip, AF_INET=socket.AF_INET, inet_pton=socket.inet_pton):
    if '.' not in ip:
        return False
    try:
        inet_pton(AF_INET, ip)
    except:
        return False
    else:
        return True

def isipv6(ip, AF_INET6=socket.AF_INET6, inet_pton=socket.inet_pton):
    if ':' not in ip:
        return False
    try:
        inet_pton(AF_INET6, ip.strip('[]'))
    except:
        return False
    else:
        return True

def explode_ip(ip):
    if isipv4(ip):
        return explode_ipv4(ip)
    elif isipv6(ip):
        return explode_ipv6(ip)
    else:
        return []

def explode_ipv4(ip):
    nw24 = ip.rpartition('.')[0]
    return [f'{nw24:s}.{i:d}' for i in range(256)]

def explode_ipv6(ip):
    if '.' in ip:
        return explode_ipv4(ip)
    nw112, _, ar16 = ip.rpartition(':')
    nw120 = f'{nw112:s}:{ar16[:-2]:s}'
    return [f'{nw120:s}{i:x}' for i in range(256)]

def get_parent_domain(host):
    ip = isip(host)
    if not ip:
        hostsp = host.split('.')
        nhost = len(hostsp)
        if nhost > 3 or nhost == 3 and (len(hostsp[-1]) > 2 or len(hostsp[-2]) > 3):
            host = '.'.join(hostsp[1:])
    return host

def get_main_domain(host):
    ip = isip(host)
    if not ip:
        hostsp = host.split('.')
        if len(hostsp[-1]) > 2:
            host = '.'.join(hostsp[-2:])
        elif len(hostsp) > 2:
            if len(hostsp[-2]) > 3:
                host = '.'.join(hostsp[-2:])
            else:
                host = '.'.join(hostsp[-3:])
    return host

direct_opener = None
dns_ip_api = None

def init_direct_opener():
    from local.GlobalConfig import GC
    global direct_opener, dns_ip_api
    direct_opener = urllib.request.OpenerDirector()
    #if GC.proxy:
    #    direct_opener.add_handler(urllib.request.ProxyHandler({
    #        'http': GC.proxy,
    #        'https': GC.proxy
    #    })
    handler_names = ['UnknownHandler', 'HTTPHandler', 'HTTPSHandler',
                     'HTTPDefaultErrorHandler', 'HTTPRedirectHandler',
                     'HTTPErrorProcessor']
    for handler_name in handler_names:
        klass = getattr(urllib.request, handler_name, None)
        if klass:
            direct_opener.add_handler(klass())
    dns_ip_api = GC.DNS_IP_API

def get_wan_ipv4():
    if direct_opener is None:
        init_direct_opener()
    if dns_ip_api:
        apis = list(dns_ip_api)
        random.shuffle(apis)
        for url in apis:
            response = None
            try:
                response = direct_opener.open(url, timeout=10)
                content = response.read().decode().strip()
                if isipv4(content):
                    logging.test('当前 IPv4 公网出口 IP 是：%s', content)
                    return content
            except:
                pass
            finally:
                if response:
                    response.close()
    logging.warning('获取 IPv4 公网出口 IP 失败，请增加更多的 IP-API')

def get_wan_ipv6():
    sock = None
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.connect(('2001:4860:4860::8888', 80))
        addr6 = ipaddress.IPv6Address(sock.getsockname()[0])
        if addr6.is_global or addr6.teredo or addr6.sixtofour:
            return addr6
    except:
        pass
    finally:
        if sock:
            sock.close()

def check_connection_dead(sock):
    dead = True
    try:
        fd = sock.fileno()
        if fd >= 0:
            rd, _, ed = select([fd], [], [fd], 0)
            dead = bool(rd or ed)
    except OSError:
        pass
    if dead:
        sock.close()
    return dead

all_forward_sockets = set()

def stop_all_forward():
    all_forward_sockets.clear()

def forward_socket(local, remote, payload=None, timeout=60, tick=4, bufsize=8192, maxping=None, maxpong=None):
    if payload:
        remote.sendall(payload)
    buf = memoryview(bytearray(bufsize))
    maxpong = maxpong or timeout
    allins = [local, remote]
    timecount = timeout
    all_forward_sockets.add(remote)
    try:
        while allins and timecount > 0:
            start_time = mtime()
            ins, _, err = select(allins, [], allins, tick)
            t = mtime() - start_time
            timecount -= int(t)
            if err:
                raise socket.error(err)
            if remote not in all_forward_sockets:
                break
            for sock in ins:
                ndata = sock.recv_into(buf)
                if ndata:
                    other = local if sock is remote else remote
                    other.sendall(buf[:ndata])
                elif sock is remote:
                    return
                else:
                    allins.remove(sock)
            if ins and len(allins) == 2:
                timecount = max(min(timecount * 2, maxpong), tick)
    except Exception as e:
        logging.debug('forward_socket except: %s %r', ins, e)
        raise
    finally:
        all_forward_sockets.discard(remote)
        remote.close()
