# coding:utf-8
'''ProxyUtil module, based on urllib.request'''

import socket
from .util import LRUCache
from urllib import request

parse_proxy_cache = LRUCache(128)
proxy_no_rdns = set()

def parse_proxy(proxy):
    try:
        return parse_proxy_cache[proxy]
    except KeyError:
        parse_proxy_cache[proxy] = proxy_tuple = request._parse_proxy(proxy)
        return proxy_tuple

def get_system_proxy():
    proxies = request.getproxies()
    return proxies.get('https') or proxies.get('http')

def get_listen_ip():
    listen_ip = []
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 53))
        listen_ip.append(sock.getsockname()[0])
    except:
        pass
    finally:
        if sock:
            sock.close()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.connect(('2001:4860:4860::8888', 53))
        listen_ip.append(sock.getsockname()[0].partition('%')[0])
    except:
        pass
    finally:
        if sock:
            sock.close()
    if listen_ip:
        return listen_ip
    else:
        import errno
        raise OSError(errno.ENETDOWN, '网络配置错误！')
