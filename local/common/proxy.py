# coding:utf-8
'''ProxyUtil module, based on urllib2'''

import socket
from local.compat import urllib2

parse_proxy = urllib2._parse_proxy

def get_system_proxy():
    proxies = urllib2.getproxies()
    return proxies.get('https') or proxies.get('http') or {}

def get_listen_ip():
    listen_ip = '127.0.0.1'
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 53))
        listen_ip = sock.getsockname()[0]
    except StandardError:
        pass
    finally:
        if sock:
            sock.close()
    return listen_ip
