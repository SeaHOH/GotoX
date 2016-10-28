# coding:utf-8
'''ProxyUtil module, based on urllib2'''

import socket
from ..compat import urllib2

def parse_proxy(proxy):
    return urllib2._parse_proxy(proxy)

def get_system_proxy():
    proxies = urllib2.getproxies()
    return proxies.get('https') or proxies.get('http') or {}

def get_listen_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(('8.8.8.8', 53))
    listen_ip = sock.getsockname()[0]
    sock.close()
    return listen_ip
