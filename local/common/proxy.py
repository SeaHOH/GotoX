# coding:utf-8
'''ProxyUtil module, based on urllib2'''

import socket
from local.compat import urllib2

parse_proxy = urllib2._parse_proxy

def get_system_proxy():
    proxies = urllib2.getproxies()
    return proxies.get('https') or proxies.get('http') or {}

def get_listen_ip():
    listen_ip = []
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 53))
        listen_ip.append(sock.getsockname()[0])
    finally:
        if sock:
            sock.close()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.connect(('2001:4860:4860::8888', 53))
        listen_ip.append(sock.getsockname()[0].partition('%')[0])
    finally:
        if sock:
            sock.close()
    return listen_ip
