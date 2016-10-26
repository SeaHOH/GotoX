# coding:utf-8

import os
import re
import string
import select
import socket
import random
from time import time, sleep
from compat import (
    thread,
    xrange,
    dnslib,
    Queue,
    urllib2,
    logging
    )

#if os.name == 'nt':
app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cert_dir = os.path.join(app_root, 'cert')
config_dir = os.path.join(app_root, 'config')
data_dir = os.path.join(app_root, 'data')
web_dir = os.path.join(app_root, 'web')
#else:
#    cert_dir = 'cert'
#    config_dir = 'config'
#    data_dir = 'data'
#    web_dir = 'web'


class LRUCache(object):
    """http://pypi.python.org/pypi/lru/"""

    def __init__(self, max_items=100):
        self.cache = {}
        self.key_order = []
        self.max_items = max_items

    def __setitem__(self, key, value):
        self.cache[key] = value
        self._mark(key)

    def __getitem__(self, key):
        value = self.cache[key]
        self._mark(key)
        return value

    def _mark(self, key):
        if key in self.key_order:
            self.key_order.remove(key)
        self.key_order.insert(0, key)
        if len(self.key_order) > self.max_items:
            remove = self.key_order[self.max_items]
            del self.cache[remove]
            self.key_order.pop(self.max_items)

    def clear(self):
        self.cache = {}
        self.key_order = []


def message_html(title, banner, detail=''):
    MESSAGE_TEMPLATE = '''
    <html><head>
    <meta http-equiv="content-type" content="text/html;charset=utf-8">
    <title>$title</title>
    <style><!--
    body {font-family: arial,sans-serif}
    div.nav {margin-top: 1ex}
    div.nav A {font-size: 10pt; font-family: arial,sans-serif}
    span.nav {font-size: 10pt; font-family: arial,sans-serif; font-weight: bold}
    div.nav A,span.big {font-size: 12pt; color: #0000cc}
    div.nav A {font-size: 10pt; color: black}
    A.l:link {color: #6f6f6f}
    A.u:link {color: green}
    //--></style>
    </head>
    <body text=#000000 bgcolor=#ffffff>
    <table border=0 cellpadding=2 cellspacing=0 width=100%>
    <tr><td bgcolor=#3366cc><font face=arial,sans-serif color=#ffffff><b>Message</b></td></tr>
    <tr><td> </td></tr></table>
    <blockquote>
    <H1>$banner</H1>
    $detail
    <p>
    </blockquote>
    <table width=100% cellpadding=0 cellspacing=0><tr><td bgcolor=#3366cc><img alt="" width=1 height=4></td></tr></table>
    </body></html>
    '''
    return string.Template(MESSAGE_TEMPLATE).substitute(title=title, banner=banner, detail=detail)

def onlytime():
    return int(time())+random.random()

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

class testip():
    lastupdata = time()
    running = False
    lasttest = lastupdata - 30
    lastactive = None
    qcount = 0
    tested = {}
    queobj = Queue.Queue()

isip = re.compile(r'(\d+\.){3}\d+$|(([a-f\d]{1,4}:){1,6}|:)([a-f\d]{1,4})?(:[a-f\d]{1,4}){1,6}$').match
isipv4 = re.compile(r'(\d+\.){3}\d+$').match
isipv6 = re.compile(r'(([a-f\d]{1,4}:){1,6}|:)([a-f\d]{1,4})?(:[a-f\d]{1,4}){1,6}$').match

from GlobalConfig import GC
dns = {}
def dns_resolve(host, dnsservers=[]):
    if isip(host):
        return [host]
    iplist = dns.get(host)
    if not iplist:
        if not dnsservers:
            iplist = list(set(socket.gethostbyname_ex(host)[-1]) - GC.DNS_BLACKLIST)
        else:
            iplist = dns_remote_resolve(host, dnsservers, GC.DNS_BLACKLIST, timeout=2)
        if not iplist:
            iplist = dns_remote_resolve(host, GC.DNS_SERVERS, GC.DNS_BLACKLIST, timeout=2)
        if iplist:
            if GC.LINK_PROFILE == 'ipv4':
                iplist = [ip for ip in iplist if isipv4(ip)]
            elif GC.LINK_PROFILE == 'ipv6':
                iplist = [ip for ip in iplist if isipv6(ip)]
            dns[host] = iplist = list(set(iplist))
        else:
            raise
    return iplist

def dns_remote_resolve(qname, dnsservers, blacklist, timeout):
    """
    http://gfwrev.blogspot.com/2009/11/gfwdns.html
    http://zh.wikipedia.org/wiki/域名服务器缓存污染
    http://support.microsoft.com/kb/241352
    """
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
        for _ in xrange(2):
            try:
                for dnsserver in dns_v4_servers:
                    sock_v4.sendto(query_data, (dnsserver, 53))
                for dnsserver in dns_v6_servers:
                    sock_v6.sendto(query_data, (dnsserver, 53))
                while time() < timeout_at:
                    ins, _, _ = select.select(socks, [], [], 0.1)
                    for sock in ins:
                        reply_data, _ = sock.recvfrom(512)
                        reply = dnslib.DNSRecord.parse(reply_data)
                        iplist = [str(x.rdata) for x in reply.rr if x.rtype == 1]
                        if any(x in blacklist for x in iplist):
                            logging.warning('query qname=%r reply bad iplist=%r', qname, iplist)
                        else:
                            logging.debug('query qname=%r reply iplist=%s', qname, iplist)
                            return iplist
            except socket.error as e:
                logging.warning('handle dns query=%s socket: %r', query, e)
    finally:
        for sock in socks:
            sock.close()


def spawn_later(seconds, target, *args, **kwargs):
    def wrap(*args, **kwargs):
        sleep(seconds)
        return target(*args, **kwargs)
    return thread.start_new_thread(wrap, args, kwargs)
