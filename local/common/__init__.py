# coding:utf-8

import os
import sys
import re
import ssl
import errno
import socket
import string
import threading
import collections
import ipaddress
import logging
import OpenSSL
from time import time, sleep
from local.compat import thread

NetWorkIOError = (socket.error, ssl.SSLError, OSError, OpenSSL.SSL.Error) if OpenSSL else (socket.error, ssl.SSLError, OSError)
# Windows: errno.WSAENAMETOOLONG = 10063
reset_errno = errno.ECONNRESET, 10063, errno.ENAMETOOLONG
closed_errno = errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE
pass_errno = -1, errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE

NONEKEY = object()
class LRUCache:
    # Modified from http://pypi.python.org/pypi/lru/
    #最近最少使用缓存，支持过期时间设置
    failobj = object()

    def __init__(self, max_items, expire=None):
        self.cache = {}
        self.max_items = int(max_items)
        self.expire = expire
        self.key_expire = {}
        self.key_noexpire = set()
        self.key_order = collections.deque()
        self.lock = threading.Lock()
        if expire:
            thread.start_new_thread(self._cleanup, ())

    def __delitem__(self, key):
        with self.lock:
            if key in self.cache:
                self.key_order.remove(key)
                if key in self.key_expire:
                    del self.key_expire[key]
                if key in self.key_noexpire:
                    del self.key_noexpire[key]
                del self.cache[key]
            else:
                raise KeyError(key)

    def __setitem__(self, key, value):
        self.set(key, value)

    def __getitem__(self, key):
        value = self.get(key, self.failobj)
        if value is self.failobj:
            raise KeyError(key)
        else:
            return value

    def __contains__(self, key):
        with self.lock:
            self._expire_check(key)
            return key in self.cache

    def __len__(self):
        with self.lock:
            return len(self.key_order)

    def set(self, key, value, expire=False, noexpire=False):
        with self.lock:
            if noexpire:
                expire = False
                self.key_noexpire.add(key)
            elif key in self.key_noexpire:
                expire = False
            else:
                expire = expire or self.expire
            if expire:
                self.key_expire[key] = int(time()) + expire
            elif key in self.key_expire:
                del self.key_expire[key]
            self._mark(key)
            self.cache[key] = value

    def get(self, key, value=None):
        with self.lock:
            self._expire_check(key)
            if key in self.cache:
                self._mark(key)
                return self.cache[key]
            else:
                return value

    def getstate(self, key):
        with self.lock:
            contains = key in self.cache
            value = self.cache.get(key)
            self._expire_check(key)
            expired = key not in self.cache
            return contains, expired, value

    def pop(self, key=NONEKEY):
        with self.lock:
            if key is not NONEKEY:
                self._expire_check(key)
                if key in self.cache:
                    self._mark(key)
                    value = self.cache[key]
                    self.key_order.remove(key)
                    if key in self.key_expire:
                        del self.key_expire[key]
                    if key in self.key_noexpire:
                        del self.key_noexpire[key]
                    del self.cache[key]
                    return value
                else:
                    raise KeyError(key)
            #未指明 key 时不检查抛出项是否过期，慎用！
            #返回元组 (key, value)
            if self.key_order:
                key = self.key_order.pop()
                value = self.cache[key]
                if key in self.key_noexpire:
                    del self.key_noexpire[key]
                if key in self.key_expire:
                    del self.key_expire[key]
                del self.cache[key]
                return key, value
            else:
                raise IndexError('pop from empty LRUCache')

    def _expire_check(self, key):
        key_expire = self.key_expire
        if key in key_expire:
            now = int(time())
            timeleft = key_expire[key] - now
            if timeleft <= 0:
                self.key_order.remove(key)
                del key_expire[key]
                del self.cache[key]
            elif timeleft < 8:
                #为可能存在的紧接的调用保持足够的反应时间
                key_expire[key] = now + 8

    def _mark(self, key):
        key_order = self.key_order
        cache = self.cache
        if key in cache:
            key_order.remove(key)
        key_order.appendleft(key)
        while len(key_order) > self.max_items:
            key = key_order.pop()
            if key in self.key_noexpire:
                key_order.appendleft(key)
            else:
                if key in self.key_expire:
                    del self.key_expire[key]
                del cache[key]

    def _cleanup(self):
        #按每秒一个的频率循环检查并清除靠后的 l/m 个项目中的过期项目
        lock = self.lock
        key_order = self.key_order
        key_expire = self.key_expire
        key_noexpire = self.key_noexpire
        cache = self.cache
        max_items = self.max_items
        m = 4
        n = 1
        while True:
            sleep(1)
            with lock:
                l = len(key_order)
                if l:
                    if l // m < n:
                        n = 1
                    key = key_order[-n]
                    if key in key_noexpire:
                        del key_order[-n]
                        key_order.appendleft(key)
                    elif key_expire[key] <= int(time()):
                        del key_order[-n]
                        del key_expire[key]
                        del cache[key]
                        n += 1

    def clear(self):
        with self.lock:
            self.cache.clear()
            self.key_expire.clear()
            self.key_noexpire.clear()
            self.key_order.clear()

class LimiterEmpty(OSError):
    pass

class LimiterFull(OSError):
    pass

class Limiter:
    'A queue.Queue-like class use for count and limit.'

    def __init__(self, maxsize=1):
        if maxsize < 1:
            raise ValueError('The maxsize can not be less than 1.')
        self.maxsize = maxsize
        self.mutex = threading.Lock()
        self.not_empty = threading.Condition(self.mutex)
        self.not_full = threading.Condition(self.mutex)
        self.__qsize = 0

    def qsize(self):
        with self.mutex:
            return self.__qsize

    def empty(self):
        with self.mutex:
            return not self.__qsize

    def full(self):
        with self.mutex:
            return self.maxsize <= self.__qsize

    def push(self, block=True, timeout=None):
        with self.not_full:
            if self.maxsize > 0:
                if not block:
                    if self.__qsize >= self.maxsize:
                        raise LimiterFull(-1)
                elif timeout is None:
                    while self.__qsize >= self.maxsize:
                        self.not_full.wait()
                elif timeout < 0:
                    raise ValueError("'timeout' must be a non-negative number")
                else:
                    endtime = time() + timeout
                    while self.__qsize >= self.maxsize:
                        remaining = endtime - time()
                        if remaining <= 0.0:
                            raise LimiterFull(-1)
                        self.not_full.wait(remaining)
            self.__qsize += 1
            self.not_empty.notify()

    def pop(self, block=True, timeout=None):
        with self.not_empty:
            if not block:
                if self.__qsize <= 0:
                    raise LimiterEmpty(-1)
            elif timeout is None:
                while self.__qsize <= 0:
                    self.not_empty.wait()
            elif timeout < 0:
                raise ValueError("'timeout' must be a non-negative number")
            else:
                endtime = time() + timeout
                while self.__qsize <= 0:
                    remaining = endtime - time()
                    if remaining <= 0.0:
                        raise LimiterEmpty(-1)
                    self.not_empty.wait(remaining)
            self.__qsize -= 1
            self.not_full.notify()

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
MESSAGE_TEMPLATE = string.Template(MESSAGE_TEMPLATE).substitute

def message_html(title, banner, detail=''):
    return MESSAGE_TEMPLATE(title=title, banner=banner, detail=detail)

import random

dchars = ['bcdfghjklmnpqrstvwxyz', 'aeiou', '0123456789']
pchars = [0, 0, 0, 1, 2, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1]
subds = [
    'www', 'img', 'pic', 'js', 'game', 'mail', 'static', 'ajax', 'video', 'lib',
    'login', 'player', 'image', 'api', 'upload', 'download', 'cdnjs', 'cc', 's',
    'book', 'v', 'service', 'web', 'forum', 'bbs', 'news', 'home', 'wiki', 'it'
    ]
gtlds = ['org', 'com', 'net', 'gov', 'edu', 'xyz','info']

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
                chars[random.randint(5, word_length - 4)] = '-'
        else:
            chars.insert(random.randint(5, word_length - 3), '-')
    sld = ''.join(chars)
    if replace_wildcard:
        return wildcard_host.replace('*', sld)
    else:
        subd = random.choice(subds)
        gtld = random.choice(gtlds)
        return '.'.join((subd, sld, gtld))

def isip(ip):
    if '.' in ip:
        return isipv4(ip)
    elif ':' in ip:
        return isipv6(ip)
    else:
        return False

def isipv4(ip, inet_aton=socket.inet_aton):
    if '.' not in ip:
        return False
    try:
        inet_aton(ip)
    except:
        return False
    else:
        return True

def isipv6(ip, AF_INET6=socket.AF_INET6, inet_pton=socket.inet_pton):
    if ':' not in ip:
        return False
    try:
        inet_pton(AF_INET6, ip)
    except:
        return False
    else:
        return True

#isipv4 = re.compile(r'^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$').match
#isipv6 = re.compile(r'^(?!:[^:]|.*::.*::)'
#                    r'(?:[0-9a-f]{0,4}(?:(?<=::)|(?<!::):)){7}'
#                    r'([0-9a-f]{1,4}'
#                    r'|(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})$', re.I).match

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

from local.GlobalConfig import GC
from local.compat import urllib2

direct_opener = urllib2.OpenerDirector()
handler_names = ['UnknownHandler', 'HTTPHandler', 'HTTPSHandler',
                 'HTTPDefaultErrorHandler', 'HTTPRedirectHandler',
                 'HTTPErrorProcessor']
for handler_name in handler_names:
    klass = getattr(urllib2, handler_name, None)
    if klass:
        direct_opener.add_handler(klass())

def get_wan_ipv4():
    for url in GC.DNS_IP_API:
        response = None
        try:
            response = direct_opener.open(url, timeout=10)
            content = response.read().decode().strip()
            if isip(content):
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
        if addr6.is_global or addr6.teredo:
            return addr6
    except:
        pass
    finally:
        if sock:
            sock.close()

class classlist(list): pass

def spawn_later(seconds, target, *args, **kwargs):
    def wrap(*args, **kwargs):
        sleep(seconds)
        try:
            target(*args, **kwargs)
        except Exception as e:
            logging.warning('%s.%s 错误：%s', target.__module__, target.__name__, e)
    thread.start_new_thread(wrap, args, kwargs)

def spawn_loop(seconds, target, *args, **kwargs):
    def wrap(*args, **kwargs):
        while True:
            sleep(seconds)
            try:
                target(*args, **kwargs)
            except Exception as e:
                logging.warning('%s.%s 错误：%s', target.__module__, target.__name__, e)
    thread.start_new_thread(wrap, args, kwargs)
