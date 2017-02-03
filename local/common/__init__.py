# coding:utf-8

import os
import sys
import glob
from local import clogging as logging

app_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
cert_dir = os.path.join(app_root, 'cert')
config_dir = os.path.join(app_root, 'config')
data_dir = os.path.join(app_root, 'data')
py_dir = os.path.join(app_root, 'python')
web_dir = os.path.join(app_root, 'web')
packages = os.path.join(py_dir, 'site-packages')

#自带 py 已经添加
if os.path.dirname(sys.executable) != py_dir:
    #优先导入当前运行 py 已安装模块
    sys.path.append(packages)
    sys.path += glob.glob('%s/*.egg' % packages)

try:
    import gevent
    import gevent.monkey
    gevent.monkey.patch_all(os=False, signal=False, subprocess=False, Event=True)
except ImportError:
    logging.warning('无法找到 gevent，请安装 gevent-1.0.0 以上版本，或将相应 .egg 放到 %r 文件夹！\n正在退出……', packages)
    sys.exit(-1)
except TypeError:
    gevent.monkey.patch_all(os=False)
    logging.warning('警告：请更新 gevent 至 1.0.0 以上版本！')

try:
    import OpenSSL
except ImportError:
    logging.exception('无法找到 pyOpenSSL，请安装 pyOpenSSL-16.0.0 以上版本，或将相应 .egg 放到 %r 文件夹！\n正在退出……', packages)
    sys.exit(-1)

from local.compat import thread
import re
import ssl
import socket
import string
import threading
import collections
from time import time, sleep

NetWorkIOError = (socket.error, ssl.SSLError, OSError) if not OpenSSL else (socket.error, ssl.SSLError, OpenSSL.SSL.Error, OSError)

class LRUCache():
    '''Modified from http://pypi.python.org/pypi/lru/'''

    def __init__(self, max_items, expire=None):
        self.cache = {}
        self.max_items = int(max_items)
        self.expire = expire
        self.key_expire = {}
        self.key_order = collections.deque()
        self.lock = threading.Lock()

    def __setitem__(self, key, value):
        with self.lock:
            if self.expire:
                self.key_expire[key] = int(time()) + self.expire
            self._mark(key)
            self.cache[key] = value

    def __getitem__(self, key):
        with self.lock:
            self._expire_check(key)
            if key in self.cache:
                self._mark(key)
                return self.cache[key]
            else:
                raise KeyError(key)

    def __contains__(self, key):
        with self.lock:
            self._expire_check(key)
            return key in self.cache

    def __len__(self):
        with self.lock:
            return len(self.key_order)

    def set(self, key, value, expire=None):
        expire = expire or self.expire
        with self.lock:
            if expire:
                self.key_expire[key] = int(time()) + expire
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

    def _expire_check(self, key):
        if key in self.key_expire and time() > self.key_expire[key]:
            self.key_order.remove(key)
            del self.key_expire[key]
            del self.cache[key]

    def _mark(self, key):
        key_order = self.key_order
        if key in self.cache:
            try:
                key_order.remove(key)
            except ValueError:
                pass
        key_order.appendleft(key)
        while len(key_order) > self.max_items:
            key = key_order.pop()
            if key in self.key_expire:
                del self.key_expire[key]
            del self.cache[key]

    def clear(self):
        with self.lock:
            self.cache.clear()
            self.key_expire.clear()
            self.key_order.clear()

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

#import random
#def onlytime():
#    return int(time())+random.random()

isip = re.compile(r'(\d+\.){3}\d+$|(([a-f\d]{1,4}:){1,6}|:)([a-f\d]{1,4})?(:[a-f\d]{1,4}){1,6}$').match
isipv4 = re.compile(r'(\d+\.){3}\d+$').match
isipv6 = re.compile(r'(([a-f\d]{1,4}:){1,6}|:)([a-f\d]{1,4})?(:[a-f\d]{1,4}){1,6}$').match

class classlist(list): pass

def spawn_later(seconds, target, *args, **kwargs):
    def wrap(*args, **kwargs):
        sleep(seconds)
        target(*args, **kwargs)
    thread.start_new_thread(wrap, args, kwargs)
