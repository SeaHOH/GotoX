# coding:utf-8

import os
import sys
from local import clogging as logging

app_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
cert_dir = os.path.join(app_root, 'cert')
config_dir = os.path.join(app_root, 'config')
data_dir = os.path.join(app_root, 'data')
launcher_dir = os.path.join(app_root, 'launcher')
py_dir = os.path.join(app_root, 'python')
web_dir = os.path.join(app_root, 'web')
packages = os.path.join(py_dir, 'site-packages')

#自带 py 已经添加
if os.path.dirname(sys.executable) != py_dir:
    import glob
    #优先导入当前运行 py 已安装模块
    sys.path.append(packages)
    sys.path.extend(glob.glob('%s/*.egg' % packages))

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
from time import time, sleep, timezone, localtime, strftime, strptime, mktime

NetWorkIOError = (socket.error, ssl.SSLError, OSError, OpenSSL.SSL.Error) if OpenSSL else (socket.error, ssl.SSLError, OSError)

refreshzone = timezone - 28800
def get_refreshtime():
    #距离 GAE 流量配额每日刷新的时间
    now = time() + refreshzone
    refreshtime = strftime('%y %j', localtime(now + 86400))
    refreshtime = mktime(strptime(refreshtime, '%y %j'))
    return refreshtime - now

class LRUCache:
    # Modified from http://pypi.python.org/pypi/lru/
    #最近最少使用缓存，支持过期时间设置

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
        with self.lock:
            expire = False if key in self.key_noexpire else self.expire
            if expire:
                self.key_expire[key] = int(time()) + expire
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
            self._expire_check(key)
            expired = key in self.cache
            return contains, expired

    def pop(self, key=False):
        with self.lock:
            if key:
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
        #按每秒一个的频率循环检查并清除靠后的 m 个项目中的过期项目
        lock = self.lock
        key_order = self.key_order
        key_expire = self.key_expire
        key_noexpire = self.key_noexpire
        cache = self.cache
        max_items = self.max_items
        m = min(max_items//4, 60)
        n = m = max_items - m
        while True:
            sleep(1)
            with lock:
                l = len(key_order)
                if l > m:
                    if l <= n:
                        n = m
                    key = key_order[n]
                    if key in key_noexpire:
                        del key_order[n]
                        key_order.appendleft(key)
                    elif key_expire[key] <= int(time()):
                        del key_order[n]
                        del key_expire[key]
                        del cache[key]
                        n += 1

    def clear(self):
        with self.lock:
            self.cache.clear()
            self.key_expire.clear()
            self.key_noexpire.clear()
            self.key_order.clear()

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

#import random
#def onlytime():
#    return int(time())+random.random()

isip = re.compile(r'^(\d+\.){3}\d+$|^(([a-f\d]{1,4}:){1,6}|:)([a-f\d]{1,4})?(:[a-f\d]{1,4}){1,6}$').match
isipv4 = re.compile(r'^(\d+\.){3}\d+$').match
isipv6 = re.compile(r'^(([a-f\d]{1,4}:){1,6}|:)([a-f\d]{1,4})?(:[a-f\d]{1,4}){1,6}$').match

class classlist(list): pass

def spawn_later(seconds, target, *args, **kwargs):
    def wrap(*args, **kwargs):
        sleep(seconds)
        target(*args, **kwargs)
    thread.start_new_thread(wrap, args, kwargs)
