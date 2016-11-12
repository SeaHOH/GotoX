# coding:utf-8

import os
app_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
cert_dir = os.path.join(app_root, 'cert')
config_dir = os.path.join(app_root, 'config')
data_dir = os.path.join(app_root, 'data')
py_dir = os.path.join(app_root, 'python')
web_dir = os.path.join(app_root, 'web')

import glob
import sys
packages = os.path.join(py_dir, 'site-packages')
#自带 py 已经添加
if os.path.dirname(sys.executable) != py_dir:
    #优先导入当前运行 py 已安装模块
    sys.path.append(packages)
    sys.path += glob.glob('%s/*.egg' % packages)

from local import clogging as logging
from time import time
from local.compat import thread

try:
    import OpenSSL
except ImportError:
    logging.error(u'无法找到 pyopenssl，请安装 pyopenssl-16.0.0 以上版本，或将相应 .egg 放到 %r 文件夹！', packages)
    sys.exit(-1)
import ssl
import socket
NetWorkIOError = (socket.error, ssl.SSLError, OSError) if not OpenSSL else (socket.error, ssl.SSLError, OpenSSL.SSL.Error, OSError)


class LRUCache(object):
    """Modified from http://pypi.python.org/pypi/lru/"""

    def __init__(self, max_items, expire=None):
        self.cache = {}
        self.max_items = int(max_items)
        self.expire = expire
        if expire:
            self.key_expire = {}
        self.key_order = []

    def __setitem__(self, key, value):
        self.cache[key] = value
        if self.expire:
            self.key_expire[key] = int(time()) + self.expire
        self._mark(key)

    def __getitem__(self, key):
        if self.expire:
            self._expire_check(key)
        value = self.cache[key]
        self._mark(key)
        return value

    def __contains__(self, key):
        if self.expire:
            self._expire_check(key)
        return key in self.cache

    def get(self, key, value=None):
        if key in self:
            return self[key]
        return value

    def _expire_check(self, key):
        if key in self.cache and time() > self.key_expire[key]:
            self.key_order.remove(key)
            del self.key_expire[key]
            del self.cache[key]

    def _mark(self, key):
        try:
            self.key_order.remove(key)
        except ValueError:
            pass
        self.key_order.append(key)
        while len(self.key_order) > self.max_items:
            key = self.key_order[0]
            del self.key_order[0]
            if self.expire:
                del self.key_expire[key]
            del self.cache[key]

    def clear(self):
        self.cache.clear()
        if self.expire:
            self.key_expire.clear()
        del self.key_order[:]

import string
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

import re
isip = re.compile(r'(\d+\.){3}\d+$|(([a-f\d]{1,4}:){1,6}|:)([a-f\d]{1,4})?(:[a-f\d]{1,4}){1,6}$').match
isipv4 = re.compile(r'(\d+\.){3}\d+$').match
isipv6 = re.compile(r'(([a-f\d]{1,4}:){1,6}|:)([a-f\d]{1,4})?(:[a-f\d]{1,4}){1,6}$').match

def spawn_later(seconds, target, *args, **kwargs):
    def wrap(*args, **kwargs):
        __import__('time').sleep(seconds)
        target(*args, **kwargs)
    thread.start_new_thread(wrap, args, kwargs)
