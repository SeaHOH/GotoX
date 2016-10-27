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
sys.path.insert(0, packages)
#sys.path = glob.glob('%s/*.egg' % packages) + sys.path

import clogging as logging
from time import time, sleep
from compat import thread, Queue

try:
    import OpenSSL
except ImportError:
    logging.error(u'无法找到 pyopenssl，请安装 pyopenssl-16.0.0 以上版本，或将相应 .egg 放到 %r 文件夹！', packages)
    sys.exit(-1)
import ssl
import socket
NetWorkIOError = (socket.error, ssl.SSLError, OSError) if not OpenSSL else (socket.error, ssl.SSLError, OpenSSL.SSL.Error, OSError)


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

import random
def onlytime():
    return int(time())+random.random()

class testip():
    lastupdata = time()
    running = False
    lasttest = lastupdata - 30
    lastactive = None
    qcount = 0
    tested = {}
    queobj = Queue.Queue()

import re
isip = re.compile(r'(\d+\.){3}\d+$|(([a-f\d]{1,4}:){1,6}|:)([a-f\d]{1,4})?(:[a-f\d]{1,4}){1,6}$').match
isipv4 = re.compile(r'(\d+\.){3}\d+$').match
isipv6 = re.compile(r'(([a-f\d]{1,4}:){1,6}|:)([a-f\d]{1,4})?(:[a-f\d]{1,4}){1,6}$').match

def spawn_later(seconds, target, *args, **kwargs):
    def wrap(*args, **kwargs):
        sleep(seconds)
        return target(*args, **kwargs)
    return thread.start_new_thread(wrap, args, kwargs)
