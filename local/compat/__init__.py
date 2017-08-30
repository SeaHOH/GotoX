# coding:utf-8

import sys

_ver = sys.version_info
PY3 = _ver[0] == 3
#PY35 = PY3 and _ver[1] == 5
if not PY3:
    from local import clogging as logging
    logging.error('请使用 Python 3 系列版本运行本程序！\n正在退出……')
    sys.exit(-1)

import queue as Queue
import _thread as thread
import http.server as BaseHTTPServer
import http.client as httplib
import urllib.request as urllib2
import urllib.parse as urlparse
import socketserver as SocketServer
from configparser import RawConfigParser, ConfigParser

#去掉 lower 以支持选项名称大小写共存
RawConfigParser.optionxform = lambda s, opt: opt

#默认编码
_read = ConfigParser.read
ConfigParser.read = lambda s, f, encoding='utf8': _read(s, f, encoding)

#可添加属性，强制使用 gevent 后已经不需要此 patch
#import socket
#class socketMod(socket.socket): pass
#socket.socket = socketMod

#重写了类方法 __getattr__ 时，修正 hasattr
hasattr = lambda o, a: getattr(o, a, None) != None
