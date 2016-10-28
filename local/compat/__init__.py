# coding:utf-8

import sys
import os
import socket
import ssl
_ver = sys.version_info
PY3 = _ver[0] == 3
PY35 = PY3 and _ver[1] == 5
if PY3:
    import queue as Queue
    import _thread as thread
    import http.server as BaseHTTPServer
    import http.client as httplib
    import urllib.request as urllib2
    import urllib.parse as urlparse
    import socketserver as SocketServer
    from configparser import ConfigParser
    xrange = range
    exc_clear = lambda: None
    #可添加属性
    class socketMod(socket.socket): pass
    socket.socket = socketMod
    #默认编码
    _read = ConfigParser.read
    ConfigParser.read = lambda s, f, encoding='utf8': _read(s, f, encoding)
else:
    import Queue
    import thread
    import BaseHTTPServer
    import httplib
    import urllib2
    import urlparse
    import SocketServer
    from ConfigParser import ConfigParser
    xrange = xrange
    exc_clear = sys.exc_clear
