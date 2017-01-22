# coding:utf-8

import sys
import os
import socket

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
    #可添加属性
    class socketMod(socket.socket): pass
    socket.socket = socketMod
    #默认编码
    _read = ConfigParser.read
    ConfigParser.read = lambda s, f, encoding='utf8': _read(s, f, encoding)
else:
    from local import clogging as logging
    logging.error('请使用 Python 3 系列版本运行本程序！\n正在退出……')
    sys.exit(-1)
