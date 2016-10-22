# coding:utf-8

import sys
import os
import socket
import ssl
import clogging as logging
PY3 = sys.version_info[0] == 3
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
    class socketMod(socket.socket): pass
    socket.socket = socketMod
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
try:
    import dnslib
except ImportError:
    dnslib = None
try:
    import OpenSSL
except ImportError:
    OpenSSL = None
try:
    import pacparser
except ImportError:
    pacparser = None
NetWorkIOError = (socket.error, ssl.SSLError, OSError) if not OpenSSL else (socket.error, ssl.SSLError, OpenSSL.SSL.Error, OSError)
