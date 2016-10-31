# coding:utf-8

import sys
import socket
import errno
import random
from time import sleep
from .compat import thread
from . import clogging as logging

localhosts = ('127.0.0.1', 'localhost')
testhosts = (
    'appleid.apple.com',
    'www.bing.com',
    'www.microsoft.com',
    'www.apple.com',
    'www.baidu.com',
    'download.windowsupdate.com'
    )
AutoProxy = GAEProxy = None

def network_test(first=None):
    haserr = None
    b = None
    while not b:
        try:
            b = socket.gethostbyname(random.choice(testhosts))
        except:
            if not haserr:
                #发生网络故障停止代理线程
                if not first:
                    AutoProxy.__shutdown_request = True
                    GAEProxy.__shutdown_request = True
                haserr = True
                logging.error(u'网络现在不可用，将每 10 秒检测一次……')
            sleep(10)
    if haserr:
        logging.test(u'网络已经可以使用，%s', u'初始化继续……' if first else u'重新开始代理……')
    if haserr or first:
        try:
            AutoProxyHandler.localhosts = tuple(set(sum((x if isinstance(x, list) else [x] for x in socket.gethostbyname_ex(socket.gethostname())), list(localhosts))))
            AutoProxyHandler.localhosts = tuple(set([get_listen_ip()] + list(localhosts)))
        except:
            pass
    #重新开始代理线程
    if haserr and not first:
        thread.start_new_thread(AutoProxy.serve_forever, ())
        thread.start_new_thread(GAEProxy.serve_forever, ())

from .common import NetWorkIOError
from .GlobalConfig import GC
from .compat import SocketServer
from .ProxyHandler import AutoProxyHandler, GAEProxyHandler

class LocalProxyServer(SocketServer.ThreadingTCPServer):
    """Local Proxy Server"""
    allow_reuse_address = True

    def close_request(self, request):
        try:
            request.close()
        except Exception:
            pass

    def finish_request(self, request, client_address):
        try:
            self.RequestHandlerClass(request, client_address, self)
        except NetWorkIOError as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise

    def handle_error(self, *args):
        """make ThreadingTCPServer happy"""
        exc_info = sys.exc_info()
        error = exc_info and len(exc_info) and exc_info[1]
        if isinstance(error, NetWorkIOError) and len(error.args) > 1 and 'bad write retry' in error.args[1]:
            exc_info = error = None
        else:
            del exc_info, error
            SocketServer.ThreadingTCPServer.handle_error(self, *args)

AutoProxy = LocalProxyServer((GC.LISTEN_IP, GC.LISTEN_AUTO_PORT), AutoProxyHandler)
GAEProxy = LocalProxyServer((GC.LISTEN_IP, GC.LISTEN_GAE_PORT), GAEProxyHandler)
