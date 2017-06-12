# coding:utf-8

import sys
import socket
import random
from time import sleep
from . import clogging as logging
from .compat import thread, SocketServer
from .common import NetWorkIOError, pass_errno
from .common.dns import reset_dns
from .common.proxy import get_listen_ip
from .GlobalConfig import GC

localhosts = ['127.0.0.1', '::1', 'localhost', 'gotox.go']
testhosts = (
    'appleid.apple.com',
    'www.bing.com',
    'www.microsoft.com',
    'www.apple.com',
    'www.baidu.com',
    'download.windowsupdate.com'
    )

def network_test(first=None):
    haserr = None
    b = None
    retry = True
    while b is None:
        try:
            #通过域名解析测试网络状态
            b = socket.gethostbyname(random.choice(testhosts))
        except:
            if retry:
                retry = False
                sleep(0.1)
                continue
            if not haserr:
                #发生网络故障停止代理线程
                if not first:
                    stop_proxyserver()
                haserr = True
                logging.error('网络现在不可用，将每 10 秒检测一次……')
            sleep(10)
    if haserr:
        logging.warning('网络已经可以使用，%s', '初始化继续……' if first else '重新开始代理……')
    if haserr or first:
        get_localhosts()
    #重新开始代理线程
    if haserr and not first:
        start_proxyserver()

def start_proxyserver():
    try:
        AutoProxy.bind_and_activate()
        GAEProxy.bind_and_activate()
        thread.start_new_thread(AutoProxy.serve_forever, ())
        thread.start_new_thread(GAEProxy.serve_forever, ())
    except SystemError as e:
        if '(libev) select: Unknown error' in repr(e):
            logging.error('如果出现此错误请告诉作者，谢谢！\nhttps://github.com/SeaHOH/GotoX/issues')
            sys.exit(-1)

def stop_proxyserver():
    AutoProxy.server_close()
    GAEProxy.server_close()
    reset_dns()

def get_localhosts():
    _localhosts = []
    try:
        _localhosts = sum((x if isinstance(x, list) else [x,] for x in socket.gethostbyname_ex(socket.gethostname())), _localhosts)
    except:
        pass
    AutoProxyHandler.localhosts = tuple(set(_localhosts + localhosts + get_listen_ip()))

IPPROTO_IPV6 = getattr(socket, 'IPPROTO_IPV6', 41)

class LocalProxyServer(SocketServer.ThreadingTCPServer):
    '''Local Proxy Server'''
    request_queue_size = 48
    is_not_online = True

    def __init__(self, server_address, RequestHandlerClass):
        SocketServer.BaseServer.__init__(self, server_address, RequestHandlerClass)
        #保存原始地址配置以重复使用
        self.orig_server_address = server_address

    def bind_and_activate(self):
        try:
            #优先尝试 IPv6
            sock = socket.socket(socket.AF_INET6, self.socket_type)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # server_address 为空时同时监听 v6 和 v4 端口，'::' 也可以但不这样使用
            if self.orig_server_address[0] == '':
                sock.setsockopt(IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind(self.orig_server_address)
        except:
            sock.close()
            sock = socket.socket(socket.AF_INET, self.socket_type)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(self.orig_server_address)
        self.socket = sock
        self.server_address = sock.getsockname()
        sock.listen(self.request_queue_size)
        self.is_not_online = False

    def server_close(self):
        self.is_not_online = True
        self.shutdown()
        self.socket.close()

    def close_request(self, request):
        try:
            request.close()
        except Exception:
            pass

    def finish_request(self, request, client_address):
        try:
            self.RequestHandlerClass(request, client_address, self)
        except NetWorkIOError as e:
            if e.args[0] not in pass_errno:
                raise

    def handle_error(self, *args):
        '''make ThreadingTCPServer happy'''
        exc_info = sys.exc_info()
        error = exc_info and len(exc_info) and exc_info[1]
        if isinstance(error, NetWorkIOError) and len(error.args) > 1 and 'bad write' in error.args[1]:
            exc_info = error = None
        else:
            del exc_info, error
            SocketServer.ThreadingTCPServer.handle_error(self, *args)

from .ProxyHandler import AutoProxyHandler, GAEProxyHandler

if GC.LISTEN_AUTH > 0:
    from .ProxyAuthHandler import AutoProxyAuthHandler, GAEProxyAuthHandler
    AutoProxy = LocalProxyServer((GC.LISTEN_IP, GC.LISTEN_AUTO_PORT), AutoProxyAuthHandler)
    GAEProxy = LocalProxyServer((GC.LISTEN_IP, GC.LISTEN_GAE_PORT), GAEProxyAuthHandler)
else:
    AutoProxy = LocalProxyServer((GC.LISTEN_IP, GC.LISTEN_AUTO_PORT), AutoProxyHandler)
    GAEProxy = LocalProxyServer((GC.LISTEN_IP, GC.LISTEN_GAE_PORT), GAEProxyHandler)
