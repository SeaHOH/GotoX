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

localhosts = ('127.0.0.1', 'localhost', 'gotox.go')
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
    while not b:
        try:
            #通过域名解析测试网络状态
            b = socket.gethostbyname(random.choice(testhosts))
        except:
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
    try:
        AutoProxyHandler.localhosts = tuple(set(sum((x if isinstance(x, list) else [x] for x in socket.gethostbyname_ex(socket.gethostname())), list(localhosts))))
    except:
        try:
            AutoProxyHandler.localhosts = tuple(set([get_listen_ip()] + list(localhosts)))
        except:
            AutoProxyHandler.localhosts = localhosts
    else:
        try:
            AutoProxyHandler.localhosts = tuple(set([get_listen_ip()] + list(AutoProxyHandler.localhosts)))
        except:
            pass

class LocalProxyServer(SocketServer.ThreadingTCPServer):
    '''Local Proxy Server'''
    request_queue_size = 48
    is_not_online = True

    def bind_and_activate(self):
        self.socket = socket.socket(self.address_family, self.socket_type)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(self.server_address)
            self.socket.listen(self.request_queue_size)
        except:
            self.socket.close()
            raise
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
    AutoProxy = LocalProxyServer((GC.LISTEN_IP, GC.LISTEN_AUTO_PORT), AutoProxyAuthHandler, False)
    GAEProxy = LocalProxyServer((GC.LISTEN_IP, GC.LISTEN_GAE_PORT), GAEProxyAuthHandler, False)
else:
    AutoProxy = LocalProxyServer((GC.LISTEN_IP, GC.LISTEN_AUTO_PORT), AutoProxyHandler, False)
    GAEProxy = LocalProxyServer((GC.LISTEN_IP, GC.LISTEN_GAE_PORT), GAEProxyHandler, False)
