# coding:utf-8

import sys
import socket
import random
import collections
import dnslib
from time import sleep
from select import select
from . import clogging as logging
from .compat import thread, SocketServer
from .common import NetWorkIOError, pass_errno
from .common.dns import reset_dns
from .common.proxy import get_listen_ip
from .GlobalConfig import GC

localhosts = ['127.0.0.1', '::1', 'localhost', 'gotox.go']
test_dnsips = (
    #需用稳定快速的 IP 来测试，所以选国内的 DNS IP
    #电信 114
    #https://www.114dns.com/
    '114.114.114.114',
    '114.114.115.115',
    '114.114.114.110',
    '114.114.115.110',
    '114.114.114.119',
    '114.114.115.119',
    #阿里
    #http://www.alidns.com/
    '223.5.5.5',
    '223.6.6.6',
    #百度
    #http://dudns.baidu.com/intro/publicdns/
    '180.76.76.76',
    #腾讯
    #DNSPod
    #https://www.dnspod.cn/Products/Public.DNS
    '119.28.28.28',
    '119.29.29.29',
    '182.254.116.116',
    '182.254.118.118',
    #DNS 派
    #http://www.dnspai.com/public.html
    '101.226.4.6',
    '218.30.118.6',
    '123.125.81.6',
    '140.207.198.6',
    #OneDNS
    #http://www.onedns.net/
    '112.124.47.27',
    '114.215.126.16',
    '42.236.82.22',
    #CNNIC SDNS
    #http://public.sdns.cn/emergency_services.shtml
    '1.2.4.8',
    '210.2.4.8',
    )
test_hosts = [
    #伪装成 Win10 系统 DNS 请求
    #数据来自：https://github.com/crazy-max/WindowsSpyBlocker
    # hosts win10 extra (17/06/2017 20:57)
    'answers.microsoft.com',
    'apps.skype.com',
    'ars.smartscreen.microsoft.com',
    'az361816.vo.msecnd.net',
    'az512334.vo.msecnd.net',
    'blob.weather.microsoft.com',
    'candycrushsoda.king.com',
    'cdn.content.prod.cms.msn.com',
    'cdn.onenote.net',
    'choice.microsoft.com',
    'choice.microsoft.com.nsatc.net',
    'client.wns.windows.com',
    'client-s.gateway.messenger.live.com',
    'clientconfig.passport.net',
    'deploy.static.akamaitechnologies.com',
    'device.auth.xboxlive.com',
    'dmd.metaservices.microsoft.com',
    'dns.msftncsi.com',
    'feedback.microsoft-hohm.com',
    'feedback.search.microsoft.com',
    'feedback.windows.com',
    'g.live.com',
    'img-s-msn-com.akamaized.net',
    'insiderppe.cloudapp.net',
    'licensing.mp.microsoft.com',
    'login.live.com',
    'm.hotmail.com',
    'msftncsi.com',
    'officeclient.microsoft.com',
    'oneclient.sfx.ms',
    'pricelist.skype.com',
    'query.prod.cms.rt.microsoft.com',
    's.gateway.messenger.live.com',
    's0.2mdn.net',
    'sO.2mdn.net',
    'search.msn.com',
    'settings-ssl.xboxlive.com',
    'static.2mdn.net',
    'store-images.s-microsoft.com',
    'storeedgefd.dsx.mp.microsoft.com',
    'tile-service.weather.microsoft.com',
    'time.windows.com',
    'tk2.plt.msn.com',
    'ui.skype.com',
    'urs.smartscreen.microsoft.com',
    'wdcp.microsoft.com',
    'wscont.apps.microsoft.com',
    'www.msftconnecttest.com',
    'www.msftncsi.com',
    # hosts win10 update (21/05/2017 15:57)
    '000202-1.l.windowsupdate.com',
    '0002c3-1.l.windowsupdate.com',
    '0002fd-1.l.windowsupdate.com',
    '00149f-1.l.windowsupdate.com',
    '001891-1.l.windowsupdate.com',
    '002062-1.l.windowsupdate.com',
    '0021d0-1.l.windowsupdate.com',
    'au.download.windowsupdate.com',
    'au.v4.download.windowsupdate.com',
    'ctldl.windowsupdate.com',
    'displaycatalog.mp.microsoft.com',
    'dl.delivery.mp.microsoft.com',
    'download.microsoft.com',
    'download.windowsupdate.com',
    'emdl.ws.microsoft.com',
    'fe2.update.microsoft.com',
    'fe2.update.microsoft.com.akadns.net',
    'fe3.delivery.dsp.mp.microsoft.com.nsatc.net',
    'fe3.delivery.mp.microsoft.com',
    'fg.ds.b1.download.windowsupdate.com',
    'fg.v4.download.windowsupdate.com',
    'microsoftwindowsupdate.net',
    'sls.update.microsoft.com',
    'sls.update.microsoft.com.akadns.net',
    'statsfe2.update.microsoft.com.akadns.net',
    'statsfe1.ws.microsoft.com',
    'statsfe2.ws.microsoft.com',
    'tlu.dl.delivery.mp.microsoft.com',
    'v4.download.windowsupdate.com',
    'windowsupdate.com',
    'windowupdate.org',
    ]
#生成乱序 DNS 服务器列表
_test_dnsservers = [(ip, 53) for ip in test_dnsips]
random.shuffle(_test_dnsservers)
#生成乱序 DNS 请求数据列表
#只请求 A 类型，增加快速响应机率
random.shuffle(test_hosts)
test_qdata_list = collections.deque(dnslib.DNSRecord.question(qname).pack() for qname in test_hosts)
#生成测试用 UDP 套接字
test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
del test_dnsips, test_hosts
test_max_times = len(_test_dnsservers)
test_dnsservers = None
test_qdata = None

def network_test(first=None):
    global test_dnsservers, test_qdata
    ok = None
    haserr = None
    ins = True
    sent = []
    times = 0
    #清理过期响应
    while ins:
        ins, _, _ = select([test_sock], [], [], 0.01)
        if ins:
            test_sock.recvfrom(512)
    #通过域名解析测试网络状态
    while ok is None:
        times += 1
        if times > test_max_times:
            if not haserr:
                #发生网络故障停止代理线程
                if not first:
                    stop_proxyserver()
                haserr = True
                logging.error('网络现在不可用，将每 10 秒检测一次……')
            sleep(10)
        #更换下一个域名的请求数据
        if not test_dnsservers:
            test_dnsservers = _test_dnsservers.copy()
            test_qdata = test_qdata_list.pop()
            test_qdata_list.appendleft(test_qdata)
        dnsserver = test_dnsservers.pop()
        sent.append(dnsserver)
        test_sock.sendto(test_qdata, dnsserver)
        ins, _, _ = select([test_sock], [], [], 0.5)
        if ins:
            _, peername = test_sock.recvfrom(512)
            if peername in sent:
                ok = True
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
    AutoProxyHandler.bufsize = AutoProxy.socket.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)

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
        server_listen_ip = self.orig_server_address[0]
        try:
            #优先尝试 IPv6
            sock = socket.socket(socket.AF_INET6)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # server_address 为空时同时监听 v6 和 v4 端口，'::' 也可以但不这样使用
            if server_listen_ip == '':
                sock.setsockopt(IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind(self.orig_server_address)
        except:
            sock.close()
            sock = socket.socket(socket.AF_INET)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(self.orig_server_address)
        #本机关闭监听端口接收缓冲
        if server_listen_ip in ('127.0.0.1', '::1'):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        #关闭 nagle's algorithm 算法
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
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
