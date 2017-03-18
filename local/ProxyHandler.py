# coding:utf-8

import os
import sys
import errno
import re
import html
import ssl
import socket
import random
import socks
import threading
from . import CertUtil
from . import clogging as logging
from select import select
from time import time, sleep
from functools import partial
from .compat import BaseHTTPServer, urlparse, thread
from .common import (
    web_dir,
    NetWorkIOError,
    get_refreshtime,
    LRUCache,
    message_html,
    isip
    )
from .common.dns import set_DNS, dns_resolve
from .common.proxy import parse_proxy
from .common.region import isdirect
from .GlobalConfig import GC
from .GAEUpdate import testip, testipuseable
from .HTTPUtil import (
    tcp_connection_cache,
    ssl_connection_cache,
    http_gws,
    http_nor
    )
from .RangeFetch import RangeFetch
from .GAEFetch import qGAE, gae_urlfetch
from .FilterUtil import (
    filters_cache,
    ssl_filters_cache,
    get_action,
    get_connect_action
    )

normcookie = partial(re.compile(r',(?= [^ =]+(?:=|$))').sub, r'\r\nSet-Cookie:')
normattachment = partial(re.compile(r'(?<=filename=)([^"\']+)').sub, r'"\1"')
getbytes = re.compile(r'bytes=(\d+)-(\d*)').search
getstart = re.compile(r'bytes (\d+)-.+').search

skip_request_headers = (
    'Vary',
    'Via',
    'X-Forwarded-For',
    'Proxy-Authorization',
    'Proxy-Connection',
    'Upgrade',
    'X-Chrome-Variations',
    'Connection',
    #'Cache-Control'
    )

skip_response_headers = (
    'Content-Length',
    'Transfer-Encoding',
    'Content-MD5',
    'Set-Cookie',
    'Upgrade'
    )

class AutoProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    nLock = threading.Lock()
    nappid = 0

    fwd_timeout = GC.LINK_FWDTIMEOUT
    listen_port = GC.LISTEN_GAE_PORT, GC.LISTEN_AUTO_PORT
    CAPath = '/ca', '/cadownload'

    #可修改
    ssl_context_cache = LRUCache(32)
    badhost = LRUCache(16, 120)
    badappids = LRUCache(len(GC.GAE_APPIDS))
    maxsize = int(GC.GAE_MAXSIZE or 1024*1024*4)

    #默认值
    ssl = False
    fakecert = False
    url = None
    url_parts = None

    def setup(self):
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)
        self.write = lambda d: self.wfile.write(d if isinstance(d, bytes) else d.encode())

    def do_action(self):
        '''Record gws connections active time'''
        if self.action in ('do_DIRECT', 'do_FORWARD'):
            self.hostname = hostname = set_DNS(self.host, self.target)
            if hostname is None:
                logging.error('无法解析主机：%r，路径：%r，请检查是否输入正确！', self.host, self.path)
                #加密请求就不返回提示页面了，搞起来太麻烦
                if not self.ssl:
                    self.write(b'HTTP/1.1 504 Resolve Failed\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n')
                    self.write(message_html('504 解析失败', '504 解析失败<p>主机名 %r 无法解析，请检查是否输入正确！' % self.host))
                return 
            elif hostname.startswith('google'):
                testip.lastactive = time()
        elif self.action == 'do_GAE':
            testip.lastactive = time()
        getattr(self, self.action)()

    def _do_CONNECT(self):
        host = self.headers.get('Host', '')
        port = None
        #从命令获取主机、端口
        chost, cport = self.parse_netloc(self.path)
        #确定主机，优先 Host 头域
        if host:
            #从头域获取主机、端口
            host, port = self.parse_netloc(host)
            #排除某些程序把代理当成主机名
            if chost and port in self.listen_port and host.startswith(self.localhosts):
                self.host = chost
                port = cport
                self.headers.replace_header('Host', chost)
            else:
                self.host = host
        else:
            self.host = chost
        self.port = int(port or cport or 443)
        #某些 http 链接也可能会使用 CONNECT 方法
        #认为非 80 端口都是加密链接
        self.ssl = self.port != 80

    def do_CONNECT(self):
        '''handle CONNECT cmmand, do a filtered action'''
        self._do_CONNECT()
        self.action, self.target = get_connect_action(self.ssl, self.host)
        #本地地址
        if self.host.startswith(self.localhosts):
            self.action = 'do_FAKECERT'
        self.fakecert = self.ssl and self.action == 'do_FAKECERT'
        self.do_action()

    def _do_METHOD(self):
        host = self.headers.get('Host', '')
        port = None
        path = self.path
        url_parts = urlparse.urlsplit(path)
        #从命令获取主机、端口
        chost, cport = self.parse_netloc(url_parts.netloc)
        #确定主机，优先 Host 头域
        if host:
            #从头域获取主机、端口
            host, port = self.parse_netloc(host)
            #排除某些程序把代理当成主机名
            if chost and port in self.listen_port and host.startswith(self.localhosts):
                self.host = host = chost
                port = cport
                self.headers.replace_header('Host', chost)
            else:
                self.host = host
        else:
            self.host = host = chost
        #确定协议
        if url_parts.scheme:
            scheme = url_parts.scheme
            #认为只有 https 协议才是加密链接
            self.ssl = scheme == 'https'
        else:
            scheme = 'https' if self.ssl else 'http'
        #确定端口
        self.port = int(port or cport or self.ssl and 443 or 80)
        #确定网址、去掉可能存在的端口
        self.url_parts = url_parts = urlparse.SplitResult(scheme, host, url_parts.path, url_parts.query, '')
        self.url = url_parts.geturl()
        #确定路径
        if path[0] != '/':
            self.path = path = self.url[self.url.find('/', self.url.find('//')+3):]

    def do_METHOD(self):
        '''handle others cmmand, do a filtered action'''
        self._do_METHOD()
        host = self.host
        path = self.path
        #本地地址
        if host.startswith(self.localhosts):
            #发送证书
            if path.lower() in self.CAPath:
                return self.send_CA()
            return self.do_LOCAL()
        self.action, self.target = get_action(self.url_parts.scheme, host, path[1:], self.url)
        #根据伪造证书与否自动将转发转换为直连
        if self.fakecert and self.action == 'do_FORWARD':
            self.action = 'do_DIRECT'
        self.do_action()

    do_GET = do_METHOD
    do_PUT = do_METHOD
    do_POST = do_METHOD
    do_HEAD = do_METHOD
    do_DELETE = do_METHOD
    do_OPTIONS = do_METHOD
    do_PATCH = do_METHOD

    def write_response_content(self, data, response, need_chunked):
        if hasattr(response, 'data'):
            # goproxy 服务端错误信息处理预读数据
            if data:
                self.write(data)
            return len(data), None
        wrote = 0
        err = None
        try:
            if not data:
                data = response.read(8192)
            while data:
                if need_chunked:
                    self.write(hex(len(data))[2:].encode())
                    self.write(b'\r\n')
                    self.write(data)
                    self.write(b'\r\n')
                else:
                    self.write(data)
                wrote += len(data)
                data = response.read(8192)
        except Exception as e:
            err = e
        finally:
            if need_chunked:
                self.write(b'0\r\n\r\n')
            return wrote, err

    def handle_request_headers(self):
        request_headers = dict((k.title(), v) for k, v in self.headers.items() if k.title() not in skip_request_headers)
        connection = self.headers.get('Connection') or self.headers.get('Proxy-Connection')
        if connection:
            request_headers['Connection'] = connection
        payload = b''
        if 'Content-Length' in request_headers:
            try:
                payload = self.rfile.read(int(request_headers['Content-Length']))
            except NetWorkIOError as e:
                logging.error('%s "%s %s" 附加请求内容读取失败：%r', self.address_string(), self.command, self.url, e)
                raise
        return request_headers, payload

    def handle_response_headers(self, response):
        response_headers = dict((k.title(), v) for k, v in response.getheaders() if k.title() not in skip_response_headers)
        length = response.getheader('Content-Length')
        if hasattr(response, 'data'):
            # goproxy 服务端错误信息处理预读数据
            data = response.data
            length = str(len(data))
            response_headers['Content-Type'] = 'text/html; charset=UTF-8'
            self.close_connection = True
        else:
            data = response.read(8192)
        need_chunked = data and not length # response 中的数据已经正确解码
        if need_chunked:
            response_headers['Transfer-Encoding'] = 'chunked'
        elif length:
            response_headers['Content-Length'] = length
        #无内容且发生错误时关闭链接
        elif response.status in (400, 403, 405, 413, 414, 415) or response.status >= 500:
            self.close_connection = True
        else:
            response_headers['Content-Length'] = 0
        cookies = response.headers.get_all('Set-Cookie')
        if cookies:
            if self.action == 'do_GAE' and len(cookies) == 1:
                response_headers['Set-Cookie'] = normcookie(cookies[0])
            else:
                response_headers['Set-Cookie'] = '\r\nSet-Cookie: '.join(cookies)
        if 'Content-Disposition' in response_headers:
            response_headers['Content-Disposition'] = normattachment(response_headers['Content-Disposition'])
        headers_data = 'HTTP/1.1 %s %s\r\n%s\r\n' % (response.status, response.reason, ''.join('%s: %s\r\n' % x for x in response_headers.items()))
        self.write(headers_data)
        if response.status in (300, 301, 302, 303, 305, 307) and 'Location' in response_headers:
            logging.info('%r 返回包含重定向 %r', self.url, response_headers['Location'])
            self.close_connection = True
        logging.debug('headers_data=%s', headers_data)
        if response.status == 304:
            logging.test('%s "%s %s %s HTTP/1.1" %s %s', self.address_string(response), self.action[3:], self.command, self.url, response.status, length or '-')
        else:
            logging.info('%s "%s %s %s HTTP/1.1" %s %s', self.address_string(response), self.action[3:], self.command, self.url, response.status, length or '-')
        return data, need_chunked

    def do_DIRECT(self):
        '''Direct http relay'''
        hostname = self.hostname
        http_util = http_gws if hostname.startswith('google') else http_nor
        host = self.host
        response = None
        noerror = True
        self.close_connection = 2
        request_headers, payload = self.handle_request_headers()
        try:
            connection_cache_key = '%s:%d' % (hostname, self.port)
            response = http_util.request(self, payload, request_headers, connection_cache_key=connection_cache_key, timeout=self.fwd_timeout)
            if not response:
                if self.target is not None or self.url_parts.path.endswith('ico') or isdirect(host):
                    #非默认规则、网站图标、直连 IP
                    logging.warn('do_DIRECT "%s %s" 失败，返回 404', self.command, self.url)
                    self.write('HTTP/1.1 404 %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s' % self.responses[404])
                    return
                else:
                    logging.warn('do_DIRECT "%s %s" 失败，尝试使用 "GAE" 规则。', self.command, self.url)
                    return self.go_GAE()
            #拒绝服务、非直连 IP
            if response.status == 403 and not isdirect(host):
                logging.warn('do_DIRECT "%s %s" 链接被拒绝，尝试使用 "GAE" 规则。', self.command, self.url)
                return self.go_GAE()
            data, need_chunked = self.handle_response_headers(response)
            _, err = self.write_response_content(data, response, need_chunked)
            if err:
                raise err
        except NetWorkIOError as e:
            noerror = False
            #链接重置、非直连 IP
            if e.args[0] == errno.ECONNRESET and not isdirect(host):
                logging.warning('%s do_DIRECT "%s %s" 链接被重置，尝试使用 "GAE" 规则。', self.address_string(response), self.command, self.url)
                return self.go_GAE()
            elif e.args[0] in (errno.WSAENAMETOOLONG, errno.ENAMETOOLONG):
                logging.error('%s do_DIRECT "%s %s" 失败：%r，返回 408', self.address_string(response), self.command, self.url, e)
                self.write('HTTP/1.1 408 %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s' % self.responses[408])
                #logging.warn('request "%s %s" failed:%s, try addto `withgae`', self.command, self.url, e)
                #self.go_GAE()
            elif e.args[0] not in (errno.ECONNABORTED, errno.EPIPE):
                raise
        except Exception as e:
            noerror = False
            logging.warning('%s do_DIRECT "%s %s" 失败：%r', self.address_string(response), self.command, self.url, e)
            raise
        finally:
            if response:
                response.close()
                if noerror:
                    if self.close_connection is 2:
                        connection = response.getheader('Connection')
                        if connection:
                            self.close_connection = connection.lower() == 'close'
                    #放入套接字缓存
                    if self.ssl:
                        if GC.GAE_KEEPALIVE or not connection_cache_key.startswith('google'):
                            #放入套接字缓存
                            ssl_connection_cache[connection_cache_key].append((time(), response.sock))
                        else:
                            #干扰严重时考虑不复用 google 链接
                            response.sock.close()
                    else:
                        tcp_connection_cache[connection_cache_key].append((time(), response.sock))

    def do_GAE(self):
        '''GAE http urlfetch'''
        if self.command not in ('GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'PATCH'):
            logging.warn('GAE 不支持 "%s %s"，转用 DIRECT', self.command, self.url)
            self.action = 'do_DIRECT'
            self.target = dns_resolve(self.host)
            return self.do_action()
        request_headers, payload = self.handle_request_headers()
        request_range = request_headers.get('Range', '')
        if request_range:
            range_start, range_end = tuple((x and int(x) or 0) for x in getbytes(request_range).group(1, 2))
            self.range_end = range_end
            range_length = range_end + 1 - range_start
        else:
            self.range_end = range_start = range_end = range_length = 0
        need_autorange =  not (range_length > 0 and range_length < self.maxsize or 'range=' in self.url_parts.query or self.command == 'HEAD')
        if self.url_parts.path.endswith(GC.AUTORANGE_ENDSWITH):
            need_autorange = True
            logging.info('发现[autorange]匹配：%r', self.url)
            if range_end:
                range_end = min(range_start+GC.AUTORANGE_FIRSTSIZE-1, range_end)
            else:
                range_end = range_start+GC.AUTORANGE_FIRSTSIZE-1
            request_headers['Range'] = 'bytes=%d-%d' % (range_start, range_end)
        errors = []
        headers_sent = False
        #为 GAE 代理请求网址加上端口
        n = self.url.find('/', self.url.find('//')+3)
        url = '%s:%s%s' % (self.url[:n], self.port, self.path)
        need_chunked = False
        start = range_start
        for retry in range(GC.GAE_FETCHMAX):
            if retry > 0 and payload:
                logging.warning('do_GAE 由于有上传数据 "%s %s" 终止重试', self.command, self.url)
                return
            with self.nLock:
                nappid = self.__class__.nappid
                while True:
                    nappid += 1
                    if nappid >= len(GC.GAE_APPIDS):
                        nappid = 0
                    appid = GC.GAE_APPIDS[nappid]
                    contains, expired = self.badappids.getstate(appid)
                    if contains and expired:
                        for i in range(GC.GAE_MAXREQUESTS):
                            qGAE.put(True)
                    if not contains or expired:
                        break
                self.__class__.nappid = nappid
            noerror = True
            data = None
            response = None
            try:
                response = gae_urlfetch(self.command, url, request_headers, payload, appid)
                if response is None:
                    if retry == GC.GAE_FETCHMAX - 1:
                        self.write(b'HTTP/1.0 502\r\nContent-Type: text/html\r\n\r\n')
                        self.write(message_html('502 资源获取失败', '本地从 GAE 获取 %r 失败' % self.url, str(errors)))
                        return
                    else:
                        logging.warning('do_GAE 超时，url=%r，重试', self.url)
                        sleep(0.5)
                        continue
                #处理 GoProxy 错误信息
                elif response.reason == 'debug error':
                    data = response.read().decode()
                    #密码错误
                    if response.app_status == 403:
                        logging.warning('GAE：%r 密码错误！你设置的密码是： %r', appid, GC.GAE_PASSWORD)
                        data = '<h1>******   GAE：%r 密码错误！请修改后重试。******</h1>' % appid
                    # GoProxy 临时错误，重试
                    elif response.app_status == 502:
                        if 'DEADLINE_EXCEEDED' in data:
                            logging.warning('GAE：%r urlfetch %r 返回 DEADLINE_EXCEEDED，重试', appid, self.url)
                            continue
                        elif 'ver quota' in data:
                            logging.warning('GAE：%r urlfetch %r 返回 over quota，重试', appid, self.url)
                            self.badappids.set(appid, True, 60)
                            for i in range(GC.GAE_MAXREQUESTS):
                                qGAE.get()
                            continue
                        elif 'urlfetch: CLOSED' in data:
                            logging.warning('GAE：%r urlfetch %r 返回 urlfetch: CLOSED，重试', appid, self.url)
                            sleep(0.5)
                            continue
                    # GoProxy 服务端版本可能不兼容
                    elif response.app_status == 400:
                        logging.error('%r 部署的可能是 GotoX 不兼容的 GoProxy 服务端版本，如果这条错误反复出现请将之反馈给开发者。', appid)
                        data = ('<h2>GotoX：%r 部署的可能是 GotoX 不兼容的 GoProxy 服务端版本，如果这条错误反复出现请将之反馈给开发者。<h2>\n'
                                '错误信息：\n%r' % (appid, data))
                    response.data = data.encode()
                #网关错误（Gateway Timeout｜Bad Gateway）
                elif response.app_status in (502, 504):
                    logging.warning('do_GAE 网关错误，url=%r，重试', self.url)
                    sleep(0.5)
                    continue
                #无法提供 GAE 服务（Found｜Forbidden｜Method Not Allowed）
                elif response.app_status in (302, 403, 405):
                    #检查 IP 可用性
                    if not testipuseable(response.xip[0]):
                        noerror = False
                    continue
                #当前 appid 流量完结(Service Unavailable)
                elif response.app_status == 503:
                    if len(GC.GAE_APPIDS) - len(self.badappids) <= 1:
                        logging.error('全部的 APPID 流量都使用完毕')
                    else:
                        logging.info('当前 appid[%s] 流量使用完毕，切换下一个…', appid)
                    self.badappids.set(appid, True, get_refreshtime())
                    for i in range(GC.GAE_MAXREQUESTS):
                        qGAE.get()
                    self.do_GAE()
                    return
                #服务端出错（Internal Server Error）
                elif response.app_status == 500:
                    logging.warning('"%s %s" GAE_APP 发生错误，重试', self.command, self.url)
                    continue
                #服务端不兼容（Bad Request｜Unsupported Media Type）
                elif response.app_status in (400, 415):
                    logging.error('%r 部署的可能是 GotoX 不兼容的服务端，如果这条错误反复出现请将之反馈给开发者。', appid)
                # appid 不存在（Not Found）
                elif response.app_status == 404:
                    if testipuseable(response.xip[0]):
                        if len(GC.GAE_APPIDS) > 1:
                            GC.GAE_APPIDS.remove(appid)
                            for i in range(GC.GAE_MAXREQUESTS):
                                qGAE.get()
                            logging.warning('APPID %r 不存在，将被移除', appid)
                            self.do_GAE()
                        else:
                            logging.error('APPID %r 不存在，请将你的 APPID 填入 Config.ini 中', appid)
                            self.write(b'HTTP/1.0 502\r\nContent-Type: text/html\r\n\r\n')
                            self.write(message_html('404 Appid 不存在', 'Appid %r 不存在' % appid, '请编辑 Config.ini 文件，将你的 APPID 填入其中。'))
                        return
                    else:
                        #只是 IP 错误，继续
                        noerror = False
                        continue
                #输出服务端返回的错误信息
                if response.app_status != 200:
                    self.close_connection = True
                    if not headers_sent:
                        data, need_chunked = self.handle_response_headers(response)
                        self.write_response_content(data, response, need_chunked)
                    return
                #与已经写入的头部状态不同
                if headers_sent and headers_sent != response.status:
                    continue
                #发生异常时的判断条件，放在 read 操作之前
                self.close_connection = 2
                content_range = response.getheader('Content-Range')
                accept_ranges = response.getheader('Accept-Ranges')
                if content_range:
                    start = int(getstart(content_range).group(1)[0])
                # 服务器不支持 Range 且错误返回成功状态
                if range_start > 0 and response.status != 206 and response.status < 300:
                    response.status = 416
                #第一个响应，不用重复写入头部
                if not headers_sent:
                    #开始自动多线程（Partial Content）
                    if response.status == 206 and need_autorange:
                        rangefetch = RangeFetch(self, url, request_headers, payload, response)
                        response = None
                        return rangefetch.fetch()
                    data, need_chunked = self.handle_response_headers(response)
                    headers_sent = response.status
                # Range 范围错误，直接放弃（Requested Range Not Satisfiable）
                if response.status == 416:
                    return
                wrote, err = self.write_response_content(data, response, need_chunked)
                start += wrote
                if err:
                    raise err
                return
            except Exception as e:
                noerror = False
                errors.append(e)
                if e.args[0] in (10053, ) or isinstance(e, NetWorkIOError) and e.args[-1] and 'bad write' in e.args[-1]:
                    #本地链接终止
                    logging.debug('do_GAE %r 返回 %r，终止', self.url, e)
                    return
                elif retry < GC.GAE_FETCHMAX - 1:
                    if accept_ranges is 'bytes':
                        #重试支持 Range 的失败请求
                        request_headers['Range'] = 'bytes=%d-%s' % (start, self.range_end or '')
                    elif start > 0:
                        #终止不支持 Range 的且中途失败的请求
                        logging.error('%s do_GAE "%s %s" 失败：%r', self.address_string(response), self.command, self.url, e)
                        return
                    logging.warning('%s do_GAE "%s %s" 返回：%r，重试', self.address_string(response), self.command, self.url, e)
                else:
                    #请求失败
                    logging.exception('%s do_GAE "%s %s" 失败：%r', self.address_string(response), self.command, self.url, e)
            finally:
                qGAE.put(True)
                if response:
                    response.close()
                    if noerror:
                        if self.close_connection is 2:
                            #connection = self.headers.get('Connection') or self.headers.get('Proxy-Connection')
                            connection = response.getheader('Connection')
                            if connection:
                                self.close_connection = connection.lower() == 'close'
                        if GC.GAE_KEEPALIVE:
                            #放入套接字缓存
                            ssl_connection_cache['google_gws:443'].append((time(), response.sock))
                        else:
                            #干扰严重时考虑不复用
                            response.sock.close()

    def do_FORWARD(self):
        '''Forward socket'''
        hostname = self.hostname
        http_util = http_gws if hostname.startswith('google') else http_nor
        host, port = self.host, self.port
        hostip = None
        remote = None
        if not GC.PROXY_ENABLE:
            connection_cache_key = '%s:%d' % (hostname, port)
            for i in range(2):
                try:
                    remote = http_util.create_connection((host, port), connection_cache_key, self.fwd_timeout, self.ssl)
                    break
                except NetWorkIOError as e:
                    logging.warning('%s 转发到 %r 失败：%r', e.xip[0], self.url or host, e)
            if hasattr(remote, 'fileno'):
                # reset timeout default to avoid long http upload failure, but it will delay timeout retry :(
                remote.settimeout(None)
        else:
            hostip = random.choice(dns_resolve(host))
            remote = http_util.create_connection((hostip, int(port)), self.fwd_timeout, self.ssl)
        if remote is None:
            if not isdirect(host):
                if self.command == 'CONNECT':
                    if self.ssl:
                        logging.warning('%s do_FORWARD 链接远程主机 (%r, %r) 失败，尝试使用 "FAKECERT" 规则。', hostip or self.address_string(), host, port)
                        self.go_FAKECERT()
                    else:
                        logging.warning('%s do_FORWARD 链接远程主机 (%r, %r) 失败，尝试跳过 "CONNECT" 命令。', hostip or self.address_string(), host, port)
                        self.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                else:
                    logging.warning('%s do_FORWARD 链接远程主机 (%r, %r) 失败，尝试使用 "GAE" 规则。', hostip or self.address_string(), host, port)
                    self.go_GAE()
            return
        logging.info('%s "FWD %s %s:%d HTTP/1.1" - -', remote.xip[0], self.command, host, port)
        self.forward_socket(remote)

    def do_PROXY(self):
        '''Forward to proxy server'''
        proxytype, proxyuser, proxypass, proxyaddress = parse_proxy(self.target)
        proxyhost, _, proxyport = proxyaddress.rpartition(':')
        proxyport = int(proxyport)
        if proxytype:
            proxytype = proxytype.upper()
        if proxytype not in socks.PROXY_TYPES:
            proxytype = 'HTTP'
        proxy = socks.socksocket()
        proxy.set_proxy(socks.PROXY_TYPES[proxytype], proxyhost, proxyport, True, proxyuser, proxypass)
        proxy.connect((self.host, self.port))
        logging.info('%s:%d 转发 "%s %s" 到 [%s] 代理', proxyhost, proxyport, self.command, self.url or self.path, proxytype)
        self.forward_socket(proxy)

    def do_REDIRECT(self):
        '''Redirect http'''
        target = self.target
        if not target:
            return
        logging.info('%s 重定向 %r 到 %r', self.address_string(), self.url, target)
        self.write('HTTP/1.1 301 Moved Permanently\r\nLocation: %s\r\n\r\n' % target)

    def do_IREDIRECT(self):
        '''Redirect http without 30X'''
        target = self.target
        if not target:
            return
        if target.startswith('file://'):
            filename = target.lstrip('file:').lstrip('/')
            logging.info('%s %r 匹配本地文件 %r', self.address_string(), self.url, filename)
            self.do_LOCAL(filename)
        else:
            logging.info('%s 内部重定向 %r 到 %r', self.address_string(), self.url, target)
            #重设网址
            origurl = self.url
            self.url = target
            #重设主机
            self.url_parts = url_parts = urlparse.urlsplit(target)
            self.headers['Host'] = self.host = url_parts.netloc
            #重设协议
            origssl = self.ssl
            self.ssl = url_parts.scheme == 'https'
            #重设端口
            if origssl != self.ssl:
                if self.ssl and self.port == 80:
                    self.port = 443
                elif origssl and self.port == 443:
                    self.port = 80
                else:
                    #不改变非标准端口
                    self.ssl = origssl
            #重设路径
            self.path = target[target.find('/', target.find('//')+3):]
            #重设 action
            self.action, self.target = get_action(self.url_parts.scheme, self.host, self.path[1:], target)
            #从非加密链接内部重定向到加密链接，结果匹配转发规则
            if not origssl and self.ssl and self.action == 'do_FORWARD':
                logging.error('规则冲突，请把当前第一个匹配以下网址的内部重定向规则改为一般重定向规则（推荐）：\n%s', origurl)
                logging.error('或者，把当前第一个匹配以下网址的转发规则改为直连规则（不建议）：\n%s', target)
                return
            self.do_action()

    def do_FAKECERT(self):
        '''Deploy a fake cert to client'''
        #logging.debug('%s "AGENT %s %s:%d HTTP/1.1" - -', self.address_string(), self.command, self.host, self.port)
        self.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        ssl_context = self.get_ssl_context()
        try:
            ssl_sock = ssl_context.wrap_socket(self.connection, server_side=True)
        except Exception as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET):
                logging.exception('伪造加密链接失败：host=%r，%r', self.host, e)
            return
        #停止非加密读写
        self.finish()
        #加载加密套接字
        self.request = ssl_sock
        self.setup()
        try:
            #恢复正常处理流程
            self.handle()
        finally:
            #关闭加密套接字
            ssl_sock.shutdown(socket.SHUT_WR)
            ssl_sock.close()

    def list_dir(self, path, displaypath):
        '''列表目录后将内容写入 html'''
        #改自 http.server.SimpleHTTPRequestHandler.list_directory
        try:
            namelist = os.listdir(path)
        except OSError as e:
            return e
        namelist.sort(key=lambda a: a.lower())
        r = []
        displaypath = html.escape(displaypath)
        # Win NT 不需要编码
        enc = None if os.name == 'nt' else sys.getfilesystemencoding()
        #设置为 str.encode 的默认值 UTF-8
        enc = enc or 'UTF-8'
        title = 'GotoX web 目录列表 - %s' % displaypath
        r.append('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" '
                 '"http://www.w3.org/TR/html4/strict.dtd">\n'
                 '<html>\n<head>\n'
                 '<meta http-equiv="Content-Type" '
                 'content="text/html; charset=%s">\n'
                 '<title>%s</title>\n'
                 '</head>\n<body>' % (enc, title))
        if displaypath == '/':
            r.append('<h2>\n'
                     '&diams;<a href="%s">点击安装 GotoX CA 证书到浏览器</a>\n'
                     '&diams;<a href="%s">点击下载 GotoX CA 证书</a>\n'
                     '</h2>\n<hr>' % self.CAPath)
        r.append('<h1>%s</h1>\n<hr>\n<ul>' % title)
        if displaypath != '/':
            r.append('<li><a href="%s/">返回上级目录</a><big>&crarr;</big></li>'
                     % displaypath[:-1].rpartition('/')[0])
        for name in namelist:
            fullname = os.path.join(path, name)
            displayname = linkname = name
            # Append / for directories or @ for symbolic links
            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = name + "/"
            if os.path.islink(fullname):
                displayname = name + "@"
                # Note: a link to a directory displays with @ and links with /
            r.append('<li><a href="%s">%s</a></li>'
                     % (urlparse.quote(linkname, errors='surrogatepass'),
                        html.escape(displayname)))
        r.append('</ul>\n<hr>\n</body>\n</html>\n')
        content = '\n'.join(r).encode(enc, 'surrogateescape')
        l = len(content)
        self.write('HTTP/1.1 200\r\n'
                   'Connection: close\r\n'
                   'Content-Length: %s\r\n'
                   'Content-Type: text/html; charset=%s\r\n\r\n'
                   % (l, enc))
        self.write(content)
        return l

    guess_type = BaseHTTPServer.SimpleHTTPRequestHandler.guess_type
    extensions_map = BaseHTTPServer.SimpleHTTPRequestHandler.extensions_map
    extensions_map.update({
        '.ass' : 'text/plain',
        '.flac': 'audio/flac',
        '.mkv' : 'video/mkv',
        '.pac' : 'text/plain',
        })

    def do_LOCAL(self, filename=None):
        '''返回一个本地文件或目录'''
        path = urlparse.unquote(self.path)
        if filename:
            filename = urlparse.unquote(filename)
        else:
            filename = os.path.join(web_dir, path[1:])
        #只列表 web_dir 文件夹
        if filename.startswith(web_dir) and os.path.isdir(filename):
            r = self.list_dir(filename, path)
            if isinstance(r, int):
                logging.info('%s "%s %s HTTP/1.1" 200 %s',
                    self.address_string(), self.command, self.url, r)
            else:
                logging.info('%s "%s %s HTTP/1.1" 403 -，无法打开本地文件：%r',
                    self.address_string(), self.command, self.url, r)
            return
        if os.path.isfile(filename):
            content_type = self.guess_type(filename)
            try:
                filesize = os.path.getsize(filename)
                with open(filename, 'rb') as fp:
                    data = fp.read(1048576) # 1M
                    logging.info('%s "%s %s HTTP/1.1" 200 %d',
                        self.address_string(), self.command, self.url, filesize)
                    self.write('HTTP/1.1 200\r\n'
                               'Connection: close\r\n'
                               'Content-Length: %s\r\n'
                               'Content-Type: %s\r\n\r\n'
                               % (filesize, content_type))
                    while data:
                        self.write(data)
                        data = fp.read(1048576)
            except Exception as e:
                logging.warning('%s "%s %s HTTP/1.1" 403 -，无法打开本地文件：%r',
                    self.address_string(), self.command, self.url, filename)
                self.write('HTTP/1.1 403\r\n'
                           'Content-Type: text/html\r\n'
                           'Connection: close\r\n\r\n'
                           '<title>403 拒绝</title>\n'
                           '<h1>403 无法打开本地文件：</h1><hr>\n'
                           '<h2><li>%s</li></h2>\n'
                           '<h2><li>%s</li></h2>\n'
                           % (filename, e))
        else:
            logging.warning('%s "%s %s HTTP/1.1" 404 -，无法找到本地文件：%r',
                self.address_string(), self.command, self.url, filename)
            self.write('HTTP/1.1 404\r\n'
                       'Content-Type: text/html\r\n'
                       'Connection: close\r\n\r\n'
                       '<title>404 无法找到</title>\n'
                       '<h1>404 无法找到本地文件：</h1><hr>\n'
                       '<h2><li>%s</li></h2>\n'
                       % filename)

    def do_BLOCK(self):
        '''Return a space content with 200'''
        content = (b'HTTP/1.1 200\r\n'
                   b'Cache-Control: max-age=86400\r\n'
                   b'Expires:Oct, 01 Aug 2100 00:00:00 GMT\r\n'
                   b'Connection: close\r\n')
        if self.url_parts and self.url_parts.path.endswith(('.jpg', '.gif', '.jpeg', '.png', '.bmp')):
            content += (b'Content-Type: image/gif\r\n\r\n'
                        b'GIF89a\x01\x00\x01\x00\x80\xff\x00\xc0\xc0\xc0'
                        b'\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00'
                        b'\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;')
        else:
            content += b'\r\n'
        logging.warning('%s "%s%s %s" 已经被拦截',
            self.address_string(), 'CONNECT BLOCK ' if self.ssl else '',
            self.command, self.url or self.host)
        self.write(content)

    def go_GAE(self):
        if self.command not in ('GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'PATCH'):
            return self.go_BAD()
        host = '%s://%s' % (self.url_parts.scheme, self.host)
        #最近是否失败（缓存设置超时两分钟）
        if host in self.badhost:
            if self.badhost[host]:
                #记录临时规则的过期时间
                filters_cache[host][-1] = '', '', 'TEMPGAE', time() + 900
                logging.warning('将 %r 加入 "GAE" 规则 15 分钟。', host)
                self.badhost[host] = False
        else:
            self.badhost[host] = True
        self.action = 'do_GAE'
        self.do_GAE()

    def go_FAKECERT(self):
        host = self.host
        #最近是否失败（缓存设置超时两分钟）
        if host in self.badhost:
            if self.badhost[host]:
                #设置临时规则的过期时间
                ssl_filters_cache.set(host, ('do_FAKECERT', None), 900)
                logging.warning('将 %r 加入 "FAKECERT" 规则 15 分钟。', host)
                self.badhost[host] = False
        else:
            self.badhost[host] = True
        #同时标记直连 badhost
        host = 'http%s://%s' % ('s' if self.ssl else '', host)
        self.badhost[host] = True
        self.action = 'do_FAKECERT'
        self.do_FAKECERT()

    def go_BAD(self):
        logging.warn('request "%s %s" 失败, 返回 404', self.command, self.url)
        self.write(b'HTTP/1.0 404\r\nContent-Type: text/html\r\n\r\n')
        self.write(message_html('404 无法访问', '不能 "%s %s"' % (self.command, self.url), '无论是通过 GAE 还是 DIRECT 都无法访问成功'))

    def forward_socket(self, remote, timeout=30, tick=4, maxping=None, maxpong=None):
        '''Forward local and remote connection'''
        if self.command == 'CONNECT':
            self.connection.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        else:
            http_headers = ''.join('%s: %s\r\n' % (k.title(), v) for k, v in self.headers.items() if k.title() not in skip_request_headers)
            rebuilt_request = '%s\r\n%s\r\n' % (self.requestline, http_headers)
            if not isinstance(rebuilt_request, bytes):
                rebuilt_request = rebuilt_request.encode()
            remote.sendall(rebuilt_request)
        local = self.connection
        buf = bytearray(32768) # 32K
        maxpong = maxpong or timeout
        allins = [local, remote]
        timecount = timeout
        try:
            while allins and timecount > 0:
                timecount -= tick
                ins, _, err = select(allins, [], allins, tick)
                if err:
                    logging.warning(err)
                    raise socket.error(err)
                for sock in ins:
                    ndata = sock.recv_into(buf)
                    if ndata:
                        other = local if sock is remote else remote
                        other.sendall(buf[:ndata])
                        timecount = min(timecount*2, maxpong)
                    else:
                        allins.remove(sock)
        except NetWorkIOError as e:
            #if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
            if e.args[0] not in (10053, 10054):
                logging.warning('转发 %r 失败：%r', self.url, e)
        finally:
            remote.close()
            self.close_connection = 1

    def get_ssl_context(self):
        '''Keep a ssl_context cache'''
        host = self.host
        ip = isip(host)
        if not ip:
            hostsp = host.split('.')
            nhost = len(hostsp)
            if nhost > 3 or (nhost == 3 and len(hostsp[-2]) > 3):
                host = '.'.join(hostsp[1:])
        if host in self.ssl_context_cache:
            return self.ssl_context_cache[host]
        else:
            logging.debug('%s-%s first', host, ip)
            certfile, keyfile = CertUtil.get_cert(host, ip)
            self.ssl_context_cache[host] = ssl_context = ssl.SSLContext(GC.LINK_LOCALSSL)
            ssl_context.verify_mode = ssl.CERT_NONE
            ssl_context.load_cert_chain(certfile, keyfile)
            return ssl_context

    def send_CA(self):
        '''Return CA cert file'''
        from .CertUtil import ca_certfile
        with open(ca_certfile, 'rb') as fp:
            data = fp.read()
        logging.info('"%s HTTP/1.1 200"，发送 CA 证书到 %r', self.url, self.address_string())
        self.write(b'HTTP/1.1 200\r\n'
                   b'Content-Type: application/x-x509-ca-cert\r\n')
        if self.path.lower() == self.CAPath[1]:
            self.write(b'Content-Disposition: attachment; filename="GotoXCA.crt"\r\n')
        self.write('Content-Length: %s\r\n\r\n' % len(data))
        self.write(data)

    def parse_netloc(self, netloc):
        host, has_br, port = netloc.partition(']')
        if has_br:
            # IPv6 必须使用方括号
            self.ipv6host = True
            host = host[1:]
            port = port[1:]
        else:
            self.ipv6host = False
            host, _, port = host.partition(':')
        return host.lower(), port

    def address_string(self, response=None):
        '''Return the connected ip or the client's ip and port'''
        if hasattr(response, 'xip'):
            return response.xip[0]
        else:
            return '%s:%s' % self.client_address[:2]

class GAEProxyHandler(AutoProxyHandler):

    def do_CONNECT(self):
        '''handle CONNECT cmmand, do a filtered action'''
        self._do_CONNECT()
        self.action = 'do_FAKECERT'
        self.do_action()

    def do_METHOD(self):
        '''handle others cmmand, do a filtered action'''
        self._do_METHOD()
        #本地地址
        if self.host.startswith(self.localhosts):
            #发送证书
            if self.path.lower() in self.CAPath:
                return self.send_CA()
            return self.do_LOCAL()
        self.action = 'do_GAE'
        self.do_action()

    do_GET = do_METHOD
    do_PUT = do_METHOD
    do_POST = do_METHOD
    do_HEAD = do_METHOD
    do_DELETE = do_METHOD
    do_OPTIONS = do_METHOD
    do_PATCH = do_METHOD

    def go_GAE(self):
        self.go_BAD()
