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
import logging
from select import select
from time import time, sleep
from functools import partial
from . import CertUtil
from .path import web_dir
from .compat import BaseHTTPServer, urlparse, thread, hasattr
from .compat.openssl import SSL, SSLConnection
from .common import (
    NetWorkIOError,
    reset_errno,
    closed_errno,
    pass_errno,
    LRUCache,
    message_html,
    isip,
    isipv6
    )
from .common.decompress import decompress_readers
from .common.dns import reset_dns, set_dns, dns_resolve
from .common.proxy import parse_proxy, proxy_no_rdns
from .common.region import isdirect
from .GlobalConfig import GC
from .GAEUpdate import testip
from .HTTPUtil import http_gws, http_nor
from .RangeFetch import RangeFetchs
from .GAEFetch import qGAE, get_appid, mark_badappid, gae_urlfetch
from .FilterUtil import (
    set_temp_action,
    set_temp_connect_action,
    get_action,
    get_connect_action
    )
from .FilterConfig import ACTION_FILTERS

normattachment = partial(re.compile(r'(?<=filename=)([^"\']+)').sub, r'"\1"')
getbytes = re.compile(r'^bytes=(\d*)-(\d*)(,..)?').search
getrange = re.compile(r'^bytes (\d+)-(\d+)/(\d+|\*)').search

class AutoProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    CAPath = '/ca', '/cadownload'
    valid_cmds = {'CONNECT', 'GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'PATCH'}
    valid_leadbytes = set(cmd[0].encode() for cmd in valid_cmds)
    gae_fetcmds = {'GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'}
    skip_request_headers = (
        'Vary',
        'Via',
        'X-Forwarded-For',
        'Proxy-Authorization',
        'Proxy-Connection',
        'Upgrade',
        'X-Chrome-Variations',
        #'Cache-Control'
        )
    skip_response_headers = (
        'Content-Length',
        'Transfer-Encoding',
        'Connection',
        'Content-MD5',
        'Set-Cookie',
        'Upgrade',
        'Alt-Svc',
        'Alternate-Protocol'
        )

    fwd_timeout = GC.LINK_FWDTIMEOUT
    fwd_keeptime = GC.LINK_FWDKEEPTIME
    listen_port = {GC.LISTEN_GAE_PORT, str(GC.LISTEN_GAE_PORT),
                   GC.LISTEN_AUTO_PORT, str(GC.LISTEN_AUTO_PORT)}
    request_compress = GC.LINK_REQUESTCOMPRESS

    #可修改
    timeout = 60 * 6
    context_cache = LRUCache(256)
    proxy_connection_time = LRUCache(32)
    badhost = LRUCache(16, 120)
    rangesize = min(GC.GAE_MAXSIZE, GC.AUTORANGE_FAST_MAXSIZE * 4, 1024 * 1024 * 3)

    #默认值
    ssl_servername = GC.LISTEN_IPHOST or '127.0.0.1'
    ssl_request = False
    tunnel = False
    ssl = False
    fakecert = False
    host = None
    url = None
    url_parts = None
    conaborted = False
    action = ''

    def __init__(self, request, client_address, server):
        self.client_address = client_address
        self.server = server
        #添加 https 代理协议支持
        leadbyte = request.recv(1, socket.MSG_PEEK)
        #估计支持的程序都不会使用旧 SSL 协议，故不予支持
        if leadbyte == b'\x16':
            context = self.get_context(self.ssl_servername)
            context.set_tlsext_servername_callback(self.pick_certificate)
            try:
                request = SSLConnection(context, request)
                request.set_accept_state()
                self.ssl_request = True
                rd, _, ed = select([request], [], [request], 4)
                if ed:
                    raise socket.error(ed)
                byte = request.recv(1, socket.MSG_PEEK) if rd else None
                if not byte:
                    #未收到后续请求数据，判断证书验证失败
                    raise ssl.SSLError('客户端证书验证失败，请检查双方主机名称设置是否匹配')
            except Exception as e:
                #if e.args[0] not in pass_errno:
                servername = request.get_servername() or self.ssl_servername
                logging.warning('%s https 代理失败：sni=%r，%r', self.address_string(), servername, e)
                return
        elif leadbyte not in self.valid_leadbytes:
            return
        self.request = request
        self.setup()
        try:
            self.handle()
        finally:
            self.finish()

    def pick_certificate(self, connection):
        servername = connection.get_servername()
        if servername is None:
            if GC.LISTEN_IPHOST is self.ssl_servername:
                return
            servername = GC.LISTEN_IPHOST
        else:
            servername = str(servername, 'iso-8859-1')
        if not servername:
            logging.warning('%s https 代理失败：对方使用 IP 访问，GotoX 未设置 IP-Host 名称', self.address_string())
            return
        new_context = self.get_context(servername)
        connection.set_context(new_context)

    def setup(self):
        #仅监听本机时关闭 nagle's algorithm 算法和接收缓冲
        if not self.disable_nagle_algorithm:
            client_ip = self.client_address[0]
            if client_ip.endswith('127.0.0.1') or client_ip == '::1':
                self.disable_nagle_algorithm = True
                if sys.platform != 'darwin':
                    self.request.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        BaseHTTPServer.BaseHTTPRequestHandler.setup(self)

    def write(self, d, raiseerror=None):
        if raiseerror is None and not isinstance(d, bytes):
            d = d.encode()
        try:
            self.wfile.write(d)
        except Exception as e:
            self.conaborted = True
            if raiseerror:
                logging.debug('%s 客户端连接断开：%r, %r', self.address_string(), self.url, e)
                raise e

    def handle_one_request(self):
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            if not self.raw_requestline or \
                    self.raw_requestline[:1] not in self.valid_leadbytes or \
                    self.server.is_offline:
                self.close_connection = True
                return
            if not self.parse_request():
                # An error code has been sent, just exit
                return
            if self.command == 'CONNECT':
                self.do_CONNECT()
            elif self.command in self.valid_cmds:
                self.do_METHOD()
            else:
                self.send_error(501, 'Unsupported method (%r)' % self.command)
                return
            self.wfile.flush() #actually send the response if not already done.
        except socket.timeout as e:
            #a read or a write timed out.  Discard this connection
            self.log_error("Request timed out: %r", e)
            self.close_connection = True
        except SSL.Error as e:
            if isinstance(e.args[0], list) and any('certificate unknown' in arg for arg in e.args[0][0]):
                logging.warn('%s host=%s，客户端 https 验证失败！可能未安装 GotoX CA 证书。', self.address_string(), self.host)
            self.close_connection = True

    def do_action(self):
        #记录 gws 连接活动时间
        #获取 hostname 别名
        self.close_connection = True
        if self.headers.get('Upgrade') == 'websocket' and self.action in ('do_DIRECT', 'do_GAE'):
            self.action = 'do_FORWARD'
            self.target = None
            logging.warn('%s %s 不支持 websocket %r，转用 FORWARD。', self.address_string(), self.action[3:], self.url)
        if self.action in ('do_DIRECT', 'do_FORWARD'):
            self.hostname = hostname = set_dns(self.host, self.target)
            if hostname is None:
                if self.ssl and not self.fakecert:
                    self.do_FAKECERT()
                else:
                    logging.error('%s 无法解析主机：%r，路径：%r，请检查是否输入正确！', self.address_string(), self.host, self.path)
                    c = message_html('504 解析失败', '504 解析失败<p>主机名 %r 无法解析，请检查是否输入正确！' % self.host).encode()
                    self.write(b'HTTP/1.1 504 Resolve Failed\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n' % len(c))
                    self.write(c)
                return 
            elif hostname.startswith('google'):
                testip.lastactive = time()
        elif self.action == 'do_GAE':
            testip.lastactive = time()
        getattr(self, self.action)()

    def parse_host(self, host, chost, mhost=True):
        port = None
        #从命令获取主机、端口
        chost, cport = urlparse.splitport(chost)
        #确定主机，优先 Host 头域
        if host:
            #从头域获取主机、端口
            host, port = urlparse.splitport(host)
            #排除某些程序把代理当成主机名
            if chost and port in self.listen_port and host in self.localhosts:
                self.host = host = chost
                port = cport
            else:
                self.host = host
        else:
            self.host = host = chost
        if host[0] == '[':
            self.host = host[1:-1]
        #确定端口
        self.port = port = int(port or cport or self.ssl and 443 or 80)
        #确定 Host 头域
        if mhost:
            if (bool(self.ssl), port) not in ((False, 80), (True, 443)):
                if isipv6(host) and host[0] != '[':
                    host = '[%s]:%d' % (host, port)
                else:
                    host = '%s:%d' % (host, port)
            else:
                host = self.host
            if 'Host' in self.headers:
                self.headers.replace_header('Host', host)
            else:
                self.headers['Host'] = host

    def _do_CONNECT(self):
        self.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        self.tunnel = True
        leadbyte = self.connection.recv(1, socket.MSG_PEEK)
        self.ssl = leadbyte in (b'\x16', b'\x80') # 0x80: ssl20
        if not self.ssl:
            return True
        self.parse_host(self.headers.get('Host'), self.path)
        #本地地址
        if self.host in self.localhosts and (
                self.port in (80, 443) or
                self.port in self.listen_port):
            self.do_FAKECERT()
            return True

    def do_CONNECT(self):
        #处理 CONNECT 请求，根据规则过滤执行目标动作
        if self._do_CONNECT():
            return
        self.action, self.target = get_connect_action(self.ssl, self.host)
        self.do_action()

    def _do_METHOD(self):
        self.reread_req = False
        self.url_parts = url_parts = urlparse.urlsplit(self.path)
        self.parse_host(self.headers.get('Host'), url_parts.netloc)
        #确定协议
        scheme = 'https' if self.ssl else 'http'
        #确定网址、去掉可能存在的端口
        self.url_parts = url_parts = urlparse.SplitResult(scheme, self.headers.get('Host'), url_parts.path, url_parts.query, '')
        self.url = url = url_parts.geturl()
        #确定路径
        if self.path[0] != '/':
            self.path = url[url.find('/', 12):]
        #本地地址
        if self.host in self.localhosts and (
                self.port in (80, 443) or
                self.port in self.listen_port):
            self.do_LOCAL()
            return True

    def do_METHOD(self):
        #处理其它请求，根据规则过滤执行目标动作
        if self._do_METHOD():
            return
        self.action, self.target = get_action(self.url_parts.scheme, self.host, self.path[1:], self.url)
        self.do_action()

    def write_response_content(self, data, response, need_chunked):
        length = self.response_length
        #无内容返回
        if not need_chunked and not length:
            return 0, None
        #写入响应内容
        ndata = len(data) if data else 0
        if hasattr(response, 'app_msg'):
            # goproxy 服务端错误信息
            if ndata:
                self.write(data)
            return ndata, None
        wrote = 0
        err = None
        buf = memoryview(bytearray(self.bufsize))
        try:
            if ndata:
                buf[:ndata] = data
            else:
                ndata = response.readinto(buf)
            while ndata:
                if need_chunked:
                    self.write(b'%x\r\n' % ndata, True)
                    self.write(buf[:ndata].tobytes(), True)
                    self.write(b'\r\n', True)
                    wrote += ndata
                else:
                    self.write(buf[:ndata].tobytes(), True)
                    wrote += ndata
                    if wrote >= length:
                        break
                ndata = response.readinto(buf)
        except Exception as e:
            err = e
        finally:
            if need_chunked:
                self.write(b'0\r\n\r\n', True)
            return wrote, err

    def handle_request_headers(self):
        #无法重复读取套接字，使用属性保存
        if self.reread_req:
            self.close_connection = self.cc
            return self.request_headers.copy(), self.payload
        #处理请求
        request_headers = dict((k.title(), v) for k, v in self.headers.items() \
                               if k.title() not in self.skip_request_headers)
        pconnection = self.headers.get('Proxy-Connection')
        if pconnection and \
                self.request_version < 'HTTP/1.1' and \
                pconnection.lower() != 'keep-alive':
            self.close_connection = True
        else:
            self.close_connection = False
        payload = b''
        length = int(request_headers.get('Content-Length', 0))
        if self.action == 'do_GAE':
            try:
                #暂时限制为 32MB，实际可能会更小一点
                if 0 < length < 33554433:
                    payload = self.rfile.read(length)
                elif 'Transfer-Encoding' in request_headers:
                    value = []
                    length = 0
                    while True:
                        chunk_size_str = self.rfile.readline(65537)
                        if len(chunk_size_str) > 65536:
                            raise Exception('分块尺寸过大')
                        chunk_size = int(chunk_size_str.split(b';')[0], 16)
                        if chunk_size == 0:
                            while True:
                                chunk = self.rfile.readline(65537)
                                if chunk in (b'\r\n', b'\n', b''): # b'' 也许无法读取到空串
                                    break
                                else:
                                    #只能抛弃，如服务器强制要求携带，则请求可能失败
                                    logging.debug('%s "%s %s %s"分块拖挂：%r', self.address_string(), self.action[3:], self.command, self.url, chunk)
                            break
                        chunk = self.rfile.read(chunk_size)
                        value.append(chunk)
                        length += len(chunk)
                        if length > 33554432:
                            break
                        if self.rfile.read(2) != b'\r\n':
                            raise Exception('分块尺寸不匹配 CRLF')
                    payload = b''.join(value)
            except Exception as e:
                logging.error('%s "%s %s %s" 附加内容读取失败：%r', self.address_string(), self.action[3:], self.command, self.url, e)
                raise
            if length > 33554432:
                logging.error('%s "%s %s %s" 附加内容尺寸过大：%d，无法通过 GAE 代理', self.address_string(), self.action[3:], self.command, self.url, length)
                raise
        elif self.action != 'do_DIRECT' or length > 65536 or 'Transfer-Encoding' in request_headers:
            #不读取，直接传递 rfile 以加快代理转发速度
            payload = self.rfile
            self.rfile.readed = 0
        elif length:
            #小于 64KB 仍然一次读取完毕
            try:
                payload = self.rfile.read(length)
            except NetWorkIOError as e:
                logging.error('%s "%s %s %s" 附加内容读取失败：%r', self.address_string(), self.action[3:], self.command, self.url, e)
                raise
        # 强制请求压缩内容，之后会自动判断解压缩
        ae = request_headers.get('Accept-Encoding', '')
        if 'identity' in ae:
            if self.action == 'do_GAE':
                request_headers['Accept-Encoding'] = 'identity'
        elif self.request_compress:
            r = request_headers.get('Range')
            if not r or not r.startswith('bytes='):
                if ae is '':
                    request_headers['Accept-Encoding'] = 'gzip, br'
                else:
                    if 'gzip' not in ae:
                        request_headers['Accept-Encoding'] += ', gzip'
                    if 'br' not in ae:
                        request_headers['Accept-Encoding'] += ', br'
        self.request_headers = request_headers
        self.payload = payload
        self.reread_req = True
        self.cc = self.close_connection
        return request_headers.copy(), payload

    def get_response_length(self, response):
        if hasattr(response, 'app_status') and response.app_status == 200:
            response._method = self.command
            content_length = response.headers.get('Content-Length', '0')
            self.response_length = content_length = int(content_length) if content_length.isdigit() else 0
            response.length = content_length if content_length else None
        elif hasattr(response, 'app_msg'):
            self.response_length = content_length = len(response.app_msg)
        else:
            self.response_length = content_length = response.length or 0
        return content_length

    def handle_response_headers(self, response):
        #处理响应
        response_headers = dict((k.title(), v) for k, v in response.headers.items() \
                                if k.title() not in self.skip_response_headers)
        #明确设置 Accept-Ranges
        if response_headers.get('Accept-Ranges') != 'bytes':
            response_headers['Accept-Ranges'] = 'none'
        #解压缩请求不支持的编码
        ce = response_headers.get('Content-Encoding')
        if ce:
            if ce.startswith('none'):
                #某些服务器压缩模块会产生多余的 'none'
                ce = ce[4:].strip(', ')
                if ce:
                    response_headers['Content-Encoding'] = ce
                else:
                    del response_headers['Content-Encoding']
            if ce and ce not in self.headers.get('Accept-Encoding', '') and \
                    ce in decompress_readers:
                response = decompress_readers[ce](response)
                del response_headers['Content-Encoding']
                response_headers.pop('Content-Length', None)
                response_headers.pop('Accept-Ranges', None)
                self.response_length = 0
                logging.debug('正在以 %r 格式解压缩 %s', ce, self.url)
        length = self.response_length
        if hasattr(response, 'app_msg'):
            # goproxy 服务端错误信息
            data = response.app_msg
            response_headers['Content-Type'] = 'text/html; charset=utf-8'
        else:
            data = response.read(self.bufsize)
        need_chunked = data and not length # response 中的数据已经正确解码
        if need_chunked:
            if self.request_version == 'HTTP/1.1':
                response_headers['Transfer-Encoding'] = 'chunked'
            else:
                # HTTP/1.1 以下不支持 chunked，关闭连接
                need_chunked = False
                self.close_connection = True
        else:
            response_headers['Content-Length'] = length
        cookies = response.headers.get_all('Set-Cookie')
        if cookies:
            response_headers['Set-Cookie'] = '\r\nSet-Cookie: '.join(cookies)
        if 'Content-Disposition' in response_headers:
            response_headers['Content-Disposition'] = normattachment(response_headers['Content-Disposition'])
        response_headers['Connection' if self.tunnel else 'Proxy-Connection'] = 'close' if self.close_connection else 'keep-alive'
        headers_data = 'HTTP/1.1 %s %s\r\n%s\r\n' % (response.status, response.reason, ''.join('%s: %s\r\n' % x for x in response_headers.items()))
        self.write(headers_data)
        logging.debug('headers_data=%s', headers_data)
        if 300 <= response.status < 400 and \
                response.status != 304 and \
                'Location' in response_headers:
            logging.info('%r 返回包含重定向 %r', self.url, response_headers['Location'])
        if response.status == 304:
            logging.test('%s "%s %s %s HTTP/1.1" %s %s', self.address_string(response), self.action[3:], self.command, self.url, response.status, length or '-')
        else:
            logging.info('%s "%s %s %s HTTP/1.1" %s %s', self.address_string(response), self.action[3:], self.command, self.url, response.status, length or '-')
        return response, data, need_chunked

    def check_useragent(self):
        #修复某些软件无法正确处理 206 Partial Content 响应的持久连接
        user_agent = self.headers.get('User-Agent', '')
        if user_agent.startswith('mpv') or \
            user_agent.endswith(('(Chrome)', 'Iceweasel/38.2.1')):
            # youtube-dl 有时会传递给其它支持的播放器，导致无法辨识，统一关闭
            # 其它自定义的就没法，此处无法辨识，感觉关闭所有 206 有点划不来
            self.close_connection = True

    def do_DIRECT(self):
        #直接请求目标地址
        hostname = self.hostname
        http_util = http_gws if hostname.startswith('google') else http_nor
        request_headers, payload = self.handle_request_headers()
        headers_sent = False
        for retry in range(2):
            if retry > 0 and payload and isinstance(payload, bytes) or hasattr(payload, 'readed') and payload.readed:
                logging.warning('%s do_DIRECT 由于有上传数据 "%s %s" 终止重试', self.address_string(), self.command, self.url)
                self.close_connection = True
                if not headers_sent:
                    c = message_html('504 响应超时', '获取 %r 超时，请稍后重试。' % self.url, '').encode()
                    self.write(b'HTTP/1.1 504 Gateway Timeout\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n' % len(c))
                    self.write(c)
                return
            noerror = True
            response = None
            self.close_connection = self.cc
            try:
                connection_cache_key = '%s:%d' % (hostname, self.port)
                response = http_util.request(self, payload, request_headers, self.bufsize, connection_cache_key)
                if not response:
                    #重试、网站图标
                    if retry or self.url_parts.path.endswith('favicon.ico'):
                        logging.warn('%s do_DIRECT "%s %s" 失败，返回 404', self.address_string(), self.command, self.url)
                        c = '404 无法找到给定的网址'.encode()
                        self.write('HTTP/1.1 404 Not Found\r\n'
                                   'Content-Type: text/plain; charset=utf-8\r\n'
                                   'Content-Length: %d\r\n\r\n' % len(c))
                        self.write(c)
                        return
                    #非默认规则、直连 IP
                    elif self.target is not None or isdirect(self.host):
                        logging.warning('%s do_DIRECT "%s %s" 没有正确响应，重试。', self.address_string(response), self.command, self.url)
                        continue
                    else:
                        logging.warn('%s do_DIRECT "%s %s" 失败，尝试使用 "GAE" 规则。', self.address_string(), self.command, self.url)
                        return self.go_GAE()
                #发生错误时关闭连接
                if response.status >= 400:
                    noerror = False
                #拒绝服务、非直连 IP
                if response.status == 403 and not isdirect(self.host):
                    logging.warn('%s do_DIRECT "%s %s" 连接被拒绝，尝试使用 "GAE" 规则。', self.address_string(response), self.command, self.url)
                    return self.go_GAE()
                #修复某些软件无法正确处理持久连接（停用）
                self.check_useragent()
                self.get_response_length(response)
                response, data, need_chunked = self.handle_response_headers(response)
                headers_sent = True
                _, err = self.write_response_content(data, response, need_chunked)
                if err:
                    raise err
                return
            except NetWorkIOError as e:
                noerror = False
                if self.conaborted:
                    raise e
                #连接重置
                if e.args[0] in reset_errno:
                    if isdirect(self.host):
                        logging.warning('%s do_DIRECT "%s %s" 连接被重置，重试。', self.address_string(response), self.command, self.url)
                        continue
                    else:
                        logging.warning('%s do_DIRECT "%s %s" 连接被重置，尝试使用 "GAE" 规则。', self.address_string(response), self.command, self.url)
                        return self.go_GAE()
                elif e.args[0] not in pass_errno:
                    raise e
            except Exception as e:
                noerror = False
                logging.warning('%s do_DIRECT "%s %s" 失败：%r', self.address_string(response), self.command, self.url, e)
                raise e
            finally:
                if not noerror:
                    self.close_connection = True
                if response:
                    response.close()
                    if noerror:
                        #放入套接字缓存
                        if self.ssl:
                            if GC.GAE_KEEPALIVE or http_util is not http_gws:
                                http_util.ssl_connection_cache[connection_cache_key].append((time(), response.sock))
                            else:
                                #干扰严重时考虑不复用 google 连接
                                response.sock.close()
                        else:
                            response.sock.used = None
                            http_util.tcp_connection_cache[connection_cache_key].append((time(), response.sock))

    def fake_OPTIONS(self, request_headers):
        response = [
            'HTTP/1.1 200 OK',
            'Access-Control-Allow-Credentials: true',
            'Access-Control-Allow-Methods: GET, POST, HEAD, PUT, DELETE, OPTIONS, PATCH',
            'Access-Control-Expose-Headers: Content-Encoding, Content-Length, Date, Server, Vary, X-Google-GFE-Backend-Request-Cost, X-FB-Debug, X-Loader-Length',
            'Access-Control-Max-Age: 1728000',
            'Vary: Origin, X-Origin',
            'Content-Length: 0'
            ]
        headers = request_headers.get('Access-Control-Request-Headers')
        if headers:
            response.append('Access-Control-Allow-Headers: ' + headers)
        else:
            response.append('Access-Control-Allow-Headers: Authorization, If-Modified-Since')
        origin = request_headers.get('Origin')
        if origin:
            response.append('Access-Control-Allow-Origin: ' + origin)
        else:
            response.append('Access-Control-Allow-Origin: *')
        response.append('\r\n')
        self.write('\r\n'.join(response))
        logging.info('%s "%s FAKEOPTIONS %s HTTP/1.1" 200 0', self.address_string(response), self.action[3:], self.url)

    def do_GAE(self):
        #发送请求到 GAE 代理
        if self.command not in self.gae_fetcmds:
            logging.warn('%s GAE 不支持 "%s %s"，转用 DIRECT。', self.address_string(), self.command, self.url)
            self.action = 'do_DIRECT'
            self.target = None
            return self.do_action()
        url_parts = self.url_parts
        request_headers, payload = self.handle_request_headers()
        if self.command == 'OPTIONS':
            return self.fake_OPTIONS(request_headers)
        #排除不支持 range 的请求
        need_autorange = self.command != 'HEAD' and 'range=' not in url_parts.query and 'range/' not in self.path and 'live=1' not in url_parts.query
        self.range_end = range_end = range_start = 0
        if need_autorange:
            #匹配网址结尾
            need_autorange = 1 if url_parts.path.endswith(GC.AUTORANGE_FAST_ENDSWITH) else 0
            request_range = request_headers.get('Range')
            if request_range is not None:
                request_range = getbytes(request_range)
                if request_range:
                    range_start, range_end, range_other = request_range.group(1, 2, 3)
                    if not range_start or range_other:
                        # autorange 无法处理未指定开始范围和不连续范围
                        range_start = 0
                        need_autorange = 0
                    else:
                        range_start = int(range_start)
                        if range_end:
                            self.range_end = range_end = int(range_end)
                            range_length = range_end + 1 - range_start
                            #有明确范围时，根据阀值判断
                            if need_autorange is 1:
                                if range_length < self.rangesize:
                                    need_autorange = -1
                            else:
                                need_autorange = 2 if range_length > GC.AUTORANGE_BIG_ONSIZE else -1
                        else:
                            self.range_end = range_end = 0
                            #if need_autorange is 0:
                            #    #非 autorange/fast 匹配
                            #    need_autorange = 2
            if need_autorange is 1:
                logging.info('发现[autorange/fast]匹配：%r', self.url)
                range_end = range_start + GC.AUTORANGE_FAST_FIRSTSIZE - 1
                request_headers['Range'] = 'bytes=%d-%d' % (range_start, range_end)
            elif need_autorange is 2:
                logging.info('发现[autorange/big]匹配：%r', self.url)
                range_end = range_start + GC.AUTORANGE_BIG_MAXSIZE - 1
                request_headers['Range'] = 'bytes=%d-%d' % (range_start, range_end)
        else:
            need_autorange = -1
        errors = []
        headers_sent = False
        need_chunked = False
        start = range_start
        end = ''
        accept_ranges = None
        for retry in range(GC.GAE_FETCHMAX):
            if retry > 0 and payload:
                logging.warning('%s do_GAE 由于有上传数据 "%s %s" 终止重试', self.address_string(), self.command, self.url)
                self.close_connection = True
                if not headers_sent:
                    c = message_html('504 GAE 响应超时', '从本地上传到 GAE-%r 超时，请稍后重试。' % self.url, str(errors)).encode()
                    self.write(b'HTTP/1.1 504 Gateway Timeout\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n' % len(c))
                    self.write(c)
                return
            appid = get_appid()
            noerror = True
            data = None
            response = None
            self.close_connection = self.cc
            try:
                response = gae_urlfetch(self.command, self.url, request_headers, payload, appid)
                if response is None:
                    if retry == GC.GAE_FETCHMAX - 1:
                        if headers_sent:
                            self.close_connection = True
                        else:
                            c = message_html('502 资源获取失败', '本地从 GAE 获取 %r 失败' % self.url, str(errors)).encode()
                            self.write(b'HTTP/1.1 502 Service Unavailable\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n' % len(c))
                            self.write(c)
                        return
                    else:
                        logging.warning('%s do_GAE 超时，url=%r，重试', self.address_string(), self.url)
                        sleep(0.5)
                        continue
                #处理 GoProxy 错误信息
                if response.reason == 'debug error':
                    app_msg = response.app_msg.decode()
                    #密码错误
                    if response.app_status == 403:
                        logging.warning('GAE：%r 密码错误！你设置的密码是： %r', appid, GC.GAE_PASSWORD)
                        app_msg = '<h1>******   GAE：%r 密码错误！请修改后重试。******</h1>' % appid
                    # GoProxy 临时错误，重试
                    elif response.app_status == 502:
                        if 'DEADLINE_EXCEEDED' in app_msg:
                            logging.warning('GAE：%r urlfetch %r 返回 DEADLINE_EXCEEDED，重试', appid, self.url)
                            continue
                        elif 'ver quota' in app_msg:
                            logging.warning('GAE：%r urlfetch %r 返回 over quota，重试', appid, self.url)
                            mark_badappid(appid, 60)
                            continue
                        elif 'urlfetch: CLOSED' in app_msg:
                            logging.warning('GAE：%r urlfetch %r 返回 urlfetch: CLOSED，重试', appid, self.url)
                            sleep(0.5)
                            continue
                        elif 'RESPONSE_TOO_LARGE' in app_msg:
                            logging.warning('GAE：%r urlfetch %r 返回 urlfetch: RESPONSE_TOO_LARGE，服务器不支持 Range。', appid, self.url)
                    # GoProxy 服务端版本可能不兼容
                    elif response.app_status == 400:
                        logging.error('%r 部署的可能是 GotoX 不兼容的 GoProxy 服务端版本，如果这条错误反复出现请将之反馈给开发者。', appid)
                        app_msg = ('<h2>GotoX：%r 部署的可能是 GotoX 不兼容的 GoProxy 服务端版本，如果这条错误反复出现请将之反馈给开发者。<h2>\n'
                                '错误信息：\n%r' % (appid, app_msg))
                    response.app_msg = app_msg.encode()
                #网关错误（Bad Gateway｜Gateway Timeout）
                elif response.app_status in (502, 504):
                    sleep(0.5)
                    logging.warning('%s do_GAE 网关错误，appid=%r，url=%r，重试', self.address_string(response), appid, self.url)
                    noerror = False
                    continue
                #无法提供 GAE 服务（Moved Permanently｜Found｜Forbidden｜Method Not Allowed）
                elif response.app_status in (301, 302, 403, 405):
                    continue
                #当前 appid 流量完结(Service Unavailable)
                elif response.app_status == 503:
                    mark_badappid(appid)
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
                    if check_appid_exists(appid):
                        continue
                    elif len(GC.GAE_APPIDS) > 1:
                        GC.GAE_APPIDS.remove(appid)
                        for _ in range(GC.GAE_MAXREQUESTS):
                            qGAE.get()
                        logging.warning('APPID %r 不存在，将被移除', appid)
                        self.do_GAE()
                    else:
                        logging.error('APPID %r 不存在，请将你的 APPID 填入 Config.ini 中', appid)
                        if headers_sent:
                            self.close_connection = True
                        else:
                            c = message_html('404 AppID 不存在',
                                             'AppID %r 不存在' % appid,
                                             '请编辑 %r 文件，将你的 AppID 填入其中并重启 GotoX。' % GC.CONFIG_FILENAME).encode()
                            self.write(b'HTTP/1.1 502 Service Unavailable\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n' % len(c))
                            self.write(c)
                    return
                content_length = self.get_response_length(response)
                #输出服务端返回的错误信息
                if response.app_status != 200:
                    if not headers_sent:
                        response, data, need_chunked = self.handle_response_headers(response)
                        self.write_response_content(data, response, need_chunked)
                    return
                #发生异常时的判断条件，放在 read 操作之前
                content_range = response.headers.get('Content-Range')
                accept_ranges = response.headers.get('Accept-Ranges')
                if content_range:
                    #提取返回范围信息（Requested Range Not Satisfiable）
                    if response.status != 416:
                        content_range = getrange(content_range)
                        if content_range:
                            start, end, length = content_range.group(1, 2, 3)
                            start = int(start)
                            end = int(end)
                            #长度未知时无法使用 autorange
                            if length == '*':
                                need_autorange = 0
                            elif need_autorange is 0:
                                if (    #不是原请求结束范围且长度等于服务端失败时的重试长度
                                        (end != range_end and end - start == GC.GAE_MAXSIZE)
                                        #长度超过指定大小时启用 autorange
                                        or (content_length > GC.AUTORANGE_BIG_ONSIZE)):
                                    logging.info('发现[autorange/big]匹配：%r', self.url)
                                    need_autorange = 2
                elif (  #重试中途失败的请求时返回错误
                        (headers_sent and start > 0) 
                        #服务器不支持 Range 且错误返回成功状态，直接放弃并断开连接
                        or (range_start > 0 and response.status < 300)):
                    self.close_connection = True
                    return
                elif need_autorange is 0 and accept_ranges == 'bytes' and content_length > GC.AUTORANGE_BIG_ONSIZE:
                    #长度超过指定大小时启用 autorange
                    logging.info('发现[autorange/big]匹配：%r', self.url)
                    response.status = 206
                    need_autorange = 2
                #修复某些软件无法正确处理持久连接（停用）
                self.check_useragent()
                #第一个响应，不用重复写入头部
                if not headers_sent:
                    #开始自动多线程（Partial Content）
                    if response.status == 206 and need_autorange > 0:
                        rangefetch = RangeFetchs[need_autorange](self, request_headers, payload, response)
                        response = None
                        return rangefetch.fetch()
                    response, data, need_chunked = self.handle_response_headers(response)
                    headers_sent = True
                wrote, err = self.write_response_content(data, response, need_chunked)
                start += wrote
                if err:
                    raise err
                return
            except Exception as e:
                noerror = False
                if self.conaborted:
                    raise e
                errors.append(e)
                if e.args[0] in closed_errno or \
                        (isinstance(e, NetWorkIOError) and len(e.args) > 1 and 'bad write' in e.args[1]) or \
                        (isinstance(e.args[0], list) and any('bad write' in arg for arg in e.args[0][0])):
                    #连接主动终止
                    logging.debug('%s do_GAE %r 返回 %r，终止', self.address_string(response), self.url, e)
                    self.close_connection = True
                    return
                elif retry < GC.GAE_FETCHMAX - 1:
                    if accept_ranges == 'bytes':
                        #重试支持 Range 的失败请求
                        if start > 0:
                            request_headers['Range'] = 'bytes=%d-%s' % (start, end)
                    elif start > 0:
                        #终止不支持 Range 的且中途失败的请求
                        logging.error('%s do_GAE "%s %s" 失败：%r', self.address_string(response), self.command, self.url, e)
                        self.close_connection = True
                        return
                    logging.warning('%s do_GAE "%s %s" 返回：%r，重试', self.address_string(response), self.command, self.url, e)
                else:
                    #请求失败
                    logging.exception('%s do_GAE "%s %s" 失败：%r', self.address_string(response), self.command, self.url, e)
                    self.close_connection = True
            finally:
                qGAE.put(True)
                if response:
                    response.close()
                    if noerror:
                        if GC.GAE_KEEPALIVE:
                            #放入套接字缓存
                            http_gws.ssl_connection_cache['google_fe:443'].append((time(), response.sock))
                        else:
                            #干扰严重时考虑不复用
                            response.sock.close()
                if retry == GC.GAE_FETCHMAX - 1 and not headers_sent:
                    c = message_html('504 GAE 响应超时', 'GAE-%r 请求超时，请稍后重试。' % self.url, str(errors)).encode()
                    self.write(b'HTTP/1.1 504 Gateway Timeout\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n' % len(c))
                    self.write(c)

    #未配置 AppID
    if not GC.GAE_APPIDS:
        def do_GAE(self):
            noid = '请编辑 %r 文件，添加可用的 AppID 到 [gae] 配置中并重启 GotoX！' % GC.CONFIG_FILENAME
            logging.critical(noid)
            c = message_html('404 AppID 为空', 'AppID 配置为空，无法使用 GAE 代理', noid).encode()
            self.write(b'HTTP/1.1 502 Service Unavailable\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n' % len(c))
            self.write(c)
            return

    def do_FORWARD(self):
        #转发到请求地址
        hostname = self.hostname
        http_util = http_gws if hostname.startswith('google') else http_nor
        host, port = self.host, self.port
        hostip = None
        remote = None
        if not GC.PROXY_ENABLE:
            connection_cache_key = '%s:%d' % (hostname, port)
            for _ in range(2):
                try:
                    remote = http_util.create_connection((host, port), hostname, connection_cache_key, self.ssl, self.fwd_timeout)
                    break
                except NetWorkIOError as e:
                    logging.warning('%s 转发到 %r 失败：%r', self.address_string(e), self.url or host, e)
        else:
            hostip = random.choice(dns_resolve(host))
            remote = http_util.create_connection((hostip, port), self.ssl, self.fwd_timeout)
        if remote is None:
            if not isdirect(host):
                if self.command == 'CONNECT':
                    logging.warning('%s%s do_FORWARD 连接远程主机 (%r, %r) 失败，尝试使用 "FAKECERT & GAE" 规则。', self.address_string(), hostip or '', host, port)
                    self.go_FAKECERT_GAE()
                elif self.headers.get('Upgrade') == 'websocket':
                    logging.warning('%s%s do_FORWARD websocket 连接远程主机 (%r, %r) 失败。', self.address_string(), hostip or '', host, port)
                else:
                    logging.warning('%s%s do_FORWARD 连接远程主机 (%r, %r) 失败，尝试使用 "GAE" 规则。', self.address_string(), hostip or '', host, port)
                    self.go_GAE()
            return
        if self.fakecert:
            remote = http_util.get_ssl_socket(remote, http_util.get_server_hostname(connection_cache_key, host))
            remote.connect(remote.xip)
            remote.do_handshake()
        if self.command == 'CONNECT':
            logging.info('%s "FWD %s %s:%d HTTP/1.1" - -', self.address_string(remote), self.command, host, port)
        else:
            logging.info('%s "FWD %s %s HTTP/1.1" - -', self.address_string(remote), self.command, self.url)
        self.forward_connect(remote)

    def do_PROXY(self):
        #转发到其它代理
        proxytype, proxyuser, proxypass, proxyaddress = parse_proxy(self.target)
        proxyhost, _, proxyport = proxyaddress.rpartition(':')
        ips = dns_resolve(proxyhost).copy()
        if ips:
            ipcnt = len(ips) 
        else:
            logging.error('%s 代理地址无法解析：%s', self.address_string(), self.target)
            return
        if ipcnt > 1:
            #优先使用未使用 IP，之后按连接速度排序
            ips.sort(key=lambda ip: self.proxy_connection_time.get(ip, 0))
        proxyport = int(proxyport)
        while ips:
            proxyip = ips.pop(0)
            host = dns_resolve(self.host)[0] if self.target in proxy_no_rdns else self.host
            if proxytype:
                proxytype = proxytype.upper()
            if proxytype not in socks.PROXY_TYPES:
                proxytype = 'HTTP'
            proxy_sock = http_nor.get_proxy_socket(proxyip, 8)
            proxy_sock.set_proxy(socks.PROXY_TYPES[proxytype], proxyip, proxyport, True, proxyuser, proxypass)
            if ipcnt > 1:
                start_time = time()
            try:
                if self.fakecert:
                    proxy_sock = http_nor.get_ssl_socket(proxy_sock, None if isip(self.host) else self.host.encode())
                proxy_sock.connect((host, self.port))
                if self.fakecert:
                    proxy_sock.do_handshake()
            except Exception as e:
                if '0x5b' in e.msg and not isip(host):
                    proxy_no_rdns.add(self.target)
                    ips.insert(0, proxyip)
                else:
                    if ipcnt > 1:
                        self.proxy_connection_time[proxyip] = self.fwd_timeout + 1 + random.random()
                    logging.error('%s%s:%d 转发 "%s %s" 到 [%s] 代理失败：%s',
                                  self.address_string(), proxyip, proxyport, self.command, self.url or self.path, proxytype, self.target)
                continue
            else:
                if ipcnt > 1:
                    self.proxy_connection_time[proxyip] = time() - start_time
            logging.info('%s%s:%d 转发 "%s %s" 到 [%s] 代理：%s',
                         self.address_string(), proxyip, proxyport, self.command, self.url or self.path, proxytype, self.target)
            proxy_sock.xip = proxyip, proxyport
            self.forward_connect(proxy_sock)

    def do_REDIRECT(self):
        #重定向到目标地址
        self.close_connection = False
        target, _ = self.target
        logging.info('%s 重定向 %r 到 %r', self.address_string(), self.url, target)
        self.write('HTTP/1.1 301 Moved Permanently\r\nLocation: %s\r\nContent-Length: 0\r\n\r\n' % target)

    def do_IREDIRECT(self):
        #直接返回重定向地址的内容
        target, (mhost, raction) = self.target
        if target.startswith('file://'):
            filename = target.lstrip('file:').lstrip('/')
            logging.info('%s %r 匹配本地文件 %r', self.address_string(), self.url, filename)
            self.do_LOCAL(filename)
        else:
            logging.info('%s 内部重定向 %r 到 %r', self.address_string(), self.url, target)
            #重设网址
            origurl = self.url
            self.url = url = target
            #重设协议
            origssl = self.ssl
            self.url_parts = url_parts = urlparse.urlsplit(target)
            self.ssl = url_parts.scheme == 'https'
            #重设主机和端口
            origport = self.port
            self.parse_host(None, url_parts.netloc, mhost)
            #未明确定义重定向端口时不改变原非标准端口
            if origport not in (80, 443) and self.port in (80, 443):
                self.ssl = origssl
                self.port = origport
                scheme = 'https' if origssl else 'http'
                netloc = '%s:%d' % (self.host, origport)
                self.url_parts = url_parts = urlparse.SplitResult(scheme, netloc, url_parts.path, url_parts.query, '')
                self.url = url = url_parts.geturl()
                logging.warning('%s 由于 %r 使用了非标准端口且重定向目标未明确定义端口，重新内部重定向到 %r', self.address_string(), origurl, url)
            #重设路径
            self.path = target[target.find('/', target.find('//')+3):]
            #重设 action
            if raction:
                if isinstance(raction, str):
                    self.action, self.target = raction, None
                else:
                    self.action, self.target = raction
            else:
                self.action, self.target = get_action(url_parts.scheme, self.host, self.path[1:], url)
            self.do_action()

    def do_FAKECERT(self):
        #为当前客户连接配置一个伪造证书
        if not self.ssl:
            self.close_connection = False
            return
        if self.ssl_request:
            #已经使用 MSG_PEEK 预读过一次<<加密连接>>丢失可读状态
            #再次握手无法读取到数据，故使用套接字对进行串接
            p1, p2 = socket.socketpair()
            payload = self.connection.recv(65536)
            thread.start_new_thread(self.forward_socket, (self.connection, p1, payload))
            self.connection = p2
            self.disable_nagle_algorithm = False
            logging.warning('%s 正在使用 https 代理协议代理 https 连接，host=%r，建议将 https 连接的代理协议单独设置为 http', self.address_string(), self.host)
        context = self.get_context()
        try:
            ssl_sock = SSLConnection(context, self.connection)
            ssl_sock.set_accept_state()
            self.fakecert = True
        except ssl.SSLEOFError:
            return
        except Exception as e:
            if e.args[0] not in pass_errno:
                logging.exception('%s 伪造加密连接失败：host=%r，%r', self.address_string(), self.host, e)
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
            #关闭加密套接字，并没有真正关闭，还有 2 个 makefile
            ssl_sock.close()

    def list_dir(self, path, displaypath):
        #列表目录后将内容写入 html
        #改自 http.server.SimpleHTTPRequestHandler.list_directory
        #统一使用 UTF-8 编码
        try:
            namelist = os.listdir(path)
        except OSError as e:
            return e
        namelist.sort(key=lambda a: a.lower())
        r = []
        displaypath = html.escape(displaypath)
        title = 'GotoX web 目录列表 - %s' % displaypath
        r.append('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" '
                 '"http://www.w3.org/TR/html4/strict.dtd">\n'
                 '<html>\n<head>\n'
                 '<meta http-equiv="Content-Type" '
                 'content="text/html; charset=utf-8">\n'
                 '<title>%s</title>\n'
                 '</head>\n<body>' % title)
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
        content = '\n'.join(r).encode(errors='surrogateescape')
        l = len(content)
        self.write('HTTP/1.1 200 Ok\r\n'
                   'Content-Length: %s\r\n'
                   'Content-Type: text/html; charset=utf-8\r\n\r\n' % l)
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
        #发送证书
        if self.path.lower() in self.CAPath:
            return self.send_CA()
        #执行 GotoX 命令
        elif self.url_parts.path == '/docmd':
            return self.do_CMD()
        #返回一个本地文件或目录
        self.close_connection = False
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
        #返回本地文件
        if os.path.isfile(filename):
            content_type = self.guess_type(filename)
            try:
                filesize = os.path.getsize(filename)
                with open(filename, 'rb') as fp:
                    data = fp.read(1048576) # 1M
                    logging.info('%s "%s %s HTTP/1.1" 200 %d',
                        self.address_string(), self.command, self.url, filesize)
                    self.write('HTTP/1.1 200 Ok\r\n'
                               'Content-Length: %s\r\n'
                               'Content-Type: %s\r\n\r\n'
                               % (filesize, content_type))
                    while data:
                        self.write(data, True)
                        data = fp.read(1048576)
            except Exception as e:
                logging.warning('%s "%s %s HTTP/1.1" 403 -，无法打开本地文件：%r',
                    self.address_string(), self.command, self.url, filename)
                c = ('<title>403 拒绝</title>\n'
                     '<h1>403 无法打开本地文件：</h1><hr>\n'
                     '<h2><li>%s</li></h2>\n'
                     '<h2><li>%s</li></h2>\n'
                     % (filename, e)).encode()
                self.write('HTTP/1.1 403 Forbidden\r\n'
                           'Content-Type: text/html; charset=utf-8\r\n'
                           'Content-Length: %d\r\n\r\n' % len(c))
                self.write(c)
        else:
            logging.warning('%s "%s %s HTTP/1.1" 404 -，无法找到本地文件：%r',
                self.address_string(), self.command, self.url, filename)
            c = ('<title>404 无法找到</title>\n'
                 '<h1>404 无法找到本地文件：</h1><hr>\n'
                 '<h2><li>%s</li></h2>\n' % filename).encode()
            self.write('HTTP/1.1 404 Not Found\r\n'
                       'Content-Type: text/html; charset=utf-8\r\n'
                       'Content-Length: %d\r\n\r\n' % len(c))
            self.write(c)

    def do_BLOCK(self):
        #返回空白内容
        self.close_connection = False
        self.write(b'HTTP/1.1 200 Ok\r\n'
                   b'Cache-Control: max-age=86400\r\n'
                   b'Expires:Oct, 01 Aug 2100 00:00:00 GMT\r\n')
        if self.url_parts and \
                self.url_parts.path.endswith(('.jpg', '.gif', '.jpeg', '.png', '.bmp')):
            content = (b'GIF89a\x01\x00\x01\x00\x80\xff\x00\xc0\xc0\xc0'
                       b'\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00'
                       b'\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;')
            self.write(b'Content-Type: image/gif\r\n'
                       b'Content-Length: %d\r\n\r\n' % len(content))
            self.write(content)
        else:
            self.write(b'Content-Length: 0\r\n\r\n')
        logging.warning('%s "%s %s" 已经被拦截', self.address_string(), self.command, self.url or self.host)

    def _set_temp_GAE(self):
        hostparts = 'https' if self.ssl else 'http', self.host
        host = '%s://%s' % hostparts
        #最近是否失败（缓存设置超时两分钟）
        try:
            f = self.badhost[host] & 12
            if f == 0:
                self.badhost[host] |= 4
            elif f == 4:
                set_temp_action(*hostparts, self.path[1:])
                logging.warning('将 %r 加入 "GAE" 规则%s。', host, GC.LINK_TEMPTIME_S)
                self.badhost[host] |= 8
        except KeyError:
            self.badhost[host] = 4

    def _set_temp_FAKECERT(self):
        host = 'http%s://%s' % ('s' if self.ssl else '', self.host)
        #最近是否失败（缓存设置超时两分钟）
        try:
            f = self.badhost[host] & 3
            if f == 0:
                self.badhost[host] |= 1
            elif f == 1:
                set_temp_connect_action(host)
                logging.warning('将 %r 加入 "FAKECERT" 规则%s。', host, GC.LINK_TEMPTIME_S)
                self.badhost[host] |= 2
        except KeyError:
            self.badhost[host] = 1

    def go_GAE(self):
        if self.command not in self.gae_fetcmds:
            return self.go_BAD()
        self._set_temp_GAE()
        self.action = 'do_GAE'
        self.do_action()

    def go_FAKECERT(self):
        self._set_temp_FAKECERT()
        self.action = 'do_FAKECERT'
        self.do_action()

    def go_FAKECERT_GAE(self):
        self.path = '/'
        self._set_temp_GAE()
        self._set_temp_GAE()
        self.go_FAKECERT()

    def go_BAD(self):
        self.close_connection = False
        logging.warn('%s request "%s %s" 失败, 返回 404', self.address_string(), self.command, self.url)
        c = message_html('404 无法访问', '不能 "%s %s"' % (self.command, self.url), '无论是通过 GAE 还是 DIRECT 都无法访问成功').encode()
        self.write(b'HTTP/1.0 404\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n' % len(c))
        self.write(c)

    def forward_socket(self, local, remote, payload=None, timeout=60, tick=4, bufsize=8192, maxping=None, maxpong=None):
        if payload:
            remote.sendall(payload)
        buf = memoryview(bytearray(bufsize))
        maxpong = maxpong or timeout
        allins = [local, remote]
        timecount = timeout
        remote_silence_time = 0
        try:
            while allins and timecount > 0:
                start_time = time()
                ins, _, err = select(allins, [], allins, tick)
                t = time() - start_time
                timecount -= int(t)
                if err:
                    raise socket.error(err)
                for sock in ins:
                    ndata = sock.recv_into(buf)
                    if ndata:
                        other = local if sock is remote else remote
                        other.sendall(buf[:ndata])
                    else:
                        allins.remove(sock)
                if remote in allins and remote in ins:
                    remote_silence_time = 0
                else:
                    remote_silence_time += t
                    if remote_silence_time > maxpong:
                        break
                if ins and len(allins) == 2:
                    timecount = min(timecount*2, maxpong)
        finally:
            remote.close()

    def forward_connect(self, remote, timeout=0, tick=4, bufsize=32768, maxping=None, maxpong=None):
        #在本地与远程连接间进行数据转发
        payload = None
        if self.command != 'CONNECT':
            request_data = []
            #某些服务器不接受包含完整网址的命令
            #request_data.append(self.requestline)
            request_data.append('%s %s %s' % (self.command, self.path, self.protocol_version))
            for k, v in self.headers.items():
                if not k.title().startswith('Proxy-'):
                    request_data.append('%s: %s' % (k.title(), v))
            request_data.append('\r\n')
            rebuilt_request = '\r\n'.join(request_data).encode()
            _, payload = self.handle_request_headers()
            if isinstance(payload, bytes) and payload:
                payload = rebuilt_request + payload
            else:
                payload = rebuilt_request
        elif self.ssl_request:
            #已经使用 MSG_PEEK 预读过一次<<加密连接>>
            # select 无法获取这次的可读状态，故先读取出来
            payload = self.connection.recv(65536)
        try:
            self.forward_socket(self.connection, remote, payload, timeout or self.fwd_keeptime, tick, bufsize, maxping, maxpong)
        except NetWorkIOError as e:
            if e.args[0] not in pass_errno:
                logging.warning('%s 转发 "%s" 失败：%r', self.address_string(remote), self.url or self.host, e)
                raise
        finally:
            logging.debug('%s 转发终止："%s"', self.address_string(remote), self.url or self.host)
            #必须在这里设置关闭，前面关闭不起作用，但是中间并没有设置过不关闭？
            self.close_connection = True

    def get_context(self, servername=None):
        #维护一个 ssl context 缓存
        host = servername or self.host
        ip = isip(host)
        if not ip:
            hostsp = host.split('.')
            #浏览器不会对域名本身的有效性进行验证
            #如：com.cn 可以作为主机名，也可以使用未注册的顶级域名
            if len(hostsp) > 2:
                host = '.'.join(hostsp[1:])
        try:
            return self.context_cache[host]
        except KeyError:
            certfile = CertUtil.get_cert(host, ip)
            self.context_cache[host] = context = SSL.Context(GC.LINK_LOCALSSL)
            context.use_privatekey_file(CertUtil.sub_keyfile)
            context.use_certificate_file(certfile)
            context.set_session_id('GotoX_SSL_Server')
            return context

    def send_CA(self):
        #返回 CA 证书
        from .CertUtil import ca_certfile
        with open(ca_certfile, 'rb') as fp:
            data = fp.read()
        logging.info('"%s HTTP/1.1 200"，发送 CA 证书到 %r', self.url, self.address_string())
        self.close_connection = False
        self.write(b'HTTP/1.1 200 Ok\r\n'
                   b'Content-Type: application/x-x509-ca-cert\r\n')
        if self.path.lower() == self.CAPath[1]:
            self.write(b'Content-Disposition: attachment; filename="GotoXCA.crt"\r\n')
        self.write('Content-Length: %s\r\n\r\n' % len(data))
        self.write(data)

    def do_CMD(self):
        reqs = urlparse.parse_qs(self.url_parts.query)
        cmd = reqs['cmd'][0]
        if cmd == 'reset_dns':
            #重置 DNS
            reset_dns()
        elif cmd == 'reset_autorule':
            #重置自动规则
            ACTION_FILTERS.RESET = True
        self.close_connection = False
        self.write('HTTP/1.1 204 No Content\r\n'
                   'Content-Length: 0\r\n\r\n')
        logging.warning('%s "%s %s HTTP/1.1" 204 0，GotoX 命令执行完毕。',
            self.address_string(), self.command, self.url)

    def log_error(self, format, *args):
        self.close_connection = True
        if format != "Request timed out: %r":
            logging.error('%s "%s %s %s" 失败，%s', self.address_string(), self.action[3:], self.command, self.url or self.host, format % args)

    def address_string(self, response=None):
        #返回请求和响应的地址
        if not hasattr(self, 'address_str'):
            client_ip = self.client_address[0]
            if client_ip.endswith('127.0.0.1'):
                client_ip = 'L4'
            elif client_ip == '::1':
                client_ip = 'L6'
            self.address_str = '%s:%s->' % (client_ip, self.client_address[1])
        if hasattr(self, 'port') and self.port in (80, 443):
            if hasattr(response, 'xip'):
                return '%s%s' % (self.address_str, response.xip[0])
        elif hasattr(response, 'xip'):
            return '%s%s:%s' % (self.address_str, *response.xip)
        elif hasattr(self, 'port'):
            return '%s:%s' % (self.address_str, self.port)
        return self.address_str

class GAEProxyHandler(AutoProxyHandler):

    def do_CONNECT(self):
        #处理 CONNECT 请求，使用伪造证书进行连接
        if self._do_CONNECT():
            return
        self.action = 'do_FAKECERT'
        self.do_action()

    def do_METHOD(self):
        #处理其它请求，转发到 GAE 代理
        if self._do_METHOD():
            return
        self.action = 'do_GAE'
        self.do_action()

    def go_GAE(self):
        self.go_BAD()
