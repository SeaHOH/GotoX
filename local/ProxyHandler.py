# coding:utf-8

import os
import sys
import errno
import re
import ssl
import socket
import random
import socks
import mimetypes
from select import select
from time import time, sleep
from functools import partial
from compat import (
    PY3,
    BaseHTTPServer,
    urlparse,
    logging,
    thread,
    xrange,
    NetWorkIOError,
    pacparser
    )
from common import (
    LRUCache,
    message_html,
    get_listen_ip,
    web_dir,
    testip,
    isipv4,
    dns,
    dns_resolve
    )
import CertUtil
from GlobalConfig import GC
from GAEUpdata import testgaeip
from HTTPUtil import http_util
from RangeFetch import RangeFetch
from GAEFetch import gae_urlfetch
from FilterUtil import (
    filters_cache,
    ssl_filters_cache,
    get_action,
    get_ssl_action
    )

HAS_PYPY = hasattr(sys, 'pypy_version_info')

class GAEProxyHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    request_queue_size = 48
    #urlfetch = staticmethod(gae_urlfetch)
    normcookie = partial(re.compile(r', ([^ =]+(?:=|$))').sub, r'\r\nSet-Cookie: \1')
    normattachment = partial(re.compile(r'filename=([^"\']+)').sub, r'filename="\1"')
    pypypath = partial(re.compile(r'(://[^/]+):\d+/').sub, r'\1/')
    getbytes = re.compile(r'bytes=(\d+)-').search
    getrange = re.compile(r'bytes (\d+)-(\d+)/(\d+)').search
    ssl_context_cache = LRUCache(64)
    fwd_timeout = GC.LINK_FWDTIMEOUT
    ssl = False
    CAfile = 'http://gotox.net/ca'
    localhosts = ('127.0.0.1', 'localhost')
    appids = GC.GAE_APPIDS[:]

    if PY3:
        def setup(self):
            BaseHTTPServer.BaseHTTPRequestHandler.setup(self)
            self.write = lambda d: self.wfile.write(d if isinstance(d, bytes) else d.encode())
    else:
        def setup(self):
            BaseHTTPServer.BaseHTTPRequestHandler.setup(self)
            self.write = self.wfile.write

    def address_string(self, response=None):
        """Return the connected ip or the client's ip and port"""
        if hasattr(response, 'xip'):
            return response.xip[0]
        else:
            return '%s:%s' % self.client_address[:2]

    def do_count(self):
        """Count alive-connects which are in iplist"""
        do_x = getattr(self, self.action)
        if self.action == 'do_GAE' or (self.action in ('do_DIRECT', 'do_FORWARD') and self.target in GC.IPLIST_MAP):
            testip.qcount += 1
            testip.lastactive = time()
            do_x()
            if testip.qcount > 0:
                testip.qcount -= 1
        else:
            do_x()

    def do_CONNECT(self):
        """handle CONNECT cmmand, do a filtered action"""
        self.ssl = True
        host, _, port = self.path.rpartition(':')
        port = int(port)
        self.host, self.port = host, port
        self.action = 'do_FAKECERT'
        self.do_count()

    def do_METHOD(self):
        """handle others cmmand, do a filtered action"""
        if HAS_PYPY:
            self.path = self.pypypath(self.path)
        self.host = self.headers.get('Host', '')
        if self.host.startswith(self.localhosts):
            return self.do_LOCAL()
        if self.path[0] == '/':
            self.path = '%s://%s%s' % ('https' if self.ssl else 'http', self.host, self.path)
        if self.path.lower() == self.CAfile:
            return self.send_CA()
        self.url_parts = urlparse.urlparse(self.path)
        if not self.ssl:
            if ':' in self.url_parts.netloc:
                _, _, port = self.url_parts.netloc.rpartition(':')
                self.port = int(port)
            else:
                self.port = 80
        self.action = 'do_GAE'
        self.do_count()

    do_GET = do_METHOD
    do_PUT = do_METHOD
    do_POST = do_METHOD
    do_HEAD = do_METHOD
    do_DELETE = do_METHOD
    do_OPTIONS = do_METHOD
    do_PATCH = do_METHOD

    def go_GAE(self):
        logging.warn(u'http_util.request "%s %s" 失败：%r, 返回 404', self.command, self.path, e)
        self.write(b'HTTP/1.0 404\r\nContent-Type: text/html\r\n\r\n')
        self.write(message_html(u'404 无法访问', u'不能 "%s %s"' % (self.command, self.path), u'无论是通过 GAE 还是 DIRECT 都无法访问成功').encode('utf-8'))

    def do_DIRECT(self):
        """Direct http relay"""
        hostname = self.setDNS()
        response = None
        noerror = True
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            payload = self.rfile.read(content_length) if content_length else b''
            need_crlf = hostname.startswith('google_') or self.host.endswith(GC.HTTP_CRLFSITES)
            connection_cache_key = '%s:%d' % (hostname, self.port)
            response = http_util.request(self.command, self.path, payload, self.headers, crlf=need_crlf, connection_cache_key=connection_cache_key, timeout=self.fwd_timeout)
            if not response:
                if self.path.endswith('ico'): #网站图标
                    logging.warn(u'http_util.request "%s %s" 失败，返回 404', self.command, self.path)
                    self.write('HTTP/1.1 404 %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s' % self.responses[404])
                    return
                else:
                    logging.warn(u'http_util.request "%s %s" 失败，尝试使用 "GAE"', self.command, self.path)
                    return self.go_GAE()
            if response.status != 304: #资源未修改
                logging.info('%s "DIRECT %s %s HTTP/1.1" %s %s', self.address_string(response), self.command, self.path, response.status, response.getheader('Content-Length', '-'))
            self.write(('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k.title() != 'Transfer-Encoding'))))
            data = response.read(8192)
            while data:
                self.write(data)
                data = response.read(8192)
        except NetWorkIOError as e:
            noerror = False
            if e.args[0] in (errno.ECONNRESET, 10063, errno.ENAMETOOLONG):
                logging.warn(u'%s http_util.request "%s %s" 失败：%r，返回 408', self.address_string(response), self.command, self.path, e)
                self.write('HTTP/1.1 408 %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s' % self.responses[408])
                #logging.warn('http_util.request "%s %s" failed:%s, try addto `withgae`', self.command, self.path, e)
                #self.go_GAE()
            elif e.args[0] not in (errno.ECONNABORTED, errno.EPIPE):
                raise
        except Exception as e:
            noerror = False
            logging.warn(u'%s do_DIRECT "%s %s" 失败：%r', self.address_string(response), self.command, self.path, e)
            raise
        finally:
            if response:
                response.close()
                if noerror:
                    #放入套接字缓存
                    http_util.tcp_connection_cache[connection_cache_key].put((time(), response.sock))

    def do_GAE(self):
        """GAE http urlfetch"""
        if self.command not in ('GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'PATCH'):
            logging.warn(u'GAE 不支持 "%s %s"，转用 DIRECT', self.command, self.path)
            return self.do_DIRECT()
        request_headers = dict((k.title(), v) for k, v in self.headers.items())
        host = self.host
        path = self.url_parts.path
        need_autorange = any(x(host) for x in GC.AUTORANGE_HOSTS_MATCH) or path.endswith(GC.AUTORANGE_ENDSWITH)
        if path.endswith(GC.AUTORANGE_NOENDSWITH) or 'range=' in self.url_parts.query or self.command == 'HEAD':
            need_autorange = False
        #if self.command != 'HEAD' and 'Range' in request_headers:
        #    m = self.getbytes(request_headers['Range'])
        #    start = int(m.group(1) if m else 0)
        #    request_headers['Range'] = 'bytes=%d-%d' % (start, start+GC.AUTORANGE_FIRSTSIZE-1)
        #    logging.info('autorange range=%r match url=%r', request_headers['Range'], self.path)
        #el
        if need_autorange:
            logging.info(u'发现[autorange]匹配：%r', self.path)
            m = self.getbytes(request_headers.get('Range', ''))
            start = int(m.group(1) if m else 0)
            request_headers['Range'] = 'bytes=%d-%d' % (start, start+GC.AUTORANGE_FIRSTSIZE-1)

        payload = b''
        if 'Content-Length' in request_headers:
            try:
                payload = self.rfile.read(int(request_headers.get('Content-Length', 0)))
            except NetWorkIOError as e:
                logging.error(u'%s "%s %s" 附加请求内容读取失败：%r', self.address_string(), self.command, self.path, e)
                return
        response = None
        range_retry = None
        errors = []
        headers_sent = False
        for retry in xrange(GC.FETCHMAX_LOCAL):
            if len(self.appids) > 0:
                appid = self.appids.pop()
            else:
                appid = random.choice(GC.GAE_APPIDS)
            noerror = True
            try:
                end = 0
                response = gae_urlfetch(self.command, self.path, request_headers, payload, appid)
                if response is None:
                    if retry == GC.FETCHMAX_LOCAL - 1:
                        if host not in testip.tested:
                            logging.warning(u'do_GAE：%r 触发 IP 检测' % host)
                            testip.tested[host] = True
                            testgaeip()
                        self.write(b'HTTP/1.0 502\r\nContent-Type: text/html\r\n\r\n')
                        self.write(message_html(u'502 资源获取失败', u'本地从 %r 获取资源失败' % self.path, str(errors)).encode('utf-8'))
                        return
                    else:
                        logging.warning(u'do_GAE 超时，url=%r，重试', self.path)
                        continue
                #网关错误
                if response.app_status in (400, 504):
                    logging.warning('do_GAE 网关错误，url=%r，重试', self.path)
                    continue
                # appid 不存在
                if response.app_status == 404:
                    if len(GC.GAE_APPIDS) > 1:
                        GC.GAE_APPIDS.remove(appid)
                        appid = None
                        logging.warning(u'APPID %r 不存在，将被移除', appid)
                        continue
                    else:
                        logging.error(u'APPID %r 不存在，请将你的 APPID 填入 Config.ini 中', appid)
                        html = message_html(u'404 Appid 不存在', u'Appid %r 不存在' % appid, u'请编辑 Config.ini 文件，将你的 APPID 填入其中。')
                        self.write(b'HTTP/1.0 502\r\nContent-Type: text/html\r\n\r\n')
                        self.write(html.encode('utf-8'))
                        return
                #当前 appid 流量完结，切换下一个
                if response.app_status == 503:
                    if len(GC.GAE_APPIDS) > 1:
                        GC.GAE_APPIDS.remove(appid)
                        appid = None
                        logging.info(u'当前 appid[%s] 流量使用完毕，切换下一个…', appid)
                        self.do_GAE()
                        return
                    else:
                        logging.error(u'全部的 APPID 流量都使用完毕')
                if response.app_status == 500 and 'Range' in request_headers:
                    logging.warning(u'Range 请求返回 GAE_APP 错误，重试')
                    continue
                if response.app_status != 200 and retry == GC.FETCHMAX_LOCAL-1:
                    logging.info('%s "GAE %s %s HTTP/1.1" %s -', self.address_string(response), self.command, self.path, response.status)
                    self.write(('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k.title() != 'Transfer-Encoding'))))
                    self.write(response.read())
                    return
                #第一个响应，不用重新写入头部
                if not headers_sent:
                    if response.status == 206 and need_autorange:
                        rangefetch = RangeFetch(self.wfile, response, self.command, self.path, self.headers, payload)
                        return rangefetch.fetch()
                    if response.getheader('Set-Cookie'):
                        response.msg['Set-Cookie'] = self.normcookie(response.getheader('Set-Cookie'))
                    if response.getheader('Content-Disposition') and '"' not in response.getheader('Content-Disposition'):
                        response.msg['Content-Disposition'] = self.normattachment(response.getheader('Content-Disposition'))
                    headers_data = 'HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k.title() != 'Transfer-Encoding'))
                    logging.debug('headers_data=%s', headers_data)
                    self.write(headers_data)
                    headers_sent = True
                    logging.info('%s "GAE %s %s HTTP/1.1" %s %s', self.address_string(response), self.command, self.path, response.status, response.getheader('Content-Length', '-'))
                length = response.getheader('Content-Length', '0')
                length = int(length) if length.isdigit() else 0
                content_range = response.getheader('Content-Range', '')
                if content_range:
                    start, end, length = tuple(int(x) for x in self.getrange(content_range).group(1, 2, 3))
                else:
                    start, end = 0, length-1
                data = response.read(8192)
                while data and start < length:
                    start += len(data)
                    self.write(data)
                    data = response.read(8192)
                return
            except Exception as e:
                noerror = False
                errors.append(e)
                if e.args[0] in (10053, ) or 'bad write' in e.args[-1]:
                    #本地链接终止
                    logging.debug(u'do_GAE %r 返回 %r，终止', self.path, e)
                    return
                elif range_retry:
                    # range 请求只重试一次
                    logging.exception(u'%s do_GAE "%s %s" 失败：%r', self.address_string(response), self.command, self.path, e)
                    return
                elif retry < GC.FETCHMAX_LOCAL - 1:
                    if end:
                        #重试中途失败的请求
                        self.headers['Range'] = 'bytes=%d-%d' % (start, end)
                        range_retry = True
                    logging.warning(u'%s do_GAE "%s %s" 返回：%r，重试', self.address_string(response), self.command, self.path, e)
                else:
                    #重试请求失败
                    logging.exception(u'%s do_GAE "%s %s" 失败：%r', self.address_string(response), self.command, self.path, e)
            finally:
                if appid and appid not in self.appids:
                    self.appids.append(appid)
                if response:
                    response.close()
                    if noerror:
                        #放入套接字缓存
                        http_util.ssl_connection_cache[GC.GAE_LISTNAME+':443'].put((time(), response.sock))

    def do_FAKECERT(self):
        """Deploy a fake cert to client"""
        #logging.debug('%s "AGENT %s %s:%d HTTP/1.1" - -', self.address_string(), self.command, self.host, self.port)
        self.write(b'HTTP/1.1 200 OK\r\n\r\n')
        ssl_context = self.get_ssl_context()
        try:
            ssl_sock = ssl_context.wrap_socket(self.connection, server_side=True)
        except Exception as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET):
                logging.exception(u'伪造加密链接失败：host=%r，%r', self.host, e)
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

    def do_LOCAL(self, filename=None):
        """Return a local file"""
        filename = filename or os.path.join(web_dir, urlparse.urlparse(self.path).path[1:])
        if os.path.isfile(filename):
            if filename.endswith('.pac'):
                content_type = 'text/plain'
            else:
                content_type = mimetypes.types_map.get(os.path.splitext(filename)[1])
                if not content_type:
                    content_type = 'application/octet-stream'
            try:
                filesize = os.path.getsize(filename)
                with open(filename, 'rb') as fp:
                    data = fp.read(1048576) # 1M
                    logging.info('%s "%s %s HTTP/1.1" 200 %d', self.address_string(), self.command, self.path, filesize)
                    self.write('HTTP/1.1 200\r\nConnection: close\r\nContent-Length: %s\r\nContent-Type: %s\r\n\r\n' % (filesize, content_type))
                    while data:
                        self.write(data)
                        data = fp.read(1048576)
            except Exception as e:
                logging.info('%s "%s %s HTTP/1.1" 403 -', self.address_string(), self.command, self.path)
                self.write('HTTP/1.1 403\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nopen %r failed: %r' % (filename, e))
        else:
            logging.info('%s "%s %s HTTP/1.1" 404 -', self.address_string(), self.command, self.path)
            self.write(b'HTTP/1.1 404\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n404 Not Found')

    def setDNS(self):
        """Maintain a self-DNS map"""
        if self.host not in dns:
            dns[self.host] = dns_resolve(self.host)
        return self.host

    def send_CA(self):
        """Return CA cert file"""
        from CertUtil import ca_certfile
        with open(ca_certfile, 'rb') as fp:
            data = fp.read()
        logging.info(u'"HTTP/1.1 200"，发送 CA 证书到 %r', self.address_string())
        self.write('HTTP/1.1 200\r\nContent-Type: application/x-x509-ca-cert\r\nContent-Length: %s\r\n\r\n' % len(data))
        self.write(data)

    def get_ssl_context(self):
        """Keep a ssl_context cache"""
        host = self.host
        hostsp = host.split('.')
        nhost = len(hostsp)
        if nhost > 3 or (nhost == 3 and len(hostsp[-2]) > 3):
            host = '.'.join(hostsp[1:])
        try:
            return self.ssl_context_cache[host]
        except KeyError:
            logging.debug('%s first', host)
            certfile, keyfile = CertUtil.get_cert(host)
            self.ssl_context_cache[host] = ssl_context = ssl.SSLContext(GC.LINK_LOCALSSL)
            ssl_context.verify_mode = ssl.CERT_NONE
            ssl_context.load_cert_chain(certfile, keyfile)
            return ssl_context

class AutoProxyHandler(GAEProxyHandler):

    def do_CONNECT(self):
        """handle CONNECT cmmand, do a filtered action"""
        self.ssl = True
        host, _, port = self.path.rpartition(':')
        port = int(port)
        self.host, self.port = host, port
        self.action, self.target = get_ssl_action(host)
        self.do_count()

    def do_METHOD(self):
        """handle others cmmand, do a filtered action"""
        if HAS_PYPY:
            self.path = self.pypypath(self.path)
        self.host = self.headers.get('Host', '')
        if self.host.startswith(self.localhosts):
            return self.do_LOCAL()
        if self.path[0] == '/':
            self.path = '%s://%s%s' % ('https' if self.ssl else 'http', self.host, self.path)
        if self.path.lower() == self.CAfile:
            return self.send_CA()
        self.url_parts = urlparse.urlparse(self.path)
        if not self.ssl:
            if ':' in self.url_parts.netloc:
                _, _, port = self.url_parts.netloc.rpartition(':')
                self.port = int(port)
            else:
                self.port = 80
        self.action, self.target  = get_action(self.url_parts)
        self.do_count()

    do_GET = do_METHOD
    do_PUT = do_METHOD
    do_POST = do_METHOD
    do_HEAD = do_METHOD
    do_DELETE = do_METHOD
    do_OPTIONS = do_METHOD
    do_PATCH = do_METHOD

    def do_PROXY(self):
        """Forward to proxy server"""
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
        logging.info(u'%s 转发"%s %s" 到[%s]代理 %r', self.target, self.command, self.path, proxytype, proxyhost)
        self.forward_socket(proxy)

    def do_REDIRECT(self):
        """Redirect http"""
        self.get_redirect()
        logging.info(u'%s 重定向 %r 到 %r', self.address_string(), self.path, self.target)
        self.write('HTTP/1.1 301\r\nLocation: %s\r\n\r\n' % self.target)

    def do_IREDIRECT(self):
        """Redirect http without 30X"""
        self.get_redirect()
        if self.target.startswith('file://'):
            filename = self.target.lstrip('file:').lstrip('/')
            logging.info(u'%s %r 匹配本地文件 %r', self.address_string(), self.path, filename)
            self.do_LOCAL(filename)
        else:
            logging.info(u'%s 内部重定向 %r 到 %r', self.address_string(), self.path, self.target)
            self.path = self.target
            self.target = ''
            self.do_METHOD()

    def go_GAE(self):
        filters_cache[self.host][''] = ('do_GAE', ''), ''
        if self.ssl:
            ssl_filters_cache[self.host] = 'do_FAKECERT', ''
        self.do_GAE()

    def do_FORWARD(self):
        """Forward socket"""
        hostname = self.setDNS()
        host, port = self.host, self.port
        if not GC.PROXY_ENABLE:
            connection_cache_key = '%s:%d' % (hostname, port)
            for i in xrange(5):
                try:
                    remote = http_util.create_connection((host, port), self.fwd_timeout, cache_key=connection_cache_key)
                    if remote is not None:
                        break
                    elif i == 0:
                        #只提示第一次链接失败
                        logging.error(u'create_connection((%r), hostname:%r) 超时', self.path, hostname or '')
                except NetWorkIOError as e:
                    if e.args[0] == 9:
                        logging.error(u'%s 转发到 %r 失败', remote.xip[0], self.path)
                        continue
                    else:
                        return
            if hasattr(remote, 'fileno'):
                # reset timeout default to avoid long http upload failure, but it will delay timeout retry :(
                remote.settimeout(None)
        else:
            hostip = random.choice(dns_resolve(host))
            remote = http_util.create_connection((hostip, int(port)), self.fwd_timeout)
            if not remote:
                logging.error('%s AutoProxyHandler proxy connect remote (%r, %r) failed', hostip, host, port)
                return
        logging.info('%s "FWD %s %s:%d HTTP/1.1" - -', remote.xip[0], self.command, host, port)
        self.forward_socket(remote)

    def do_BLOCK(self):
        """Return a space content with 200"""
        content = (b'HTTP/1.1 200\r\n'
                   b'Cache-Control: max-age=86400\r\n'
                   b'Expires:Oct, 01 Aug 2100 00:00:00 GMT\r\n'
                   b'Connection: close\r\n')
        if urlparse.urlparse(self.path).path.endswith(('.jpg', '.gif', '.jpeg', '.png', '.bmp')):
            content += (b'Content-Type: image/gif\r\n\r\n'
                        b'GIF89a\x01\x00\x01\x00\x80\xff\x00\xc0\xc0\xc0'
                        b'\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00'
                        b'\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;')
        else:
            content += b'\r\n'
        logging.warning(u'%s "%s %s" 已经被拦截', self.address_string(), self.command, self.path)
        self.write(content)

    def setDNS(self):
        """Maintain a self-DNS map"""
        iporname = self.target
        if self.host not in dns:
            if isinstance(iporname, list):
                dns[self.host] = iporname
            elif iporname in GC.IPLIST_MAP:
                dns[self.host] = GC.IPLIST_MAP[iporname]
                return iporname
            elif '.' in iporname or ':' in iporname:
                dns[self.host] = iporname
            else:
                dns[self.host] = dns_resolve(self.host)
        return self.host

    def get_redirect(self):
        '''Get the redirect target'''
        if isinstance(self.target, partial):
            self.target = self.target(self.path, 1)
        elif isinstance(self.target, tuple):
            self.target = self.path.replace(self.target)

    def forward_socket(self, remote, timeout=30, tick=4, maxping=None, maxpong=None):
        '''Forward local and remote connection'''
        if self.ssl:
            self.connection.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
        else:
            http_headers = ''.join('%s: %s\r\n' % (k, v) for k, v in self.headers.items())
            rebuilt_request = '%s\r\n%s\r\n' % (self.requestline, http_headers)
            remote.sendall(rebuilt_request)
        local = self.connection
        buf = bytearray(65536) # 64K
        maxpong = maxpong or timeout
        allins = [local, remote]
        zeroretry = 2
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
                        zeroretry = min(zeroretry+1, 2)
                        timecount = min(timecount*2, maxpong)
                    elif zeroretry:
                        zeroretry  -= 1
                        logging.debug('Forward "%s" zero retry %d', self.path, zeroretry)
                    else:
                        allins.remove(sock)
        except NetWorkIOError as e:
            #if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
            if e.args[0] not in (10053, 10054):
                logging.warning(u'转发 %r 失败：%r', self.path, e)
        finally:
            remote.close()
            self.close_connection = 1
