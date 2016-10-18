# coding:utf-8

import os
import sys
import errno
import thread
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
from GAEUpdata import flashgaeip
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
        logging.warn('http_util.request "%s %s" failed:%s, return 404', self.command, self.path, e)
        html = message_html('Can not "%s %s" via either GAE or DIRECT' % (self.command, self.path))
        self.wfile.write(b'HTTP/1.0 404\r\nContent-Type: text/html\r\n\r\n' + html.encode('utf-8'))

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
                if self.path.endswith('ico'): # no site ico
                    logging.warn('http_util.request "%s %s" failed, return 404', self.command, self.path)
                    self.wfile.write(b'HTTP/1.1 404 %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s' % self.responses[404])
                    return
                else:
                    logging.warn('http_util.request "%s %s" failed, try using "gae"', self.command, self.path)
                    return self.go_GAE()
            if response.status != 304:
                logging.info('%s "DIRECT %s %s HTTP/1.1" %s %s', self.address_string(response), self.command, self.path, response.status, response.getheader('Content-Length', '-'))
            self.wfile.write((b'HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k.title() != 'Transfer-Encoding'))))
            data = response.read(8192)
            while data:
                self.wfile.write(data)
                data = response.read(8192)
        except NetWorkIOError as e:
            noerror = False
            if e.args[0] in (errno.ECONNRESET, 10063, errno.ENAMETOOLONG):
                logging.warn('%s http_util.request "%s %s" failed:%r, return 408', address_string(response), self.command, self.path, e)
                self.wfile.write(b'HTTP/1.1 408 %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s' % self.responses[408])
                #logging.warn('http_util.request "%s %s" failed:%s, try addto `withgae`', self.command, self.path, e)
                #self.go_GAE()
            elif e.args[0] not in (errno.ECONNABORTED, errno.EPIPE):
                raise
        except Exception as e:
            noerror = False
            host = self.headers.get('Host', '')
            logging.warning('AutoProxyHandler direct(%s) Error:%s', host, e)
            raise
        finally:
            if response:
                response.close()
                if noerror:
                    # return to sock cache
                    http_util.tcp_connection_cache[connection_cache_key].put((time(), response.sock))

    def do_GAE(self):
        """GAE http urlfetch"""
        if self.command not in ('GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'PATCH'):
            logging.warn('GAE can not support "%s %s", now using DIRECT', self.command, self.path)
            return self.do_DIRECT()
        request_headers = dict((k.title(), v) for k, v in self.headers.items())
        host = self.host
        path = self.url_parts.path
        need_autorange = any(x(host) for x in GC.AUTORANGE_HOSTS_MATCH) or path.endswith(GC.AUTORANGE_ENDSWITH)
        if path.endswith(GC.AUTORANGE_NOENDSWITH) or 'range=' in self.url_parts.query or self.command == 'HEAD':
            need_autorange = False
        if self.command != 'HEAD' and 'Range' in request_headers:
            m = self.getbytes(request_headers['Range'])
            start = int(m.group(1) if m else 0)
            request_headers['Range'] = 'bytes=%d-%d' % (start, start+GC.AUTORANGE_FIRSTSIZE-1)
            logging.info('autorange range=%r match url=%r', request_headers['Range'], self.path)
        elif need_autorange:
            logging.info('Found [autorange]endswith match url=%r', self.path)
            m = self.getbytes(request_headers.get('Range', ''))
            start = int(m.group(1) if m else 0)
            request_headers['Range'] = 'bytes=%d-%d' % (start, start+GC.AUTORANGE_FIRSTSIZE-1)

        payload = b''
        if 'Content-Length' in request_headers:
            try:
                payload = self.rfile.read(int(request_headers.get('Content-Length', 0)))
            except NetWorkIOError as e:
                logging.error('handle_method_urlfetch read payload failed:%s', e)
                return
        response = None
        range_retry = None
        errors = []
        headers_sent = False
        for retry in xrange(GC.FETCHMAX_LOCAL):
            appid = random.choice(GC.GAE_APPIDS)
            noerror = True
            try:
                end = 0
                response = gae_urlfetch(self.command, self.path, request_headers, payload, appid)
                if response is None:
                    if retry == GC.FETCHMAX_LOCAL - 1:
                        if host not in testip.tested:
                            logging.warning('"%s" trigger flashgaeip' % host)
                            testip.tested[host] = True
                            flashgaeip()
                        html = message_html('502 URLFetch failed', 'Local URLFetch %r failed' % self.path, str(errors))
                        self.wfile.write(b'HTTP/1.0 502\r\nContent-Type: text/html\r\n\r\n' + html.encode('utf-8'))
                        return
                    else:
                        logging.warning('AutoProxyHandler.do_GAE timed out, url=%r, try again', self.path)
                        continue
                # gateway error, switch to https mode
                if response.app_status in (400, 504):
                    logging.warning('AutoProxyHandler.do_GAE gateway error, url=%r, try again', self.path)
                    continue
                # appid not exists, try remove it from appid
                if response.app_status == 404:
                    if len(GC.GAE_APPIDS) > 1:
                        GC.GAE_APPIDS.remove(appid)
                        logging.warning('APPID %r not exists, remove it.', appid)
                        continue
                    else:
                        logging.error('APPID %r not exists, please ensure your appid in proxy.ini.', appid)
                        html = message_html('404 Appid Not Exists', 'Appid %r Not Exists' % appid, 'appid %r not exist, please edit your proxy.ini' % appid)
                        self.wfile.write(b'HTTP/1.0 502\r\nContent-Type: text/html\r\n\r\n' + html.encode('utf-8'))
                        return
                # appid over qouta, switch to next appid
                if response.app_status == 503:
                    if len(GC.GAE_APPIDS) > 1:
                        GC.GAE_APPIDS.remove(appid)
                        logging.info('Current APPID Over Quota,Auto Switch to [%s], Retrying…', appid)
                        self.do_GAE()
                        return
                    else:
                        logging.error('All APPID Over Quota')
                if response.app_status == 500 and need_autorange:
                    logging.warning('500 with range in query, trying another fetchserver')
                    continue
                if response.app_status != 200 and retry == GC.FETCHMAX_LOCAL-1:
                    logging.info('%s "GAE %s %s HTTP/1.1" %s -', self.address_string(response), self.command, self.path, response.status)
                    self.wfile.write((b'HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k.title() != 'Transfer-Encoding'))))
                    self.wfile.write(response.read())
                    return
                # first response, has no retry.
                if not headers_sent:
                    if response.status == 206:
                        rangefetch = RangeFetch(self.wfile, response, self.command, self.path, self.headers, payload)
                        return rangefetch.fetch()
                    if response.getheader('Set-Cookie'):
                        response.msg['Set-Cookie'] = self.normcookie(response.getheader('Set-Cookie'))
                    if response.getheader('Content-Disposition') and '"' not in response.getheader('Content-Disposition'):
                        response.msg['Content-Disposition'] = self.normattachment(response.getheader('Content-Disposition'))
                    headers_data = b'HTTP/1.1 %s\r\n%s\r\n' % (response.status, b''.join(b'%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k.title() != 'Transfer-Encoding'))
                    logging.debug('headers_data=%s', headers_data)
                    self.wfile.write(headers_data)
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
                    self.wfile.write(data)
                    data = response.read(8192)
                return
            except Exception as e:
                noerror = False
                errors.append(e)
                if e.args[0] in (10053, ) or 'bad write' in e.args[-1]:
                    # local connection abort
                    logging.warning('AutoProxyHandler.do_GAE "%s" return %r, abort.', self.path, e)
                    return
                elif range_retry:
                    # retry range only once
                    logging.exception('AutoProxyHandler.do_GAE "%s" failed:%r', self.path, e)
                    return
                elif retry < GC.FETCHMAX_LOCAL - 1:
                    if end:
                        # we can retry range fetch here
                        self.headers['Range'] = 'bytes=%d-%d' % (start, end)
                        range_retry = True
                    logging.warning('AutoProxyHandler.do_GAE "%s" return %r, try again', self.path, e)
                else:
                    # last retry failed
                    logging.exception('AutoProxyHandler.do_GAE "%s" failed:%r', self.path, e)
            finally:
                if response:
                    response.close()
                    if noerror:
                        # return to sock cache
                        http_util.ssl_connection_cache[GC.GAE_LISTNAME+':443'].put((time(), response.sock))

    def do_FAKECERT(self):
        """Deploy a fake cert to client"""
        #logging.debug('%s "AGENT %s %s:%d HTTP/1.1" - -', self.address_string(), self.command, self.host, self.port)
        self.wfile.write(b'HTTP/1.1 200 OK\r\n\r\n')
        ssl_context = self.get_ssl_context()
        try:
            ssl_sock = ssl_context.wrap_socket(self.connection, server_side=True)
        except Exception as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET):
                logging.exception('wrap_socket(self.connection=%r) failed: %s', self.host, e)
            return
        #stop normal socket read/write
        self.finish()
        #load ssl socket
        self.request = ssl_sock
        self.setup()
        try:
            #go on
            self.handle()
        finally:
            #close ssl socket, not real closed, will close in finish()
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
                    self.wfile.write(b'HTTP/1.1 200\r\nConnection: close\r\nContent-Length: %s\r\nContent-Type: %s\r\n\r\n' % (filesize, content_type))
                    while data:
                        self.wfile.write(data)
                        data = fp.read(1048576)
            except Exception as e:
                logging.info('%s "%s %s HTTP/1.1" 403 -', self.address_string(), self.command, self.path)
                self.wfile.write(b'HTTP/1.1 403\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nopen %r failed: %r' % (filename, e))
        else:
            logging.info('%s "%s %s HTTP/1.1" 404 -', self.address_string(), self.command, self.path)
            self.wfile.write(b'HTTP/1.1 404\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n404 Not Found')

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
        logging.info('HTTP/1.1" 200, return CA file to %s', self.address_string())
        self.wfile.write(b'HTTP/1.1 200\r\nContent-Type: application/x-x509-ca-cert\r\nContent-Length: %s\r\n\r\n' % len(data))
        self.wfile.write(data)

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
        logging.info('%s "PROXY %s %s:%d HTTP/1.1" - -', self.target, self.command, self.path, self.port)
        self.forward_socket(proxy)

    def do_REDIRECT(self):
        """Redirect http"""
        self.get_redirect()
        logging.info('%s "REDIRECT %s to %s"', self.address_string(), self.path, self.target)
        self.wfile.write(b'HTTP/1.1 301\r\nLocation: %s\r\n\r\n' % self.target)

    def do_IREDIRECT(self):
        """Redirect http without 30X"""
        self.get_redirect()
        if self.target.startswith('file://'):
            filename = self.target.lstrip('file:').lstrip('/')
            logging.info('%s matched local file %s, return', self.path, filename)
            self.do_LOCAL(filename)
        else:
            logging.info('%s "IREDIRECT %s to %s"', self.address_string(), self.path, self.target)
            self.path = self.target
            self.target = ''
            self.do_DIRECT()

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
                        # only logging first create_connection error
                        logging.error('http_util.create_connection((host=%r, port=%r), hostname:%s) timeout', host, port, hostname or '')
                except NetWorkIOError as e:
                    if e.args[0] == 9:
                        logging.error('%s AutoProxyHandler direct forward remote (%r, %r) failed', remote.xip[0], host, port)
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
        logging.warning('%s "%s %s HTTP/1.1" has been blocked', self.address_string(), self.command, self.path)
        self.wfile.write(content)

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
        if isinstance(self.target, partial):
            self.target = self.target(self.path, 1)
        elif isinstance(self.target, tuple):
            self.target = self.path.replace(self.target)

    def forward_socket(self, remote, timeout=30, tick=4, maxping=None, maxpong=None):
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
                        logging.warning('Forward "%s" zero retry %d', self.path, zeroretry)
                    else:
                        allins.remove(sock)
        except NetWorkIOError as e:
            #if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
            if e.args[0] not in (10053, 10054):
                logging.warning('Forward "%s" failed:%s', self.path, e)
        finally:
            remote.close()
            self.close_connection = 1
