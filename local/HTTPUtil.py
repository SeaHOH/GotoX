# coding:utf-8
'''HTTP Request Util'''

import sys
import os
import re
import socket
import ssl
import struct
import random
import OpenSSL
from . import clogging as logging
from select import select
from time import time, sleep
from .GlobalConfig import GC
from .compat.openssl import SSLConnection
from .compat import (
    Queue,
    thread,
    httplib,
    urlparse
    )
from .common import cert_dir, NetWorkIOError, closed_errno, isip
from .common.dns import dns, dns_resolve
from .common.proxy import parse_proxy

GoogleG2PKP = (
b'-----BEGIN PUBLIC KEY-----\n'
b'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnCoEd1zYUJE6BqOC4NhQ\n'
b'SLyJP/EZcBqIRn7gj8Xxic4h7lr+YQ23MkSJoHQLU09VpM6CYpXu61lfxuEFgBLE\n'
b'XpQ/vFtIOPRT9yTm+5HpFcTP9FMN9Er8n1Tefb6ga2+HwNBQHygwA0DaCHNRbH//\n'
b'OjynNwaOvUsRBOt9JN7m+fwxcfuU1WDzLkqvQtLL6sRqGrLMU90VS4sfyBlhH82d\n'
b'qD5jK4Q1aWWEyBnFRiL4U5W+44BKEMYq7LqXIBHHOZkQBKDwYXqVJYxOUnXitu0I\n'
b'yhT8ziJqs07PRgOXlwN+wLHee69FM8+6PnG33vQlJcINNYmdnfsOEXmJHjfFr45y\n'
b'aQIDAQAB\n'
b'-----END PUBLIC KEY-----\n'
)

class BaseHTTPUtil:
    '''Basic HTTP Request Class'''

    use_openssl = 0
    ssl_ciphers = ssl._RESTRICTED_SERVER_CIPHERS

    def __init__(self, use_openssl=None, cacert=None, ssl_ciphers=None):
        self.cacert = cacert
        if ssl_ciphers:
            self.ssl_ciphers = ssl_ciphers
        if use_openssl:
            self.use_openssl = use_openssl
            self.set_ssl_option = self.set_openssl_option
            self.get_ssl_socket = self.get_openssl_socket
            self.get_peercert = self.get_openssl_peercert
            if GC.LINK_VERIFYG2PK:
                self.google_verify = self.google_verify_g2
        self.set_ssl_option()

    def set_ssl_option(self):
        #强制 GWS 使用 TLSv1.2
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2 if self.ssl_ciphers is gws_ciphers else GC.LINK_REMOTESSL)
        #validate
        self.context.verify_mode = ssl.CERT_REQUIRED
        if self.cacert:
            self.load_cacert()
        #obfuscate
        self.context.set_ciphers(self.ssl_ciphers)

    def set_openssl_option(self):
        #强制 GWS 使用 TLSv1.2
        self.context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD if self.ssl_ciphers is gws_ciphers else GC.LINK_REMOTESSL)
        #cache
        import binascii
        self.context.set_session_id(binascii.b2a_hex(os.urandom(10)))
        self.context.set_session_cache_mode(OpenSSL.SSL.SESS_CACHE_BOTH)
        #validate
        if self.cacert:
            self.load_cacert()
            self.context.set_verify(OpenSSL.SSL.VERIFY_PEER, lambda c, x, e, d, ok: ok)
        #obfuscate
        self.context.set_cipher_list(self.ssl_ciphers)

    def load_cacert(self):
        if os.path.isdir(self.cacert):
            import glob
            cacerts = glob.glob(os.path.join(self.cacert, '*.pem'))
            if cacerts:
                for cacert in cacerts:
                    self.context.load_verify_locations(cacert)
                return
        elif os.path.isfile(self.cacert):
            self.context.load_verify_locations(self.cacert)
            return
        logging.error('未找到可信任 CA 证书集，GotoX 即将退出！请检查：%r', self.cacert)
        sys.exit(-1) 

    def get_ssl_socket(self, sock, server_hostname=None):
        return self.context.wrap_socket(sock, do_handshake_on_connect=False, server_hostname=server_hostname)

    def get_openssl_socket(self, sock, server_hostname=None):
        ssl_sock = SSLConnection(self.context, sock)
        if server_hostname:
            ssl_sock.set_tlsext_host_name(server_hostname)
        return ssl_sock

    def get_peercert(self, sock):
        return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, sock.getpeercert(True))

    def get_openssl_peercert(self, sock):
        return sock.get_peer_certificate()

    def google_verify(self, sock):
        cert = self.get_peercert(sock)
        if not cert:
            raise ssl.SSLError('没有获取到证书')
        subject = cert.get_subject()
        if subject.O != 'Google Inc':
            raise ssl.SSLError('%s 证书的公司名称（%s）不是 "Google Inc"' % (address[0], subject.O))
        return cert

    def google_verify_g2(self, sock):
        certs = sock.get_peer_cert_chain()
        if len(certs) < 3:
            raise ssl.SSLError('谷歌域名没有获取到正确的证书链：缺少中级 CA。')
        if GoogleG2PKP != OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, certs[1].get_pubkey()):
            raise ssl.SSLError('谷歌域名没有获取到正确的证书链：中级 CA 公钥不匹配。')
        return certs[0]

linkkeeptime = GC.LINK_KEEPTIME
gaekeeptime = GC.GAE_KEEPTIME
cachetimeout = GC.FINDER_MAXTIMEOUT * 1.2 / 1000
import collections
from .common import LRUCache
tcp_connection_time = LRUCache(256)
ssl_connection_time = LRUCache(256)
tcp_connection_cache = collections.defaultdict(collections.deque)
ssl_connection_cache = collections.defaultdict(collections.deque)

def check_tcp_connection_cache():
    '''check and close unavailable connection continued forever'''
    while True:
        sleep(10)
        #将键名放入元组
        keys = None
        while keys is None:
            try:
                keys = tuple(key for key in tcp_connection_cache)
            except:
                sleep(0.01)
        for cache_key in keys:
            keeptime = gaekeeptime if cache_key.startswith('google') else linkkeeptime
            cache = tcp_connection_cache[cache_key]
            if not cache:
                del tcp_connection_cache[cache_key]
            try:
                while cache:
                    ctime, sock = cache.popleft()
                    if time()-ctime > keeptime:
                        sock.close()
                        continue
                    rd, _, ed = select([sock], [], [sock], 0.01)
                    if rd or ed:
                        sock.close()
                        continue
                    _, wd, ed = select([], [sock], [sock], cachetimeout)
                    if not wd or ed:
                        sock.close()
                        continue
                    cache.appendleft((ctime, sock))
                    break
            except (IndexError, OSError):
                pass
            except Exception as e:
                if e.args[0] == 9:
                    pass
                else:
                    logging.error('链接池守护线程错误：%r', e)

def check_ssl_connection_cache():
    '''check and close unavailable connection continued forever'''
    while True:
        sleep(5)
        keys = None
        while keys is None:
            try:
                keys = tuple(key for key in ssl_connection_cache)
            except:
                sleep(0.01)
        for cache_key in keys:
            keeptime = gaekeeptime if cache_key.startswith('google') else linkkeeptime
            cache = ssl_connection_cache[cache_key]
            if not cache:
                del ssl_connection_cache[cache_key]
            try:
                while cache:
                    ctime, ssl_sock = cache.popleft()
                    sock = ssl_sock.sock
                    if time()-ctime > keeptime:
                        sock.close()
                        continue
                    rd, _, ed = select([sock], [], [sock], 0.01)
                    if rd or ed:
                        sock.close()
                        continue
                    _, wd, ed = select([], [sock], [sock], cachetimeout)
                    if not wd or ed:
                        sock.close()
                        continue
                    cache.appendleft((ctime, ssl_sock))
                    break
            except (IndexError, OSError):
                pass
            except Exception as e:
                if e.args[0] == 9:
                    pass
                else:
                    logging.error('链接池守护线程错误：%r', e)
thread.start_new_thread(check_tcp_connection_cache, ())
thread.start_new_thread(check_ssl_connection_cache, ())

connect_limiter = LRUCache(512)
def set_connect_start(ip):
    if ip not in connect_limiter:
        #只是限制同时正在发起的链接数，并不限制链接的总数，所以设定尽量小的数字
        connect_limiter[ip] = Queue.LifoQueue(3)
    connect_limiter[ip].put(True)

def set_connect_finish(ip):
    connect_limiter[ip].get()

class HTTPUtil(BaseHTTPUtil):
    '''HTTP Request Class'''

    protocol_version = 'HTTP/1.1'

    def __init__(self, max_window=4, timeout=8, proxy='', ssl_ciphers=None, max_retry=2):
        # http://docs.python.org/dev/library/ssl.html
        # http://blog.ivanristic.com/2009/07/examples-of-the-information-collected-from-ssl-handshakes.html
        # http://src.chromium.org/svn/trunk/src/net/third_party/nss/ssl/sslenum.c
        # http://www.openssl.org/docs/apps/ciphers.html
        # openssl s_server -accept 443 -key CA.crt -cert CA.crt
        # set_ciphers as Modern Browsers
        self.max_window = max_window
        self.max_retry = max_retry
        self.timeout = timeout
        self.proxy = proxy
        self.tcp_connection_time = tcp_connection_time
        self.ssl_connection_time = ssl_connection_time
        #if self.proxy:
        #    dns_resolve = self.__dns_resolve_withproxy
        #    self.create_connection = self.__create_connection_withproxy
        #    self.create_ssl_connection = self.__create_ssl_connection_withproxy
        BaseHTTPUtil.__init__(self, GC.LINK_OPENSSL, os.path.join(cert_dir, 'cacerts'), ssl_ciphers)

    def get_tcp_ssl_connection_time(self, addr):
        return self.tcp_connection_time.get(addr, False) or self.ssl_connection_time.get(addr, self.timeout)

    def get_tcp_connection_time(self, addr):
        return self.tcp_connection_time.get(addr, self.timeout)

    def get_ssl_connection_time(self, addr):
        return self.ssl_connection_time.get(addr, self.timeout)

    def _create_connection(self, ipaddr, timeout, forward, queobj):
        ip = ipaddr[0]
        try:
            # create a ipv4/ipv6 socket object
            sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6)
            # set reuseaddr option to avoid 10048 socket error
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # set struct linger{l_onoff=1,l_linger=0} to avoid 10048 socket error
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            # resize socket recv buffer 8K->32K to improve browser releated application performance
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
            # disable nagle algorithm to send http request quickly.
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
            # set a short timeout to trigger timeout retry more quickly.
            sock.settimeout(timeout if forward else 1)
            set_connect_start(ip)
            # start connection time record
            start_time = time()
            # TCP connect
            sock.connect(ipaddr)
            # set a normal timeout
            if not forward:
                sock.settimeout(timeout)
            # record TCP connection time
            self.tcp_connection_time[ipaddr] = sock.tcp_time = time() - start_time
            # put socket object to output queobj
            sock.xip = ipaddr
            queobj.put(sock)
        except NetWorkIOError as e:
            # any socket.error, put Excpetions to output queobj.
            e.xip = ipaddr
            queobj.put(e)
            # reset a large and random timeout to the ipaddr
            self.tcp_connection_time[ipaddr] = self.timeout + 1
            # close tcp socket
            sock.close()
        finally:
            set_connect_finish(ip)

    def _close_connection(self, cache, count, queobj, first_tcp_time):
        now = time()
        tcp_time_threshold = max(min(1.5, 1.5 * first_tcp_time), 0.5)
        for _ in range(count):
            sock = queobj.get()
            if isinstance(sock, socket.socket):
                if sock.tcp_time < tcp_time_threshold:
                    cache.append((now, sock))
                else:
                    sock.close()

    def create_connection(self, address, hostname, cache_key, timeout, ssl=None, forward=None, **kwargs):
        cache = tcp_connection_cache[cache_key]
        try:
            keeptime = gaekeeptime if cache_key.startswith('google') else linkkeeptime
            while cache:
                ctime, sock = cache.pop()
                try:
                    rd, _, ed = select([sock], [], [sock], 0.01)
                    if rd or ed or time()-ctime > keeptime:
                        sock.close()
                    else:
                        return sock
                except OSError:
                    pass
        except IndexError:
            pass

        result = None
        host, port = address
        addresses = [(x, port) for x in dns[hostname]]
        #单 IP 适当增加超时时间
        if len(addresses) == 1 and timeout < 5:
            timeout += 2
        if ssl:
            get_connection_time = self.get_tcp_ssl_connection_time
        else:
            get_connection_time = self.get_tcp_connection_time
        for i in range(self.max_retry):
            addresseslen = len(addresses)
            if addresseslen > self.max_window:
                addresses.sort(key=get_connection_time)
                window = min((self.max_window+1)//2 + min(i, 1), addresseslen)
                addrs = addresses[:window] + random.sample(addresses[window:], self.max_window-window)
            else:
                addrs = addresses
            queobj = Queue.Queue()
            for addr in addrs:
                thread.start_new_thread(self._create_connection, (addr, timeout, forward, queobj))
            addrslen = len(addrs)
            for i in range(addrslen):
                result = queobj.get()
                if isinstance(result, Exception):
                    addr = result.xip
                    #临时移除 badip
                    try:
                        addresses.remove(addr)
                    except ValueError:
                        pass
                    if i == 0:
                        #only output first error
                        logging.warning('%s _create_connection %r 返回 %r，重试', addr[0], host, result)
                else:
                    thread.start_new_thread(self._close_connection, (cache, addrslen-i-1, queobj, result.tcp_time))
                    return result
        if result:
            raise result

    def _create_ssl_connection(self, ipaddr, hostname, cache_key, timeout, host, queobj, test=None, retry=None):
        ip = ipaddr[0]
        try:
            # create a ipv4/ipv6 socket object
            sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6)
            # set reuseaddr option to avoid 10048 socket error
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # set struct linger{l_onoff=1,l_linger=0} to avoid 10048 socket error
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            # resize socket recv buffer 8K->32K to improve browser releated application performance
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
            # disable negal algorithm to send http request quickly.
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
            # pick up the sock socket
            if cache_key == 'google_gws:443':
                server_hostname = b'www.google.com'
            else:
                server_hostname = None if isip(host) else host.encode()
            ssl_sock = self.get_ssl_socket(sock, server_hostname)
            # set a short timeout to trigger timeout retry more quickly.
            ssl_sock.settimeout(1)
            set_connect_start(ip)
            # start connection time record
            start_time = time()
            # TCP connect
            ssl_sock.connect(ipaddr)
            #connected_time = time()
            # set a short timeout to trigger timeout retry more quickly.
            ssl_sock.settimeout(timeout if test else 1.5)
            # SSL handshake
            ssl_sock.do_handshake()
            # set a normal timeout
            ssl_sock.settimeout(timeout)
            handshaked_time = time()
            # record TCP connection time
            #self.tcp_connection_time[ipaddr] = ssl_sock.tcp_time = connected_time - start_time
            # record SSL connection time
            self.ssl_connection_time[ipaddr] = ssl_sock.ssl_time = handshaked_time - start_time
            if test:
                if ssl_sock.ssl_time > timeout:
                    raise socket.timeout('%d 超时' % int(ssl_sock.ssl_time*1000))
            # verify SSL certificate.
            if cache_key.startswith('google'):
                self.google_verify(ssl_sock)
            # sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
            ssl_sock.sock = sock
            ssl_sock.xip = ipaddr
            if test:
                ssl_connection_cache[cache_key].append((time(), ssl_sock))
                return test.put((ip, ssl_sock.ssl_time))
            # put ssl socket object to output queobj
            queobj.put(ssl_sock)
        except NetWorkIOError as e:
            # reset a large and random timeout to the ipaddr
            self.ssl_connection_time[ipaddr] = self.timeout + 1
            # close tcp socket
            sock.close()
            # any socket.error, put Excpetions to output queobj.
            e.xip = ipaddr
            if test:
                if not retry and e.args == (-1, 'Unexpected EOF'):
                    return self._create_ssl_connection(ipaddr, hostname, cache_key, timeout, host, test, test, True)
                return test.put(e)
            queobj.put(e)
        finally:
            set_connect_finish(ip)

    def _close_ssl_connection(self, cache, count, queobj, first_ssl_time):
        now = time()
        ssl_time_threshold = max(min(1.5, 1.5 * first_ssl_time), 1.0)
        for _ in range(count):
            ssl_sock = queobj.get()
            if isinstance(ssl_sock, (SSLConnection, ssl.SSLSocket)):
                if ssl_sock.ssl_time < ssl_time_threshold:
                    cache.append((now, ssl_sock))
                else:
                    ssl_sock.sock.close()

    def create_ssl_connection(self, address, hostname, cache_key, timeout, test=None, getfast=None, **kwargs):
        if test:
            return self._create_ssl_connection(address, hostname, cache_key, timeout, None, test, test)

        cache = ssl_connection_cache[cache_key]
        try:
            keeptime = gaekeeptime if cache_key.startswith('google') else linkkeeptime
            while cache:
                ctime, ssl_sock = cache.pop()
                try:
                    rd, _, ed = select([ssl_sock.sock], [], [ssl_sock.sock], 0.01)
                    if rd or ed or time()-ctime > keeptime:
                        ssl_sock.sock.close()
                    else:
                        ssl_sock.settimeout(timeout)
                        return ssl_sock
                except OSError:
                    pass
        except IndexError:
            pass

        result = None
        host, port = address
        addresses = [(x, port) for x in dns[hostname]]
        #单 IP 适当增加超时时间
        if len(addresses) == 1 and timeout < 5:
            timeout += 2
        for i in range(self.max_retry):
            addresseslen = len(addresses)
            if getfast and GC.GAE_USEGWSIPLIST:
                #按线程数量获取排序靠前的 IP
                addresses.sort(key=self.get_ssl_connection_time)
                addrs = addresses[:GC.AUTORANGE_THREADS+1]
            else:
                if addresseslen > self.max_window:
                    addresses.sort(key=self.get_ssl_connection_time)
                    window = min((self.max_window+1)//2 + min(i, 1), addresseslen)
                    addrs = addresses[:window] + random.sample(addresses[window:], self.max_window-window)
                else:
                    addrs = addresses
            queobj = Queue.Queue()
            for addr in addrs:
                thread.start_new_thread(self._create_ssl_connection, (addr, hostname, cache_key, timeout, host, queobj))
            addrslen = len(addrs)
            for i in range(addrslen):
                result = queobj.get()
                if isinstance(result, Exception):
                    addr = result.xip
                    #临时移除 badip
                    try:
                        addresses.remove(addr)
                    except ValueError:
                        pass
                    if i == 0:
                        #only output first error
                        logging.warning('%s _create_ssl_connection %r 返回 %r，重试', addr[0], host, result)
                else:
                    thread.start_new_thread(self._close_ssl_connection, (cache, addrslen-i-1, queobj, result.ssl_time))
                    return result
        if result:
            raise result

    def __create_connection_withproxy(self, address, timeout=None, source_address=None, **kwargs):
        host, port = address
        logging.debug('__create_connection_withproxy connect (%r, %r)', host, port)
        _, proxyuser, proxypass, proxyaddress = parse_proxy(self.proxy)
        try:
            try:
                dns_resolve(host)
            except (socket.error, OSError):
                pass
            proxyhost, _, proxyport = proxyaddress.rpartition(':')
            sock = socket.create_connection((proxyhost, int(proxyport)))
            if host in dns:
                hostname = random.choice(dns[host])
            elif host.endswith('.appspot.com'):
                hostname = 'www.google.com'
            else:
                hostname = host
            request_data = 'CONNECT %s:%s HTTP/1.1\r\n' % (hostname, port)
            if proxyuser and proxypass:
                request_data += 'Proxy-authorization: Basic %s\r\n' % base64.b64encode(('%s:%s' % (proxyuser, proxypass)).encode()).decode().strip()
            request_data += '\r\n'
            sock.sendall(request_data)
            response = httplib.HTTPResponse(sock)
            response.begin()
            if response.status >= 400:
                logging.error('__create_connection_withproxy return http error code %s', response.status)
                sock = None
            return sock
        except Exception as e:
            logging.error('__create_connection_withproxy error %s', e)
            raise

    def __create_ssl_connection_withproxy(self, address, timeout=None, source_address=None, **kwargs):
        host, port = address
        logging.debug('__create_ssl_connection_withproxy connect (%r, %r)', host, port)
        try:
            sock = self.__create_connection_withproxy(address, timeout, source_address)
            ssl_sock = self.get_ssl_socket(sock)
            ssl_sock.sock = sock
            return ssl_sock
        except Exception as e:
            logging.error('__create_ssl_connection_withproxy error %s', e)
            raise

    def _request(self, sock, method, path, protocol_version, headers, payload, bufsize=8192):
        request_data = '%s %s %s\r\n' % (method, path, protocol_version)
        request_data += ''.join('%s: %s\r\n' % (k.title(), v) for k, v in headers.items())
        if self.proxy:
            _, username, password, _ = parse_proxy(self.proxy)
            if username and password:
                request_data += 'Proxy-Authorization: Basic %s\r\n' % base64.b64encode(('%s:%s' % (username, password)).encode()).decode().strip()
        request_data += '\r\n'
        request_data = request_data.encode() + payload

        sock.sendall(request_data)
        try:
            response = httplib.HTTPResponse(sock)
            response.begin()
        except Exception as e:
            #这里有时会捕捉到奇怪的异常，找不到来源路径
            # py2 的 raise 不带参数会导致捕捉到错误的异常，但使用 exc_clear 或换用 py3 还是会出现
            if hasattr(e, 'xip'):
                #logging.warning('4444 %r | %r | %r', sock.getpeername(), sock.xip, e.xip)
                del e.xip
            raise e

        response.xip =  sock.xip
        response.sock = sock
        return response

    def request(self, request_params, payload=b'', headers={}, bufsize=8192, connection_cache_key=None, getfast=None, realurl=None):
        ssl = request_params.ssl
        address = request_params.host, request_params.port
        hostname = request_params.hostname
        method = request_params.command
        url = request_params.url

        if 'Host' not in headers:
            headers['Host'] = request_params.host
        if payload:
            if not isinstance(payload, bytes):
                payload = payload.encode()
            if 'Content-Length' not in headers:
                headers['Content-Length'] = str(len(payload))

        for _ in range(self.max_retry):
            sock = None
            ssl_sock = None
            ip = ''
            try:
                if ssl:
                    ssl_sock = self.create_ssl_connection(address, hostname, connection_cache_key, getfast or self.timeout, getfast=getfast)
                else:
                    sock = self.create_connection(address, hostname, connection_cache_key, self.timeout)
                if ssl_sock or sock:
                    response =  self._request(ssl_sock or sock, method, request_params.path, self.protocol_version, headers, payload, bufsize=bufsize)
                    return response
            except Exception as e:
                if ssl_sock:
                    ip = ssl_sock.xip
                    ssl_sock.sock.close()
                elif sock:
                    ip = sock.xip
                    sock.close()
                if hasattr(e, 'xip'):
                    ip = e.xip
                    logging.warning('%s create_%sconnection %r 失败：%r', ip[0], 'ssl_' if ssl else '', realurl or url, e)
                else:
                    logging.warning('%s _request "%s %s" 失败：%r', ip[0], method, realurl or url, e)
                    if realurl:
                        self.ssl_connection_time[ip] = self.timeout + 1
                if not realurl and e.args[0] in closed_errno:
                    raise e

# Google video ip can act as Google FrontEnd if cipher suits not include
# RC4-SHA
# AES128-GCM-SHA256
# ECDHE-RSA-RC4-SHA
# ECDHE-RSA-AES128-GCM-SHA256
#不安全 cipher
# AES128-SHA
# ECDHE-RSA-AES128-SHA
# http://docs.python.org/dev/library/ssl.html
# https://www.openssl.org/docs/manmaster/man1/ciphers.html
gws_ciphers = (
    'ECDHE+AES256+AESGCM:'
    'RSA+AES256+AESGCM:'
    'ECDHE+AESGCM:'
    'RSA+AESGCM:'
    'ECDHE+SHA384+TLSv1.2:'
    'RSA+SHA384+TLSv1.2:'
    'ECDHE+SHA256+TLSv1.2:'
    'RSA+SHA256+TLSv1.2:'
    '!ECDHE-RSA-AES128-GCM-SHA256:'
    '!AES128-GCM-SHA256:'
    '!aNULL:!eNULL:!MD5:!DSS:!RC4:!3DES'
    )

def_ciphers = ssl._DEFAULT_CIPHERS
res_ciphers = ssl._RESTRICTED_SERVER_CIPHERS

# max_window=4, timeout=8, proxy='', ssl_ciphers=None, max_retry=2
http_gws = HTTPUtil(GC.LINK_WINDOW, GC.GAE_TIMEOUT, GC.proxy, gws_ciphers)
http_nor = HTTPUtil(GC.LINK_WINDOW, GC.LINK_TIMEOUT, GC.proxy, res_ciphers)
