# coding:utf-8
'''HTTP Request Util'''

import sys
import os
import re
import socket
import ssl
import struct
import random
import socks
import OpenSSL
from . import clogging as logging
from select import select
from time import time, sleep
from .GlobalConfig import GC
from .compat.openssl import zero_EOF_error, SSLConnection
from .compat import (
    Queue,
    thread,
    httplib,
    urlparse
    )
from .common import cert_dir, NetWorkIOError, closed_errno, LRUCache, isip
from .common.dns import dns, dns_resolve
from .common.proxy import parse_proxy, proxy_no_rdns

GoogleG23PKP = set((
# https://pki.google.com/GIAG2.crt
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnCoEd1zYUJE6BqOC4NhQ
SLyJP/EZcBqIRn7gj8Xxic4h7lr+YQ23MkSJoHQLU09VpM6CYpXu61lfxuEFgBLE
XpQ/vFtIOPRT9yTm+5HpFcTP9FMN9Er8n1Tefb6ga2+HwNBQHygwA0DaCHNRbH//
OjynNwaOvUsRBOt9JN7m+fwxcfuU1WDzLkqvQtLL6sRqGrLMU90VS4sfyBlhH82d
qD5jK4Q1aWWEyBnFRiL4U5W+44BKEMYq7LqXIBHHOZkQBKDwYXqVJYxOUnXitu0I
yhT8ziJqs07PRgOXlwN+wLHee69FM8+6PnG33vQlJcINNYmdnfsOEXmJHjfFr45y
aQIDAQAB
-----END PUBLIC KEY-----
''',
# https://pki.goog/gsr2/GIAG3.crt
# https://pki.goog/gsr2/GTSGIAG3.crt
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAylJL6h7/ziRrqNpyGGjV
Vl0OSFotNQl2Ws+kyByxqf5TifutNP+IW5+75+gAAdw1c3UDrbOxuaR9KyZ5zhVA
Cu9RuJ8yjHxwhlJLFv5qJ2vmNnpiUNjfmonMCSnrTykUiIALjzgegGoYfB29lzt4
fUVJNk9BzaLgdlc8aDF5ZMlu11EeZsOiZCx5wOdlw1aEU1pDbcuaAiDS7xpp0bCd
c6LgKmBlUDHP+7MvvxGIQC61SRAPCm7cl/q/LJ8FOQtYVK8GlujFjgEWvKgaTUHF
k5GiHqGL8v7BiCRJo0dLxRMB3adXEmliK+v+IO9p+zql8H4p7u2WFvexH6DkkCXg
MwIDAQAB
-----END PUBLIC KEY-----
''',
# https://pki.goog/gsr4/GIAG3ECC.crt
b'''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEG4ANKJrwlpAPXThRcA3Z4XbkwQvW
hj5J/kicXpbBQclS4uyuQ5iSOGKcuCRt8ralqREJXuRsnLZo0sIT680+VQ==
-----END PUBLIC KEY-----
'''))

gws_servername = GC.GAE_SERVERNAME
gae_testgwsiplist = GC.GAE_TESTGWSIPLIST
autorange_threads = GC.AUTORANGE_FAST_THREADS

class BaseHTTPUtil:
    '''Basic HTTP Request Class'''

    use_openssl = 0
    ssl_ciphers = ssl._RESTRICTED_SERVER_CIPHERS
    wtimeout = 0

    def __init__(self, use_openssl=None, cacert=None, ssl_ciphers=None):
        if use_openssl:
            self.use_openssl = use_openssl
            self.set_ssl_option = self.set_openssl_option
            self.get_ssl_socket = self.get_openssl_socket
            self.get_peercert = self.get_openssl_peercert
            if GC.LINK_VERIFYG2PK:
                self.google_verify = self.google_verify_g23
        self.cacert = cacert
        if ssl_ciphers:
            self.ssl_ciphers = ssl_ciphers
        self.gws = gws = self.ssl_ciphers is gws_ciphers
        if gws:
            self.keeptime = GC.GAE_KEEPTIME
            self.wtimeout = GC.FINDER_MAXTIMEOUT * 1.2 / 1000
        else:
            self.keeptime = GC.LINK_KEEPTIME
            self.google_verify = lambda x: None
        self.set_ssl_option()
        import collections
        self.tcp_connection_cache = collections.defaultdict(collections.deque)
        self.ssl_connection_cache = collections.defaultdict(collections.deque)
        thread.start_new_thread(self.check_tcp_connection_cache, ())
        thread.start_new_thread(self.check_ssl_connection_cache, ())

    def set_ssl_option(self):
        #强制 GWS 使用 TLSv1.2
        self.context = context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2 if self.gws else GC.LINK_REMOTESSL)
        #validate
        context.verify_mode = ssl.CERT_REQUIRED
        self.load_cacert()
        context.check_hostname = not self.gws
        context.set_ciphers(self.ssl_ciphers)

    def set_openssl_option(self):
        #强制 GWS 使用 TLSv1.2
        self.context = context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD if self.gws else GC.LINK_REMOTESSL)
        #cache
        import binascii
        context.set_session_id(binascii.b2a_hex(os.urandom(10)))
        context.set_session_cache_mode(OpenSSL.SSL.SESS_CACHE_BOTH)
        #validate
        self.load_cacert()
        context.set_verify(OpenSSL.SSL.VERIFY_PEER, lambda c, x, e, d, ok: ok)
        context.set_cipher_list(self.ssl_ciphers)

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

    def google_verify_g23(self, sock):
        certs = sock.get_peer_cert_chain()
        if len(certs) < 3:
            raise ssl.SSLError('谷歌域名没有获取到正确的证书链：缺少中级 CA。')
        if OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, certs[1].get_pubkey()) not in GoogleG23PKP:
            raise ssl.SSLError('谷歌域名没有获取到正确的证书链：中级 CA 公钥不匹配。')
        return certs[0]

    @staticmethod
    def check_connection_alive(keeptime, wtimeout, ctime, sock):
        if time() - ctime > keeptime:
            sock.close()
            return
        try:
            rd, _, ed = select([sock], [], [sock], 0.01)
            if rd or ed:
                sock.close()
                return
            if wtimeout:
                _, wd, ed = select([], [sock], [sock], wtimeout)
                if not wd or ed:
                    sock.close()
                    return
        except OSError:
            return
        return True

    def check_tcp_connection_cache(self):
        check_connection_alive = self.check_connection_alive
        tcp_connection_cache = self.tcp_connection_cache
        keeptime = self.keeptime
        wtimeout = self.wtimeout or 2.0
        while True:
            sleep(30)
            #将键名放入元组
            keys = tuple(tcp_connection_cache.keys())
            for cache_key in keys:
                cache = tcp_connection_cache[cache_key]
                if not cache:
                    del tcp_connection_cache[cache_key]
                try:
                    while cache:
                        ctime, sock = cachedsock = cache.popleft()
                        if check_connection_alive(keeptime, wtimeout, ctime, sock):
                            cache.appendleft(cachedsock)
                            break
                except Exception as e:
                    logging.error('check_tcp_connection_cache(%s) 错误：%r', cache_key, e)

    def check_ssl_connection_cache(self):
        check_connection_alive = self.check_connection_alive
        ssl_connection_cache = self.ssl_connection_cache
        keeptime = self.keeptime
        wtimeout = self.wtimeout or 2.0
        while True:
            sleep(30)
            keys = tuple(ssl_connection_cache.keys())
            for cache_key in keys:
                cache = ssl_connection_cache[cache_key]
                if not cache:
                    del ssl_connection_cache[cache_key]
                try:
                    while cache:
                        ctime, ssl_sock = cachedsock = cache.popleft()
                        if check_connection_alive(keeptime, wtimeout, ctime, ssl_sock.sock):
                            cache.appendleft(cachedsock)
                            break
                except Exception as e:
                    logging.error('check_ssl_connection_cache(%s) 错误：%r', cache_key, e)

connect_limiter = LRUCache(512)
def set_connect_start(ip):
    try:
        connect_limiter[ip].put(True)
    except KeyError:
        #只是限制同时正在发起的链接数，并不限制链接的总数，所以设定尽量小的数字
        connect_limiter[ip] = Queue.LifoQueue(3)
        connect_limiter[ip].put(True)

def set_connect_finish(ip):
    connect_limiter[ip].get()

class HTTPUtil(BaseHTTPUtil):
    '''HTTP Request Class'''

    protocol_version = 'HTTP/1.1'
    offlinger_val = struct.pack('ii', 1, 0)

    def __init__(self, max_window=4, timeout=8, proxy='', ssl_ciphers=None, max_retry=2):
        # http://docs.python.org/dev/library/ssl.html
        # http://blog.ivanristic.com/2009/07/examples-of-the-information-collected-from-ssl-handshakes.html
        # http://src.chromium.org/svn/trunk/src/net/third_party/nss/ssl/sslenum.c
        # http://www.openssl.org/docs/apps/ciphers.html
        # openssl s_server -accept 443 -key CA.crt -cert CA.crt
        # set_ciphers as Modern Browsers
        BaseHTTPUtil.__init__(self, GC.LINK_OPENSSL, os.path.join(cert_dir, 'cacerts'), ssl_ciphers)
        self.max_window = max_window
        self.max_retry = max_retry
        self.timeout = timeout
        self.proxy = proxy
        self.tcp_connection_time = LRUCache(512 if self.gws else 4096)
        self.ssl_connection_time = LRUCache(512 if self.gws else 4096)

        if self.gws and GC.GAE_ENABLEPROXY:
            self.gws_front_connection_time = LRUCache(128)
            self.gws_front_connection_time.set('ip', LRUCache(128), noexpire=True)
            self.create_ssl_connection = self.create_gws_connection_withproxy

        #if self.proxy:
        #    dns_resolve = self.__dns_resolve_withproxy
        #    self.create_connection = self.__create_connection_withproxy
        #    self.create_ssl_connection = self.__create_ssl_connection_withproxy

    def get_tcp_ssl_connection_time(self, addr):
        return self.tcp_connection_time.get(addr, False) or self.ssl_connection_time.get(addr, self.timeout)

    def get_tcp_connection_time(self, addr):
        return self.tcp_connection_time.get(addr, self.timeout)

    def get_ssl_connection_time(self, addr):
        return self.ssl_connection_time.get(addr, self.timeout)

    def _create_connection(self, ipaddr, forward, queobj):
        ip = ipaddr[0]
        try:
            # create a ipv4/ipv6 socket object
            sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6)
            # set reuseaddr option to avoid 10048 socket error
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # set struct linger{l_onoff=1,l_linger=0} to avoid 10048 socket error
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, self.offlinger_val)
            # resize socket recv buffer 8K->1M to improve browser releated application performance
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
            # disable nagle algorithm to send http request quickly.
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
            # set a short timeout to trigger timeout retry more quickly.
            sock.settimeout(forward if forward else 1)
            set_connect_start(ip)
            # start connection time record
            start_time = time()
            # TCP connect
            sock.connect(ipaddr)
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

    def create_connection(self, address, hostname, cache_key, ssl=None, forward=None, **kwargs):
        cache = self.tcp_connection_cache[cache_key]
        newconn = forward and ssl
        keeptime = self.keeptime
        wtimeout = self.wtimeout
        used_sock = []
        try:
            while cache:
                ctime, sock = cachedsock = cache.pop()
                if newconn and hasattr(sock, 'used'):
                    used_sock.append(cachedsock)
                    continue
                if self.check_connection_alive(keeptime, wtimeout, ctime, sock):
                    if forward:
                        sock.settimeout(forward)
                    return sock
        except IndexError:
            pass
        finally:
            if newconn and used_sock:
                used_sock.reverse()
                cache.extend(used_sock)

        result = None
        host, port = address
        addresses = [(x, port) for x in dns[hostname]]
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
                thread.start_new_thread(self._create_connection, (addr, forward, queobj))
            addrslen = len(addrs)
            for n in range(addrslen):
                result = queobj.get()
                if isinstance(result, Exception):
                    addr = result.xip
                    if addresseslen > 1:
                        #临时移除 badip
                        try:
                            addresses.remove(addr)
                            addresseslen -= 1
                        except ValueError:
                            pass
                    if i == n == 0:
                        #only output first error
                        logging.warning('%s _create_connection %r 返回 %r，重试', addr[0], host, result)
                else:
                    if addrslen - n > 1:
                        thread.start_new_thread(self._close_connection, (cache, addrslen-n-1, queobj, result.tcp_time))
                    return result
        if result:
            raise result

    def _create_ssl_connection(self, ipaddr, cache_key, host, queobj, test=None, retry=None):
        ip = ipaddr[0]
        try:
            # create a ipv4/ipv6 socket object
            sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6)
            # set reuseaddr option to avoid 10048 socket error
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # set struct linger{l_onoff=1,l_linger=0} to avoid 10048 socket error
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, self.offlinger_val)
            # resize socket recv buffer 8K->1M to improve browser releated application performance
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
            # disable negal algorithm to send http request quickly.
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
            # pick up the sock socket
            if self.gws and gws_servername is not None:
                server_hostname = random.choice(gws_servername)
            elif cache_key == 'google_gws:443':
                server_hostname = b'update.googleapis.com'
            else:
                server_hostname = None if isip(host) else host.encode()
            ssl_sock = self.get_ssl_socket(sock, server_hostname)
            # set a short timeout to trigger timeout retry more quickly.
            ssl_sock.settimeout(test if test else 1)
            set_connect_start(ip)
            # start connection time record
            start_time = time()
            # TCP connect
            ssl_sock.connect(ipaddr)
            #connected_time = time()
            # set a short timeout to trigger timeout retry more quickly.
            ssl_sock.settimeout(test if test else 1.5)
            # SSL handshake
            ssl_sock.do_handshake()
            handshaked_time = time()
            # record TCP connection time
            #self.tcp_connection_time[ipaddr] = ssl_sock.tcp_time = connected_time - start_time
            # record SSL connection time
            self.ssl_connection_time[ipaddr] = ssl_sock.ssl_time = handshaked_time - start_time
            if test:
                if ssl_sock.ssl_time > test:
                    raise socket.timeout('%d 超时' % int(ssl_sock.ssl_time*1000))
            # verify Google SSL certificate.
            self.google_verify(ssl_sock)
            # sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
            ssl_sock.sock = sock
            ssl_sock.xip = ipaddr
            if test:
                self.ssl_connection_cache[cache_key].append((time(), ssl_sock))
                return queobj.put((ip, ssl_sock.ssl_time))
            # put ssl socket object to output queobj
            queobj.put(ssl_sock)
        except NetWorkIOError as e:
            # reset a large and random timeout to the ipaddr
            self.ssl_connection_time[ipaddr] = self.timeout + 1
            # close tcp socket
            sock.close()
            # any socket.error, put Excpetions to output queobj.
            e.xip = ipaddr
            if test and not retry and e.args == zero_EOF_error:
                return self._create_ssl_connection(ipaddr, cache_key, host, queobj, test, True)
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

    def create_ssl_connection(self, address, hostname, cache_key, getfast=None, **kwargs):
        cache = self.ssl_connection_cache[cache_key]
        keeptime = self.keeptime
        wtimeout = self.wtimeout
        try:
            while cache:
                ctime, ssl_sock = cache.pop()
                if self.check_connection_alive(keeptime, wtimeout, ctime, ssl_sock.sock):
                    return ssl_sock
        except IndexError:
            pass

        result = None
        host, port = address
        addresses = [(x, port) for x in dns[hostname]]
        for i in range(self.max_retry):
            addresseslen = len(addresses)
            if getfast and gae_testgwsiplist:
                #按线程数量获取排序靠前的 IP
                addresses.sort(key=self.get_ssl_connection_time)
                addrs = addresses[:autorange_threads + 1]
            else:
                if addresseslen > self.max_window:
                    addresses.sort(key=self.get_ssl_connection_time)
                    window = min((self.max_window + 1)//2 + min(i, 1), addresseslen)
                    addrs = addresses[:window] + random.sample(addresses[window:], self.max_window-window)
                else:
                    addrs = addresses
            queobj = Queue.Queue()
            for addr in addrs:
                thread.start_new_thread(self._create_ssl_connection, (addr, cache_key, host, queobj))
            addrslen = len(addrs)
            for n in range(addrslen):
                result = queobj.get()
                if isinstance(result, Exception):
                    addr = result.xip
                    if addresseslen > 1:
                        #临时移除 badip
                        try:
                            addresses.remove(addr)
                            addresseslen -= 1
                        except ValueError:
                            pass
                    if i == n == 0:
                        #only output first error
                        logging.warning('%s _create_ssl_connection %r 返回 %r，重试', addr[0], host, result)
                else:
                    if addrslen - n > 1:
                        thread.start_new_thread(self._close_ssl_connection, (cache, addrslen-n-1, queobj, result.ssl_time))
                    return result
        if result:
            raise result

#    def __create_connection_withproxy(self, address, timeout=None, source_address=None, **kwargs):
#        host, port = address
#        logging.debug('__create_connection_withproxy connect (%r, %r)', host, port)
#        _, proxyuser, proxypass, proxyaddress = parse_proxy(self.proxy)
#        try:
#            try:
#                dns_resolve(host)
#            except (socket.error, OSError):
#                pass
#            proxyhost, _, proxyport = proxyaddress.rpartition(':')
#            sock = socket.create_connection((proxyhost, int(proxyport)))
#            if host in dns:
#                hostname = random.choice(dns[host])
#            elif host.endswith('.appspot.com'):
#                hostname = 'www.google.com'
#            else:
#                hostname = host
#            request_data = 'CONNECT %s:%s HTTP/1.1\r\n' % (hostname, port)
#            if proxyuser and proxypass:
#                request_data += 'Proxy-authorization: Basic %s\r\n' % base64.b64encode(('%s:%s' % (proxyuser, proxypass)).encode()).decode().strip()
#            request_data += '\r\n'
#            sock.sendall(request_data)
#            response = httplib.HTTPResponse(sock)
#            response.begin()
#            if response.status >= 400:
#                logging.error('__create_connection_withproxy return http error code %s', response.status)
#                sock = None
#            return sock
#        except Exception as e:
#            logging.error('__create_connection_withproxy error %s', e)
#            raise

#    def __create_ssl_connection_withproxy(self, address, timeout=None, source_address=None, **kwargs):
#        host, port = address
#        logging.debug('__create_ssl_connection_withproxy connect (%r, %r)', host, port)
#        try:
#            sock = self.__create_connection_withproxy(address, timeout, source_address)
#            ssl_sock = self.get_ssl_socket(sock)
#            ssl_sock.sock = sock
#            return ssl_sock
#        except Exception as e:
#            logging.error('__create_ssl_connection_withproxy error %s', e)
#            raise

    if GC.GAE_ENABLEPROXY:
        def get_gws_front(self, getfast=None):
            if len(GC.GAE_PROXYLIST) == 1:
                return GC.GAE_PROXYLIST[0]
            proxy_list = GC.GAE_PROXYLIST.copy()
            proxy_list.sort(key=self.get_gws_front_connection_time)
            if getfast:
                return proxy_list[0]
            else:
                return random.choice((proxy_list[0], random.choice(proxy_list[1:])))

        def get_gws_front_connection_time(self, addr):
            return self.gws_front_connection_time.get(addr, self.timeout)

        def get_gws_front_connection_time_ip(self, addr):
            return self.gws_front_connection_time['ip'].get(addr, 0)

        def create_gws_connection_withproxy(self, address, hostname, cache_key, getfast=None, **kwargs):
            proxy = self.get_gws_front(getfast)
            proxytype, proxyuser, proxypass, proxyaddress = parse_proxy(proxy)
            proxyhost, _, proxyport = proxyaddress.rpartition(':')
            ips = dns_resolve(proxyhost)
            if ips:
                ipcnt = len(ips) 
            else:
                logging.error('create_gws_connection_withproxy 代理地址无法解析：%r', proxy)
                return
            if ipcnt > 1:
                #优先使用未使用 IP，之后按链接速度排序
                ips.sort(key=self.get_gws_front_connection_time_ip)
            proxyport = int(proxyport)
            ohost, port = address
            while ips:
                proxyhost = ips.pop(0)
                host = random.choice(dns[hostname])
                if proxytype:
                    proxytype = proxytype.upper()
                if proxytype not in socks.PROXY_TYPES:
                    proxytype = 'HTTP'
                proxy_sock = socks.socksocket(socket.AF_INET if ':' not in proxyhost else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # set struct linger{l_onoff=1,l_linger=0} to avoid 10048 socket error
                proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, self.offlinger_val)
                # resize socket recv buffer 8K->1M to improve browser releated application performance
                proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
                proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
                # disable nagle algorithm to send http request quickly.
                proxy_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                proxy_sock.set_proxy(socks.PROXY_TYPES[proxytype], proxyhost, proxyport, True, proxyuser, proxypass)
                start_time = time()
                try:
                    proxy_ssl_sock = self.get_ssl_socket(proxy_sock, ohost.encode())
                    proxy_ssl_sock.settimeout(self.timeout)
                    #proxy_ssl_sock.set_connect_state()
                    proxy_ssl_sock.connect((host, port))
                    proxy_ssl_sock.do_handshake()
                except Exception as e:
                    cost_time = self.timeout + 1 + random.random()
                    if ipcnt > 1:
                        self.gws_front_connection_time['ip'][proxyhost] = cost_time
                    self.gws_front_connection_time[proxy] = cost_time
                    logging.error('create_gws_connection_withproxy 链接代理 [%s] 失败：%r', proxy, e)
                    continue
                else:
                    cost_time = time() - start_time
                    if ipcnt > 1:
                        self.gws_front_connection_time['ip'][proxyhost] = cost_time
                    self.gws_front_connection_time[proxy] = cost_time
                proxy_ssl_sock.sock = proxy_sock
                proxy_ssl_sock.xip = proxyhost, proxyport
                return proxy_ssl_sock

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
            response = httplib.HTTPResponse(sock, method=method)
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

    def request(self, request_params, payload=b'', headers={}, bufsize=8192, connection_cache_key=None, getfast=None, realmethod=None, realurl=None):
        ssl = request_params.ssl
        address = request_params.host, request_params.port
        hostname = request_params.hostname
        method = request_params.command
        realmethod = realmethod or method
        url = request_params.url
        timeout = getfast or self.timeout
        has_content = realmethod in ('POST', 'PUT', 'PATCH')

        #有上传数据适当增加超时时间
        if has_content:
            timeout += 4
        #单 IP 适当增加超时时间
        elif len(dns[hostname]) == 1 and timeout < 5:
            timeout += 2
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
                    ssl_sock = self.create_ssl_connection(address, hostname, connection_cache_key, getfast=getfast)
                else:
                    sock = self.create_connection(address, hostname, connection_cache_key)
                result = ssl_sock or sock
                if result:
                    result.settimeout(timeout)
                    response =  self._request(result, method, request_params.path, self.protocol_version, headers, payload, bufsize=bufsize)
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
                    logging.warning('%s _request "%s %s" 失败：%r', ip[0], realmethod, realurl or url, e)
                    if realurl:
                        self.ssl_connection_time[ip] = self.timeout + 1
                if not realurl and e.args[0] in closed_errno:
                    raise e
                #确保不重复上传数据
                if has_content and (sock or ssl_sock):
                    return

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
    #'ECDHE+AES256+AESGCM:'
    #'RSA+AES256+AESGCM:'
    #'ECDHE+AESGCM:'
    #'RSA+AESGCM:'
    #'ECDHE+SHA384+TLSv1.2:'
    #'RSA+SHA384+TLSv1.2:'
    #'ECDHE+SHA256+TLSv1.2:'
    #'RSA+SHA256+TLSv1.2:'
    #'TLSv1.2:'
    'ALL:'
    '!RC4-SHA:'
    '!AES128-GCM-SHA256:'
    '!ECDHE-RSA-RC4-SHA:'
    '!ECDHE-RSA-AES128-GCM-SHA256:'
    '!AES128-SHA:'
    '!ECDHE-RSA-AES128-SHA:'
    #'!aNULL:!eNULL:!MD5:!DSS:!RC4:!3DES'
    '!aNULL:!eNULL:!EXPORT:!EXPORT40:!EXPORT56:!LOW:!RC4'
    )

def_ciphers = ssl._DEFAULT_CIPHERS
res_ciphers = ssl._RESTRICTED_SERVER_CIPHERS

# max_window=4, timeout=8, proxy='', ssl_ciphers=None, max_retry=2
http_gws = HTTPUtil(GC.LINK_WINDOW, GC.GAE_TIMEOUT, GC.proxy, gws_ciphers)
http_nor = HTTPUtil(GC.LINK_WINDOW, GC.LINK_TIMEOUT, GC.proxy, res_ciphers)
