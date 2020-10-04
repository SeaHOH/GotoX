# coding:utf-8
'''HTTP Request Util'''

import sys
import os
import errno
import socket
import random
import socks
import collections
import OpenSSL
import logging
import threading
from select import select
from time import time, sleep
from queue import Queue
from threading import _start_new_thread as start_new_thread
from http.client import HTTPResponse
from .GlobalConfig import GC
from .compat.openssl import (
    zero_errno, zero_EOF_error, res_ciphers, SSL, SSLConnection,
    CertificateError, CertificateErrorTab, match_hostname )
from .common.dns import dns, dns_resolve
from .common.internet_active import internet_v4, internet_v6
from .common.net import (
    NetWorkIOError, random_hostname, bypass_errno, isip, check_connection_dead )
from .common.decorator import make_lock_decorator
from .common.path import cert_dir
from .common.proxy import parse_proxy, proxy_no_rdns
from .common.util import LRUCache, LimiterFull, LimitDictBase, wait_exit
from .FilterUtil import reset_method_list, get_fake_sni

GoogleONames = {'Google Inc', 'Google LLC'}
GoogleICAPkeys = {
# https://pki.google.com/GIAG2.crt 已过期

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
''',
# https://pki.goog/gsr2/giag4.crt
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvSw7AnhsoyYa5z/crKtt
B52X+R0ld3UdQBU4Yc/4wmF66cpHeEOMSmhdaY5RzYrowZ6kG1xXLrSoVUuudUPR
fg/zjRqv/AAVDJFqc8OnhghzaWZU9zlhtRgY4lx4Z6pDosTuR5imCcKvwqiDztOJ
r4YKHuk23p3cxu1zDnUsuN+cm4TkVtI1SsuSc9t1uErBvFIcW6v3dLcjrPkmwE61
udZQlBDHJzCFwrhXLtXLlmuSA5/9pOuWJ+U3rSgS7ICSfa83vkBe00ymjIZT6ogD
XWuFsu4edue27nG8g9gO1YozIUCV7+zExG0G5kxTovis+FJpy9hIIxSFrRIKM4DX
aQIDAQAB
-----END PUBLIC KEY-----
''',
# https://pki.goog/gsr4/giag4ecc.crt
b'''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWgDxDsTP7Od9rB8TPUltMacYCHYI
NthcDjlPu3wP0Csmy6Drit3ghqaTqFecqcgks5RwcKQkT9rbY3e8lHuuAw==
-----END PUBLIC KEY-----
''',
# https://pki.goog/gsr2/GTS1O1.crt
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0BjPRdSLzdOc5EDvfrTd
aSEbyc88jkx1uQ8xGYQ9njwp71ANEJNvBYCAnyqgvRJLAuE9n1gWJP4wnwt0d1WT
HUv3TeGSghD2UawMw7IilA80a5gQSecLnYM53SDGHC3v0RhhZecjgyCoIxL/0iR/
1C/nRGpbTddQZrCvnkJjBfvgHMRjYa+fajP/Ype9SNnTfBRn3HXcLmno+G14adC3
EAW48THCOyT9GjN0+CPg7GsZihbG482kzQvbs6RZYDiIO60ducaMp1Mb/LzZpKu8
3Txh15MVmO6BvY/iZEcgQAZO16yX6LnAWRKhSSUj5O1wNCyltGN8+aM9g9HNbSSs
BwIDAQAB
-----END PUBLIC KEY-----
''',
# https://pki.goog/gsr2/GTS1D2.crt
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstl74eHXPxyRcv/5EM2H
FXl0tz5Hi7JhVf0MNsZ+d0I6svpSWwtxgdZN1ekrJE0jXosrcl8hVbUp70TL64JS
qz4npJJJQUreqN0x4DzfbXpNLdZtCbAO42Hysv6QbFp7EGRJtAs8CPLqeQxsphqJ
alYyoCmiMIKPgVEM86K52XW5Ip4nFLpKLyxjWIfxXRDmX5G7uVvMR+IedbaMj8x1
XVcF54LGhA50cirLO1X1bnDrZmnDJLs4kzWbaGEvm9aupndyfHFIWDMQr+mAgh21
B0Ab9j3soq1HnbSUKTSzjC/NJQNYNcAlpFVf4bMHVj3I0GO4IPuMHUMs+Pmp1exv
lwIDAQAB
-----END PUBLIC KEY-----
'''}

gws_servername = GC.GAE_SERVERNAME
gae_testgwsiplist = GC.GAE_TESTGWSIPLIST
autorange_threads = GC.AUTORANGE_FAST_THREADS
_lock_context = make_lock_decorator()

class LimitConnection(LimitDictBase):
    'A connection limiter wrapper for remote IP.'

    maxsize = GC.LINK_MAXPERIP
    timeout = 3

    @classmethod
    def _limiterFactory(cls):
        limiter = super()._limiterFactory()
        limiter.iplock = threading.Lock()
        return limiter

    def __init__(self, sock, ip, maxsize=None, timeout=None):
        super().__init__(ip, maxsize, timeout)
        self._sock = sock
        self.iplock = self._limiter.iplock

    def __getattr__(self, name):
        return getattr(self._sock, name)

    def close(self):
        if super().close():
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()

class LimitConnect(LimitDictBase):
    'A connect limiter for host cache key.'

    maxsize = 2
    timeout = 8

LimitConnection.init()
LimitConnect.init()

def limit_connect(func):

    def newfunc(*args, **kwargs):
        key = args[2]
        limiter = LimitConnect.push(key)
        try:
            return func(*args, **kwargs)
        finally:
            LimitConnect.pop(key)

    return newfunc

class BaseHTTPUtil:
    '''Basic HTTP Request Class'''

    ssl_ciphers = res_ciphers
    new_sock4_cache = collections.deque()
    new_sock6_cache = collections.deque()

    def __init__(self, cacert=None, ssl_ciphers=None):
        if GC.LINK_VERIFYGPK:
            self.google_verify = self.google_verify_pkey
        #建立公用 CA 证书库
        self._context = SSL.Context(SSL.SSLv23_METHOD)
        self.load_cacert(cacert)
        self._cert_store = OpenSSL._util.lib.SSL_CTX_get_cert_store(self._context._context)
        if ssl_ciphers:
            self.ssl_ciphers = ssl_ciphers
        self.gws = gws = self.ssl_ciphers is gws_ciphers
        if gws:
            self.keeptime = GC.GAE_KEEPTIME
            self.max_per_ip = GC.GAE_MAXPERIP
        else:
            self.keeptime = GC.LINK_KEEPTIME
            self.max_per_ip = GC.LINK_MAXPERIP
        self.context_cache = LRUCache(min(GC.DNS_CACHE_ENTRIES, 256))
        self.tcp_connection_cache = collections.defaultdict(collections.deque)
        self.ssl_connection_cache = collections.defaultdict(collections.deque)
        start_new_thread(self.check_connection_cache, ('tcp',))
        start_new_thread(self.check_connection_cache, ('ssl',))

    def load_cacert(self, cacert):
        if os.path.isdir(cacert):
            import glob
            cacerts = glob.glob(os.path.join(cacert, '*.pem'))
            if cacerts:
                for cacert in cacerts:
                    self._context.load_verify_locations(cacert)
        elif os.path.isfile(cacert):
            self._context.load_verify_locations(cacert)
        else:
            wait_exit('未找到可信任 CA 证书集，GotoX 即将退出！请检查：%r', cacert)

    @_lock_context
    def get_context(self, server_hostname):
        if self.gws:
            server_hostname = None
        try:
            return self.context_cache[server_hostname]
        except KeyError:
            pass
        if self.gws:
            #强制 GWS 使用 TLSv1.2
            context = SSL.Context(SSL.TLSv1_2_METHOD)
        else:
            context = SSL.Context(GC.LINK_REMOTESSL)
            #兼容模式 TLS 禁用 TLSv1 及以下版本
            if GC.LINK_REMOTESSL == SSL.SSLv23_METHOD:
                context.set_options(SSL.OP_NO_SSLv2)
                context.set_options(SSL.OP_NO_SSLv3)
                context.set_options(SSL.OP_NO_TLSv1)
        #不使用压缩
        context.set_options(SSL.OP_NO_COMPRESSION)
        #通用问题修复
        context.set_options(SSL.OP_ALL)
        #会话重用
        context.set_session_cache_mode(SSL.SESS_CACHE_CLIENT)
        context.lock = threading.Lock()
        #证书验证
        OpenSSL._util.lib.SSL_CTX_set_cert_store(context._context, self._cert_store)
        context.set_verify(SSL.VERIFY_PEER, self._verify_callback)
        #加密选择
        context.set_cipher_list(self.ssl_ciphers)
        self.context_cache[server_hostname] = context
        return context

    def _verify_callback(self, sock, cert, error_number, depth, ok):
        if ok and depth == 0 and not self.gws:
            self.match_hostname(sock, cert)
        elif error_number:
            if error_number in CertificateErrorTab:
                raise CertificateError(-1, (CertificateErrorTab[error_number](cert), depth))
            else:
                logging.test('%s：%d-%d，%s', sock.get_servername(), depth, error_number, cert.get_subject())
        elif depth and ok:
            #添加可信的中间证书，一定程度上有助于验证配置缺失的服务器
            #下一步计划使用直接下载
            OpenSSL._util.lib.X509_STORE_add_cert(self._cert_store, cert._x509)
        return ok

    @staticmethod
    def match_hostname(sock, cert=None, hostname=None):
        cert = cert or sock.get_peer_certificate()
        if cert is None:
            raise CertificateError(-1, 'No cert has found.')
        hostname = hostname or sock.orig_hostname
        if hostname is None:
            return
        match_hostname(cert, hostname)

    def get_server_hostname(self, host, cache_key):
        servername = get_fake_sni(host)
        if servername:
            return servername
        if self.gws:
            if cache_key == 'google_gae|:443' or host and host.endswith('.appspot.com'):
                if gws_servername is None:
                    fakehost = random_hostname('*com')
                    return fakehost
                else:
                    return random.choice(gws_servername)
            else:
                return GC.PICKER_SERVERNAME
        else:
            return host

    @staticmethod
    def set_tcp_socket(sock, timeout=None, set_buffer=True):
        # set reuseaddr option to avoid 10048 socket error
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # set struct linger{l_onoff=1,l_linger=0} to avoid 10048 socket error
        # struct.pack('ii', 1, 0) == b'\x01\x00\x00\x00\x00\x00\x00\x00'
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b'\x01\x00\x00\x00\x00\x00\x00\x00')
        # resize socket recv buffer 8K->*K to improve browser releated application performance
        if set_buffer:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, GC.LINK_RECVBUFFER)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
        # disable negal algorithm to send http request quickly.
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
        # set a short timeout to trigger timeout retry more quickly.
        sock.settimeout(timeout if timeout else 1)

    def _get_tcp_socket(self, _socket, ip, timeout=None):
        if not ':' in ip:
            if not internet_v4.last_stat:
                sleep(1)
                raise socket.error('无法连接 IPv4 互联网')
            new_sock_cache = self.new_sock4_cache
            AF_INETX = socket.AF_INET
        else:
            if not internet_v6.last_stat:
                sleep(1)
                raise socket.error('无法连接 IPv6 互联网')
            new_sock_cache = self.new_sock6_cache
            AF_INETX = socket.AF_INET6
        if new_sock_cache:
            sock = new_sock_cache.popleft()
        else:
            # create a ipv4/ipv6 socket object
            sock = _socket(AF_INETX)
        try:
            # wrap for connect limit
            sock = LimitConnection(sock, ip, self.max_per_ip)
        except LimiterFull as e:
            new_sock_cache.append(sock)
            raise e
        else:
            self.set_tcp_socket(sock, timeout)
            return sock

    def get_tcp_socket(self, ip, timeout=None):
        return self._get_tcp_socket(socket.socket, ip, timeout)

    def get_proxy_socket(self, proxyip, timeout=None):
        return self._get_tcp_socket(socks.socksocket, proxyip, timeout)

    def get_ssl_socket(self, sock, server_hostname=None):
        if isinstance(server_hostname, tuple):
            server_hostname, sock.orig_hostname = server_hostname
        else:
            sock.orig_hostname = server_hostname
        context = self.get_context(sock.orig_hostname)
        ssl_sock = SSLConnection(context, sock)
        if server_hostname and not isip(server_hostname):
            ssl_sock.set_tlsext_host_name(server_hostname.encode())
        return ssl_sock

    @staticmethod
    def google_verify(sock):
        cert = sock.get_peer_certificate()
        if not cert:
            raise CertificateError(-1, '没有获取到证书')
        subject = cert.get_subject()
        if subject.O not in GoogleONames:
            raise CertificateError(-1, '%s 证书的组织名称（%s）不属于 %s 之一。' % (sock.getpeername[0], subject.O, GoogleONames))
        return cert

    @staticmethod
    def google_verify_pkey(sock):
        certs = sock.get_peer_cert_chain()
        if len(certs) < 2:
            raise CertificateError(-1, '谷歌域名没有获取到正确的证书链：缺少 CA。')
        if OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, certs[1].get_pubkey()) not in GoogleICAPkeys:
            raise CertificateError(-1, '谷歌域名没有获取到正确的证书链：CA 公钥不匹配。')
        return certs[0]

    @staticmethod
    def check_connection_alive(sock, keeptime, ctime):
        if time() - ctime > keeptime:
            sock.close()
            return
        return not check_connection_dead(sock)

    def check_connection_cache(self, type='tcp'):
        check_connection_alive = self.check_connection_alive
        if type == 'tcp':
            connection_cache = self.tcp_connection_cache
        elif type == 'ssl':
            connection_cache = self.ssl_connection_cache
        else:
            raise ValueError('unknown connection cache type: %r' % type)
        keeptime = self.keeptime
        while True:
            sleep(1)
            #将键名放入元组
            keys = tuple(connection_cache.keys())
            for cache_key in keys:
                if cache_key not in connection_cache:
                    continue
                cache = connection_cache[cache_key]
                try:
                    while cache:
                        ctime, connection = cached_connection = cache.popleft()
                        if check_connection_alive(connection, keeptime, ctime):
                            cache.appendleft(cached_connection)
                            break
                except Exception as e:
                    logging.error('check_connection_cache(type=%r, key=%r) 错误：%s', type, cache_key, e)
                if not cache:
                    del connection_cache[cache_key]

    def clear_all_connection_cache(self):
        self.tcp_connection_cache.clear()
        self.ssl_connection_cache.clear()

class HTTPUtil(BaseHTTPUtil):
    '''HTTP Request Class'''

    protocol_version = 'HTTP/1.1'

    def __init__(self, cacert, ssl_ciphers=None, max_window=4, timeout=8, proxy='', max_retry=2):
        # http://docs.python.org/dev/library/ssl.html
        # http://blog.ivanristic.com/2009/07/examples-of-the-information-collected-from-ssl-handshakes.html
        # http://src.chromium.org/svn/trunk/src/net/third_party/nss/ssl/sslenum.c
        # http://www.openssl.org/docs/apps/ciphers.html
        # openssl s_server -accept 443 -key CA.crt -cert CA.crt
        # set_ciphers as Modern Browsers
        BaseHTTPUtil.__init__(self, cacert, ssl_ciphers)
        self.max_window = max_window
        self.max_retry = max_retry
        self.timeout = timeout
        self.proxy = proxy
        self.tcp_connection_time = LRUCache(512 if self.gws else 4096)
        self.ssl_connection_time = LRUCache(512 if self.gws else 4096)

        if self.gws and GC.GAE_ENABLEPROXY:
            self.gws_front_connection_time = LRUCache(128)
            self.gws_front_connection_time.set('ip', LRUCache(128), expire=False)
            self.create_ssl_connection = self.create_gws_connection_withproxy

        #if self.proxy:
        #    dns_resolve = self.__dns_resolve_withproxy
        #    self.create_connection = self.__create_connection_withproxy
        #    self.create_ssl_connection = self.__create_ssl_connection_withproxy

        self.create_connection = limit_connect(self.create_connection)
        self.create_ssl_connection = limit_connect(self.create_ssl_connection)

    def get_tcp_ssl_connection_time(self, addr):
        t = self.tcp_connection_time.get(addr) or self.ssl_connection_time.get(addr, self.timeout)
        if LimitConnection.full(addr[0]):
            t += self.timeout
        return t

    def get_tcp_connection_time(self, addr):
        t = self.tcp_connection_time.get(addr, self.timeout)
        if LimitConnection.full(addr[0]):
            t += self.timeout
        return t

    def get_ssl_connection_time(self, addr):
        t = self.ssl_connection_time.get(addr, self.timeout)
        if LimitConnection.full(addr[0]):
            t += self.timeout
        return t

    def _cache_connection(self, cache, count, queobj):
        for _ in range(count):
            sock = queobj.get()
            if hasattr(sock, '_sock'):
                cache.append((time(), sock))

    def _create_connection(self, ipaddr, queobj, timeout=None, get_cache_sock=None):
        if get_cache_sock:
            sock = get_cache_sock()
            if sock:
                queobj.put(sock)
                return

        sock = None
        try:
            sock = self.get_tcp_socket(ipaddr[0], timeout)
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
            if sock:
                sock.close()
            # any socket.error, put Excpetions to output queobj.
            e.xip = ipaddr
            queobj.put(e)
            # reset a large and random timeout to the ipaddr
            self.tcp_connection_time[ipaddr] = self.timeout + 1

    def create_connection(self, address, hostname, cache_key, ssl=None, forward=None, **kwargs):
        def get_cache_sock(cache=None):
            if cache is None:
                cache = self.tcp_connection_cache.get(cache_key)
            used_sock = []
            try:
                while cache:
                    ctime, sock = cachedsock = cache.pop()
                    if newconn and hasattr(sock, 'used'):
                        used_sock.append(cachedsock)
                        continue
                    if self.check_connection_alive(sock, self.keeptime, ctime):
                        return sock
            except IndexError:
                pass
            finally:
                if newconn and used_sock:
                    used_sock.reverse()
                    cache.extend(used_sock)

        def get_cache_sock_ex():
            if cache_key is None or '|' in hostname:
                return
            names = hostname.split('.')
            if len(names[-1]) == 2 and len(names[-2]) <= 3:
                if len(names) > 3:
                    del names[0]
            elif len(names) > 2:
                del names[0]
            chost = '.'.join(names)
            ckey = '%s:%s' % (chost, cache_key.partition(':')[-1])
            keys = tuple(self.tcp_connection_cache.keys())
            for key in keys:
                if key not in self.tcp_connection_cache or\
                         '|' in key or not key.endswith(ckey):
                    continue
                cache = self.tcp_connection_cache[key]
                sock = get_cache_sock(cache)
                if sock:
                    if key != cache_key:
                        logging.warning(
                            '%s create_connection %r 尝试复用 %r 连接，'
                            '站点 %r 可能配置了多个子域名和较少的 IP。\n'
                            '可以尝试在 iplist 配置列表：\tcdn_%s = %s\n'
                            '然后在自动规则中使用此列表：\t%s$ = cdn_%s',
                            sock.xip[0], hostname, key, chost, chost, chost, chost, chost)
                    return sock

        newconn = forward and ssl
        sock = get_cache_sock()
        if sock:
            return sock

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
            queobj = Queue()
            for addr in addrs:
                start_new_thread(self._create_connection, (addr, queobj, forward, get_cache_sock))
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
                        if isinstance(result, LimiterFull):
                            sock = get_cache_sock_ex()
                            if sock:
                                return sock
                        else:
                            #only output first error
                            logging.warning('%s _create_connection %r 返回 %r，重试', addr[0], host, result)
                else:
                    if addrslen - n > 1:
                        cache = self.tcp_connection_cache[cache_key]
                        start_new_thread(self._cache_connection, (cache, addrslen-n-1, queobj))
                    return result
        if result:
            raise result

    def _create_ssl_connection(self, ipaddr, cache_key, host, queobj, timeout=None, get_cache_sock=None, callback=None):
        retry = None
        while True:
            if get_cache_sock:
                sock = get_cache_sock()
                if sock:
                    queobj.put(sock)
                    return

            ip = ipaddr[0]
            sock = None
            try:
                sock = self.get_tcp_socket(ip, timeout)
                server_name = self.get_server_hostname(host, cache_key)
                ssl_sock = self.get_ssl_socket(sock, server_name)
                # start connection time record
                start_time = time()
                # TCP connect
                ssl_sock.connect(ipaddr)
                #connected_time = time()
                # set a short timeout to trigger timeout retry more quickly.
                if timeout is not None:
                    ssl_sock.settimeout(3 if self.gws else 1.5)
                # SSL handshake
                ssl_sock.do_handshake()
                handshaked_time = time()
                # record SSL connection time
                ssl_sock.ssl_time = handshaked_time - start_time
                # verify Google SSL certificate.
                if self.gws:
                    self.google_verify(ssl_sock)
                ssl_sock.xip = ipaddr
                if callback:
                    cache_key = callback(ssl_sock) or cache_key
                    self.ssl_connection_time[ipaddr] = ssl_sock.ssl_time
                    self.ssl_connection_cache[cache_key].append((time(), ssl_sock))
                    return True
                self.ssl_connection_time[ipaddr] = ssl_sock.ssl_time
                # put ssl socket object to output queobj
                queobj.put(ssl_sock)
            except NetWorkIOError as e:
                if sock:
                    sock.close()
                # any socket.error, put Excpetions to output queobj.
                e.xip = ipaddr
                if callback:
                    if not retry and (e.args == zero_EOF_error or e.args[0] in zero_errno):
                        retry = True
                        continue
                    else:
                        callback(e)
                        return isinstance(e, LimiterFull)
                # reset a large and random timeout to the ipaddr
                self.ssl_connection_time[ipaddr] = self.timeout + 1
                queobj.put(e)
            break

    def create_ssl_connection(self, address, hostname, cache_key, getfast=None, forward=None, **kwargs):
        def get_cache_sock(cache=None):
            if cache is None:
                cache = self.ssl_connection_cache.get(cache_key)
            try:
                while cache:
                    ctime, ssl_sock = cache.pop()
                    if self.check_connection_alive(ssl_sock, self.keeptime, ctime):
                        return ssl_sock
            except IndexError:
                pass

        def get_cache_sock_ex():
            if cache_key is None or '|' in hostname:
                return
            names = hostname.split('.')
            if len(names[-1]) == 2 and len(names[-2]) <= 3:
                if len(names) > 3:
                    del names[0]
            elif len(names) > 2:
                del names[0]
            chost = '.'.join(names)
            ckey = '%s:%s' % (chost, cache_key.partition(':')[-1])
            keys = tuple(self.ssl_connection_cache.keys())
            for key in keys:
                if key not in self.ssl_connection_cache or\
                         '|' in key or not key.endswith(ckey):
                    continue
                cache = self.ssl_connection_cache[key]
                sock = get_cache_sock(cache)
                if sock:
                    if key != cache_key:
                        logging.warning(
                            '%s create_ssl_connection %r 尝试复用 %r 连接，'
                            '站点 %r 可能配置了多个子域名和较少的 IP。\n'
                            '可以尝试在 iplist 配置列表：\tcdn_%s = %s\n'
                            '然后在自动规则中使用此列表：\t%s$ = cdn_%s',
                            sock.xip[0], hostname, key, chost, chost, chost, chost, chost)
                    return sock

        sock = get_cache_sock()
        if sock:
            return sock

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
            queobj = Queue()
            for addr in addrs:
                start_new_thread(self._create_ssl_connection, (addr, cache_key, host, queobj, forward, get_cache_sock))
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
                        if isinstance(result, LimiterFull):
                            sock = get_cache_sock_ex()
                            if sock:
                                return sock
                        else:
                            #only output first error
                            logging.warning('%s _create_ssl_connection %r 返回 %r，重试', addr[0], host, result)
                else:
                    if addrslen - n > 1:
                        cache = self.ssl_connection_cache[cache_key]
                        start_new_thread(self._cache_connection, (cache, addrslen-n-1, queobj))
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
#            response = HTTPResponse(sock)
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
#            ssl_sock._sock = sock
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
            ips = dns_resolve(proxyhost).copy()
            if ips:
                ipcnt = len(ips) 
            else:
                logging.error('create_gws_connection_withproxy 代理地址无法解析：%r', proxy)
                return
            if ipcnt > 1:
                #优先使用未使用 IP，之后按连接速度排序
                ips.sort(key=self.get_gws_front_connection_time_ip)
            proxyport = int(proxyport)
            ohost, port = address
            while ips:
                proxyip = ips.pop(0)
                ip = random.choice(dns[hostname])
                if proxytype:
                    proxytype = proxytype.upper()
                if proxytype not in socks.PROXY_TYPES:
                    proxytype = 'HTTP'
                proxy_sock = self.get_proxy_socket(proxyip, 8)
                proxy_sock.set_proxy(socks.PROXY_TYPES[proxytype], proxyip, proxyport, True, proxyuser, proxypass)
                start_time = time()
                try:
                    proxy_ssl_sock = self.get_ssl_socket(proxy_sock, ohost.encode())
                    proxy_ssl_sock.settimeout(self.timeout)
                    #proxy_ssl_sock.set_connect_state()
                    proxy_ssl_sock.connect((ip, port))
                    proxy_ssl_sock.do_handshake()
                except Exception as e:
                    cost_time = self.timeout + 1 + random.random()
                    if ipcnt > 1:
                        self.gws_front_connection_time['ip'][proxyip] = cost_time
                    self.gws_front_connection_time[proxy] = cost_time
                    logging.error('create_gws_connection_withproxy 连接代理 [%s] 失败：%r', proxy, e)
                    continue
                else:
                    cost_time = time() - start_time
                    if ipcnt > 1:
                        self.gws_front_connection_time['ip'][proxyip] = cost_time
                    self.gws_front_connection_time[proxy] = cost_time
                proxy_ssl_sock.xip = proxyip, proxyport
                return proxy_ssl_sock

    def _request(self, sock, method, path, protocol_version, headers, payload, bufsize=8192):
        request_data = []
        request_data.append('%s %s %s' % (method, path, protocol_version))
        for k, v in headers.items():
            request_data.append('%s: %s' % (k.title(), v))
        #if self.proxy:
        #    _, username, password, _ = parse_proxy(self.proxy)
        #    if username and password:
        #        request_data += 'Proxy-Authorization: Basic %s\r\n' % base64.b64encode(('%s:%s' % (username, password)).encode()).decode().strip()
        request_data.append('\r\n')

        if hasattr(payload, 'read'):
            #避免发送多个小数据包
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, False)
            request_data = '\r\n'.join(request_data).encode()
            sock.sendall(request_data)
            readed = 0
            #以下按原样转发
            if 'Transfer-Encoding' in headers:
                while True:
                    chunk = payload.read(bufsize)
                    if chunk:
                        sock.sendall(chunk)
                        readed += len(chunk)
                    else:
                        break
                    #chunk_size_str = payload.readline(65537)
                    #if len(chunk_size_str) > 65536:
                    #    raise Exception('分块尺寸过大')
                    #sock.sendall(chunk_size_str)
                    #readed += len(chunk_size_str)
                    #chunk_size = int(chunk_size_str.split(b';')[0], 16) + 2
                    #if chunk_size == 2:
                    #    while True:
                    #        chunk = payload.readline(65536)
                    #        sock.sendall(chunk)
                    #        readed += len(chunk)
                    #        if chunk in (b'\r\n', b'\n', b''): # b'' 也许无法读取到空串
                    #            break
                    #        else:
                    #            logging.debug('%s "%s %s%s"分块拖挂：%r', sock.xip[0], method, headers['Host'], path, chunk)
                    #    break
                    #chunk = payload.read(chunk_size)
                    #sock.sendall(chunk)
                    #readed += chunk_size
                    #if chunk[-2:] != b'\r\n':
                    #    raise Exception('分块尺寸不匹配 CRLF')
            else:
                left_size = int(headers.get('Content-Length', 0))
                while True:
                    if left_size < 1:
                        break
                    data = payload.read(min(bufsize, left_size))
                    sock.sendall(data)
                    left_size -= len(data)
                    readed += len(data)
            payload.readed = readed
            #为下个请求恢复无延迟发送
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
        else:
            request_data = '\r\n'.join(request_data).encode() + payload
            sock.sendall(request_data)

#        try:
#            response = HTTPResponse(sock, method=method)
#            response.begin()
#        except Exception as e:
            #这里有时会捕捉到奇怪的异常，找不到来源路径
            # py2 的 raise 不带参数会导致捕捉到错误的异常，但使用 exc_clear 或换用 py3 还是会出现
#            if hasattr(e, 'xip'):
                #logging.warning('4444 %r | %r | %r', sock.getpeername(), sock.xip, e.xip)
#                del e.xip
#            raise e
        response = HTTPResponse(sock, method=method)
        response.begin()

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
            timeout += 10
        #单 IP 适当增加超时时间
        elif len(dns[hostname]) == 1 and timeout < 5:
            timeout += 2
        if 'Host' not in headers:
            headers['Host'] = request_params.host
        if hasattr(payload, 'read'):
            pass
        elif payload:
            if not isinstance(payload, bytes):
                payload = payload.encode()
            if 'Content-Length' not in headers:
                headers['Content-Length'] = str(len(payload))

        for i in range(self.max_retry):
            if hasattr(request_params, 'connection') and check_connection_dead(request_params.connection):
                raise socket.error(errno.ECONNABORTED, '本地连接已断开')
            sock = None
            ssl_sock = None
            ip = ''
            try:
                if ssl:
                    ssl_sock = self.create_ssl_connection(address, hostname, connection_cache_key, getfast=bool(getfast))
                else:
                    sock = self.create_connection(address, hostname, connection_cache_key)
                result = ssl_sock or sock
                if result:
                    result.settimeout(timeout)
                    return self._request(result, method, request_params.path, self.protocol_version, headers, payload, bufsize=bufsize)
            except Exception as e:
                if i < self.max_retry - 1 and isinstance(e, LimiterFull):
                    continue
                if ssl_sock:
                    ip = ssl_sock.xip
                    ssl_sock.close()
                elif sock:
                    ip = sock.xip
                    sock.close()
                if hasattr(e, 'xip'):
                    ip = e.xip
                    logging.warning('%s create_%sconnection %r 失败：%r', ip[0], 'ssl_' if ssl else '', realurl or url, e)
                elif isinstance(e, LimiterFull):
                    logging.warning('request "%s %s" 失败：%r', realmethod, realurl or url, e)
                else:
                    logging.warning('%s _request "%s %s" 失败：%r', ip and ip[0], realmethod, realurl or url, e)
                    if ip and realurl:
                        self.ssl_connection_time[ip] = self.timeout + 1
                if not realurl and e.args[0] in bypass_errno or i == self.max_retry - 1 and isinstance(e, LimiterFull):
                    if ip:
                        e.xip = ip
                    raise
                #确保不重复上传数据
                if has_content and (sock or ssl_sock):
                    return
                if 'timed out' in str(e):
                    timeout += 10

# Google video ip can act as Google Web Server if cipher suits not include
# RC4-SHA
# AES128-GCM-SHA256
# ECDHE-RSA-RC4-SHA
# ECDHE-RSA-AES128-GCM-SHA256
#不安全 cipher
# CBC
# AES128-SHA
# ECDHE-RSA-AES128-SHA
# http://docs.python.org/dev/library/ssl.html
# https://www.openssl.org/docs/manmaster/man1/openssl-ciphers.html
# 以下 GWS ciphers 设置用于 TLS v1.2 连接
gws_ciphers = (
    'ECDHE+AES256+AESGCM:'
    'ECDHE+AESGCM:'
    'ECDHE+HIGH:'
    'RSA+AES256+AESGCM:'
    'RSA+AESGCM:'
    'RSA+HIGH:'
    'HIGH:MEDIUM:'
    'TLSv1.2:'
    '!AES128-GCM-SHA256:'
    '!ECDHE-RSA-AES128-GCM-SHA256:'
    '!ECDHE-RSA-AES128-SHA:'
    '!TLSv1.0:!SSLv3:'
    '!aNULL:!eNULL:!EXPORT:!EXPORT40:!EXPORT56:!LOW:!CBC:!DSS:'
    '!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK'
    ).encode()

# max_window=4, timeout=8, proxy='', ssl_ciphers=None, max_retry=2
http_nor = HTTPUtil(os.path.join(cert_dir, 'cacerts'), res_ciphers, GC.LINK_WINDOW, GC.LINK_TIMEOUT, GC.proxy)
http_cfw = HTTPUtil(os.path.join(cert_dir, 'cacerts'), res_ciphers, GC.LINK_WINDOW, GC.CFW_TIMEOUT, GC.proxy)
http_gws = HTTPUtil(os.path.join(cert_dir, 'cacerts', 'gws.pem'), gws_ciphers, GC.LINK_WINDOW, GC.GAE_TIMEOUT, GC.proxy)
reset_method_list.append(http_nor.clear_all_connection_cache)
reset_method_list.append(http_cfw.clear_all_connection_cache)
reset_method_list.append(http_gws.clear_all_connection_cache)
