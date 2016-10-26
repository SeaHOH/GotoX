# coding:utf-8
"""HTTP Request Util"""

import sys
import os
import errno
import re
import socket
import ssl
import struct
import random
from select import select
from time import time, sleep
from compat import (
    PY3,
    Queue,
    logging,
    thread,
    httplib,
    urlparse,
    xrange,
    exc_clear,
    OpenSSL,
    NetWorkIOError
    )
from common import (
    cert_dir,
    parse_proxy,
    onlytime,
    testip,
    dns,
    dns_resolve,
    spawn_later
    )
from GlobalConfig import GC

class SSLConnection(object):
    """OpenSSL Connection Wapper"""

    def __init__(self, context, sock):
        self._context = context
        self._sock = sock
        self._connection = OpenSSL.SSL.Connection(context, sock)
        self._makefile_refs = 0

    def __del__(self):
        if self._sock:
            self._sock.close()
            self._sock = None

    def __getattr__(self, attr):
        if attr not in ('_context', '_sock', '_connection', '_makefile_refs'):
            return getattr(self._connection, attr)

    def __iowait(self, io_func, *args, **kwargs):
        timeout = self._sock.gettimeout()
        fd = self._sock
        while self._connection:
            try:
                return io_func(*args, **kwargs)
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError):
                exc_clear()
                rd, _, ed = select([fd], [], [fd], timeout)
                if ed:
                    raise socket.error(ed)
                if not rd:
                    raise socket.timeout('The read operation timed out')
            except OpenSSL.SSL.WantWriteError:
                exc_clear()
                _, wd, ed = select([], [fd], [fd], timeout)
                if ed:
                    raise socket.error(ed)
                if not wd:
                    raise socket.timeout('The write operation timed out')
            except OpenSSL.SSL.SysCallError as e:
                if e.args[0] == 10035 and 'WSAEWOULDBLOCK' in e.args[1]:
                    exc_clear()
                    rd, wd, ed = select([fd], [fd], [fd], timeout)
                    if ed:
                        raise socket.error(ed)
                    if not rd and not wd:
                        raise socket.timeout('The socket operation timed out')
                else:
                    raise e
            except Exception as e:
                raise e

    def accept(self):
        sock, addr = self._sock.accept()
        client = SSLConnection(self._context, sock)
        client.set_accept_state()
        return client, addr

    def do_handshake(self):
        self.__iowait(self._connection.do_handshake)

    def connect(self, addr):
        self.__iowait(self._connection.connect, addr)

    def send(self, data, flags=0):
        try:
            return self.__iowait(self._connection.send, data)
        except OpenSSL.SSL.SysCallError as e:
            if e.args[0] == -1 and not data:
                return 0
            raise socket.error(str(e))
        except Exception as e:
            raise socket.error(str(e))

    def sendall(self, data, flags=0):
        total_sent = 0
        total_to_send = len(data)
        while total_sent < total_to_send:
            sent = self.send(data[total_sent:total_sent + 16384]) # 16K
            total_sent += sent
    write = sendall

    def recv(self, bufsiz, flags=None):
        pending = self._connection.pending()
        if pending:
            return self._connection.recv(min(pending, bufsiz))
        try:
            return self.__iowait(self._connection.recv, bufsiz, flags)
        except OpenSSL.SSL.ZeroReturnError as e:
            if self._connection.get_shutdown() == OpenSSL.SSL.RECEIVED_SHUTDOWN:
                return b''
            raise e
        except OpenSSL.SSL.SysCallError as e:
            if e.args[0] == -1 and 'Unexpected EOF' in e.args[1]:
                return b''
            elif e.args[0] in (10053, 10054, 10038):
                return b''
            raise socket.error(str(e))
    read = recv

    def recv_into(self, buffer, nbytes=None, flags=None):
        try:
            return self.__iowait(self._connection.recv_into, buffer, nbytes, flags)
        except OpenSSL.SSL.ZeroReturnError as e:
            if self._connection.get_shutdown() == OpenSSL.SSL.RECEIVED_SHUTDOWN:
                return 0
            raise e
        except OpenSSL.SSL.SysCallError as e:
            if e.args[0] == -1 and 'Unexpected EOF' in e.args[1]:
                return 0
            elif e.args[0] in (10053, 10054, 10038):
                return 0
            raise socket.error(str(e))

    def close(self):
        if self._makefile_refs < 1:
            self._connection = None
            if self._sock:
                self._sock.close()
                self._sock = None
        else:
            self._makefile_refs -= 1

    if PY3:
        from makefile import backport_makefile as makefile
    else:
        def makefile(self, mode='r', bufsize=-1):
            self._makefile_refs += 1
            return socket._fileobject(self, mode, bufsize, close=True)

class BaseHTTPUtil(object):
    """Basic HTTP Request Class"""

    use_openssl = 0
    ssl_ciphers = ':'.join([
                            'ECDHE-ECDSA-AES256-SHA',
                            'ECDHE-RSA-AES256-SHA',
                            'DHE-RSA-CAMELLIA256-SHA',
                            'DHE-DSS-CAMELLIA256-SHA',
                            'DHE-RSA-AES256-SHA',
                            'DHE-DSS-AES256-SHA',
                            'ECDH-RSA-AES256-SHA',
                            'ECDH-ECDSA-AES256-SHA',
                            'CAMELLIA256-SHA',
                            'AES256-SHA',
                            #'ECDHE-ECDSA-RC4-SHA',
                            #'ECDHE-ECDSA-AES128-SHA',
                            #'ECDHE-RSA-RC4-SHA',
                            #'ECDHE-RSA-AES128-SHA',
                            #'DHE-RSA-CAMELLIA128-SHA',
                            #'DHE-DSS-CAMELLIA128-SHA',
                            #'DHE-RSA-AES128-SHA',
                            #'DHE-DSS-AES128-SHA',
                            #'ECDH-RSA-RC4-SHA',
                            #'ECDH-RSA-AES128-SHA',
                            #'ECDH-ECDSA-RC4-SHA',
                            #'ECDH-ECDSA-AES128-SHA',
                            #'SEED-SHA',
                            #'CAMELLIA128-SHA',
                            #'RC4-SHA',
                            #'RC4-MD5',
                            #'AES128-SHA',
                            #'ECDHE-ECDSA-DES-CBC3-SHA',
                            #'ECDHE-RSA-DES-CBC3-SHA',
                            #'EDH-RSA-DES-CBC3-SHA',
                            #'EDH-DSS-DES-CBC3-SHA',
                            #'ECDH-RSA-DES-CBC3-SHA',
                            #'ECDH-ECDSA-DES-CBC3-SHA',
                            #'DES-CBC3-SHA',
                            'TLS_EMPTY_RENEGOTIATION_INFO_SCSV'])
    openssl_ciphers = ':'.join([
                            #defaultTLS ex
                            'ECDHE-RSA-AES128-SHA256',
                            'AES128-SHA256',
                            #mixinCiphers ex
                            'AES256-SHA256',
                            #defaultTLS
                            #'AES128-SHA',
                            #'AES256-SHA',
                            #'AES128-GCM-SHA256',
                            'AES256-GCM-SHA384',
                            #'ECDHE-ECDSA-AES128-SHA',
                            'ECDHE-ECDSA-AES256-SHA',
                            #'ECDHE-RSA-AES128-SHA',
                            'ECDHE-RSA-AES256-SHA',
                            #'ECDHE-RSA-AES128-GCM-SHA256',
                            'ECDHE-RSA-AES256-GCM-SHA384',
                            #'ECDHE-ECDSA-AES128-GCM-SHA256',
                            'ECDHE-ECDSA-AES256-GCM-SHA384',
                            #mixinCiphers
                            #'RC4-SHA',
                            #'DES-CBC3-SHA',
                            #'ECDHE-RSA-RC4-SHA',
                            #'ECDHE-RSA-DES-CBC3-SHA',
                            #'ECDHE-ECDSA-RC4-SHA',
                            'TLS_EMPTY_RENEGOTIATION_INFO_SCSV'])

    def __init__(self, use_openssl=None, cacert=None, ssl_ciphers=None):
        # http://docs.python.org/dev/library/ssl.html
        # http://www.openssl.org/docs/apps/ciphers.html
        self.cacert = cacert
        #self.ssl_ciphers = self.openssl_ciphers #debug
        if ssl_ciphers:
            self.ssl_ciphers = ssl_ciphers
        if use_openssl:
            self.use_openssl = use_openssl
            self.set_ssl_option = self.set_openssl_option
            self.get_ssl_socket = self.get_openssl_socket
            self.get_peercert = self.get_openssl_peercert
        self.set_ssl_option()

    def set_ssl_option(self):
        self.ssl_context = ssl.SSLContext(GC.LINK_REMOTESSL)
        #validate
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        if self.cacert:
            self.ssl_context.load_verify_locations(self.cacert)
        #obfuscate
        self.ssl_context.set_ciphers(self.ssl_ciphers)

    def set_openssl_option(self):
        self.ssl_context = OpenSSL.SSL.Context(GC.LINK_REMOTESSL)
        #cache
        import binascii
        self.ssl_context.set_session_id(binascii.b2a_hex(os.urandom(10)))
        self.ssl_context.set_session_cache_mode(OpenSSL.SSL.SESS_CACHE_BOTH)
        #validate
        if self.cacert:
            self.ssl_context.load_verify_locations(self.cacert)
            self.ssl_context.set_verify(OpenSSL.SSL.VERIFY_PEER, lambda c, x, e, d, ok: ok)
        #obfuscate
        self.ssl_context.set_cipher_list(self.ssl_ciphers)

    def get_ssl_socket(self, sock, server_hostname=None):
        return self.ssl_context.wrap_socket(sock, do_handshake_on_connect=False, server_hostname=server_hostname)

    def get_openssl_socket(self, sock, server_hostname=None):
        ssl_sock = SSLConnection(self.ssl_context, sock)
        if server_hostname:
            ssl_sock.set_tlsext_host_name(server_hostname)
        return ssl_sock

    def get_peercert(self, sock):
        return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, sock.getpeercert(True))

    def get_openssl_peercert(self, sock):
        return sock.get_peer_certificate()

class HTTPUtil(BaseHTTPUtil):
    """HTTP Request Class"""

    #MessageClass = dict
    protocol_version = 'HTTP/1.1'
    ssl_ciphers = ':'.join([
                            #defaultTLS ex
                            'ECDHE-RSA-AES128-SHA256',
                            'AES128-SHA256',
                            #mixinCiphers ex
                            'AES256-SHA256',
                            #defaultTLS
                            #'AES128-SHA',
                            #'AES256-SHA',
                            #'AES128-GCM-SHA256',
                            'AES256-GCM-SHA384',
                            #'ECDHE-ECDSA-AES128-SHA',
                            'ECDHE-ECDSA-AES256-SHA',
                            #'ECDHE-RSA-AES128-SHA',
                            'ECDHE-RSA-AES256-SHA',
                            #'ECDHE-RSA-AES128-GCM-SHA256',
                            'ECDHE-RSA-AES256-GCM-SHA384',
                            #'ECDHE-ECDSA-AES128-GCM-SHA256',
                            'ECDHE-ECDSA-AES256-GCM-SHA384',
                            #mixinCiphers
                            #'RC4-SHA',
                            #'DES-CBC3-SHA',
                            #'ECDHE-RSA-RC4-SHA',
                            #'ECDHE-RSA-DES-CBC3-SHA',
                            #'ECDHE-ECDSA-RC4-SHA',
                            'TLS_EMPTY_RENEGOTIATION_INFO_SCSV'])
    outtimes = 0
    keeptime = 90
    import collections
    tcp_connection_time = collections.defaultdict(float)
    tcp_connection_cache = collections.defaultdict(Queue.PriorityQueue)
    ssl_connection_time = collections.defaultdict(float)
    ssl_connection_cache = collections.defaultdict(Queue.PriorityQueue)

    def __init__(self, max_window=4, max_timeout=8, max_retry=2, proxy=''):
        # http://docs.python.org/dev/library/ssl.html
        # http://blog.ivanristic.com/2009/07/examples-of-the-information-collected-from-ssl-handshakes.html
        # http://src.chromium.org/svn/trunk/src/net/third_party/nss/ssl/sslenum.c
        # http://www.openssl.org/docs/apps/ciphers.html
        # openssl s_server -accept 443 -key CA.crt -cert CA.crt
        # set_ciphers as Modern Browsers
        self.max_window = max_window
        self.max_retry = max_retry
        self.max_timeout = max_timeout
        self.proxy = proxy
        #if self.proxy:
        #    dns_resolve = self.__dns_resolve_withproxy
        #    self.create_connection = self.__create_connection_withproxy
        #    self.create_ssl_connection = self.__create_ssl_connection_withproxy
        BaseHTTPUtil.__init__(self, GC.LINK_OPENSSL, os.path.join(cert_dir, 'cacert.pem'))

    def check_connection_cache(self):
        '''check and close unavailable connection continued forever'''
        while True:
            sleep(60)
            #get keyname put in a tuple
            keys = None
            while keys is None:
                try:
                    keys = tuple(key for key in self.tcp_connection_cache)
                except:
                    sleep(1)
            for connection_cache_key in keys:
                try:
                    while True:
                        ctime, sock = self.tcp_connection_cache[connection_cache_key].get_nowait()
                        rd, _, ed = select([sock], [], [sock], 0.1)
                        if rd or ed or time()-ctime > self.keeptime:
                            sock.close()
                        else:
                            self.tcp_connection_cache[connection_cache_key].put((ctime, sock))
                            break
                except Queue.Empty:
                    pass
                except Exception as e:
                    if e.args[0] == 9:
                        pass
                    else:
                        raise e
            keys = None
            while keys is None:
                try:
                    keys = tuple(key for key in self.ssl_connection_cache)
                except:
                    sleep(1)
            for connection_cache_key in keys:
                try:
                    while True:
                        ctime, ssl_sock = self.ssl_connection_cache[connection_cache_key].get_nowait()
                        rd, _, ed = select([ssl_sock.sock], [], [ssl_sock.sock], 0.1)
                        if rd or ed or time()-ctime > self.keeptime:
                            ssl_sock.sock.close()
                        else:
                            self.ssl_connection_cache[connection_cache_key].put((ctime, ssl_sock))
                            break
                except Queue.Empty:
                    pass
                except Exception as e:
                    if e.args[0] == 9:
                        pass
                    else:
                        raise e

    def create_connection(self, address, timeout=None, source_address=None, **kwargs):
        connection_cache_key = kwargs.get('cache_key')
        hostname = connection_cache_key or ''
        def _create_connection(ipaddr, timeout, queobj):
            sock = None
            try:
                # create a ipv4/ipv6 socket object
                sock = socket.socket(socket.AF_INET if ':' not in ipaddr[0] else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # set struct linger{l_onoff=1,l_linger=0} to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                # resize socket recv buffer 8K->32K to improve browser releated application performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                # disable nagle algorithm to send http request quickly.
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                # set a short timeout to trigger timeout retry more quickly.
                sock.settimeout(1)
                # start connection time record
                start_time = time()
                # TCP connect
                sock.connect(ipaddr)
                # set a normal timeout
                sock.settimeout(timeout)
                # record TCP connection time
                self.tcp_connection_time[ipaddr] = sock.tcp_time = time() - start_time
                # put socket object to output queobj
                sock.xip = ipaddr
                queobj.put(sock)
            except (socket.error, OSError) as e:
                # any socket.error, put Excpetions to output queobj.
                e.xip = ipaddr
                queobj.put(e)
                # reset a large and random timeout to the ipaddr
                self.tcp_connection_time[ipaddr] = self.max_timeout+random.random()
                # close tcp socket
                sock.close()
        def _close_connection(count, queobj, first_tcp_time):
            for i in xrange(count):
                sock = queobj.get()
                tcp_time_threshold = min(0.66, 1.5 * first_tcp_time)
                if isinstance(sock, socket.socket):
                    if connection_cache_key and sock.tcp_time < tcp_time_threshold:
                        self.tcp_connection_cache[connection_cache_key].put((onlytime(), sock))
                    else:
                        sock.close()
        try:
            while connection_cache_key:
                ctime, sock = self.tcp_connection_cache[connection_cache_key].get_nowait()
                rd, _, ed = select([sock], [], [sock], 0.1)
                if rd or ed or time()-ctime > self.keeptime:
                    sock.close()
                else:
                    return sock
        except Queue.Empty:
            pass
        host, port = address
        result = None
        addresses = [(x, port) for x in dns_resolve(host)]
        if port == 443:
            get_connection_time = lambda addr: self.ssl_connection_time.__getitem__(addr) or self.tcp_connection_time.__getitem__(addr)
        else:
            get_connection_time = self.tcp_connection_time.__getitem__
        for i in xrange(self.max_retry):
            addresseslen = len(addresses)
            addresses.sort(key=get_connection_time)
            if addresseslen > self.max_window:
                window = min((self.max_window+1)//2 + min(i, 1), addresseslen)
                addrs = addresses[:window] + random.sample(addresses[window:], self.max_window-window)
            else:
                addrs = addresses
            queobj = Queue.Queue()
            for addr in addrs:
                thread.start_new_thread(_create_connection, (addr, timeout, queobj))
            addrslen = len(addrs)
            for i in xrange(addrslen):
                result = queobj.get()
                if isinstance(result, Exception):
                    addr = result.xip
                    #临时移除 badip
                    try:
                        addresses.remove(addr)
                    except Exception:
                        pass
                    if i == 0:
                        #only output first error
                        logging.warning(u'%s create_connection %r 返回 %r，重试', addr[0], host, result)
                else:
                    thread.start_new_thread(_close_connection, (addrslen-i-1, queobj, result.tcp_time))
                    return result
            if i == self.max_retry - 1:
                if 'google' in hostname:
                    testgaeip()
                raise result

    def create_ssl_connection(self, address, timeout=None, test=None, source_address=None, rangefetch=None, **kwargs):
        connection_cache_key = kwargs.get('cache_key')
        hostname = connection_cache_key or ''
        def _create_ssl_connection(ipaddr, timeout, queobj, retry=None):
            sock = None
            ssl_sock = None
            try:
                # create a ipv4/ipv6 socket object
                sock = socket.socket(socket.AF_INET if ':' not in ipaddr[0] else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # set struct linger{l_onoff=1,l_linger=0} to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                # resize socket recv buffer 8K->32K to improve browser releated application performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                # disable negal algorithm to send http request quickly.
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                # pick up the sock socket
                server_hostname = b'www.google.com' if address[0].endswith('.appspot.com') else None
                ssl_sock = self.get_ssl_socket(sock, server_hostname)
                # set a short timeout to trigger timeout retry more quickly.
                ssl_sock.settimeout(1)
                # start connection time record
                start_time = time()
                # TCP connect
                ssl_sock.connect(ipaddr)
                connected_time = time()
                # set a short timeout to trigger timeout retry more quickly.
                ssl_sock.settimeout(timeout if test else 1.5)
                # SSL handshake
                ssl_sock.do_handshake()
                # set a normal timeout
                ssl_sock.settimeout(timeout)
                handshaked_time = time()
                # record TCP connection time
                self.tcp_connection_time[ipaddr] = ssl_sock.tcp_time = connected_time - start_time
                # record SSL connection time
                self.ssl_connection_time[ipaddr] = ssl_sock.ssl_time = handshaked_time - start_time
                if test:
                    if ssl_sock.ssl_time > timeout:
                        raise socket.timeout(u'%d 超时' % int(ssl_sock.ssl_time*1000))
                # verify SSL certificate.
                if 'google' in hostname or test:
                    #多次使用慢速或无效的 IP 刷新
                    if not test and ssl_sock.ssl_time > 1.5:
                        if self.outtimes > max(min(len(GC.IPLIST_MAP[GC.GAE_LISTNAME])/2, 12), 6):
                            logging.warning(u'连接过慢 %s: %d' %('.'.join(x.rjust(3) for x in ipaddr[0].split('.')), int(ssl_sock.ssl_time*1000)))
                            spawn_later(5, testgaeip)
                        else:
                            self.outtimes += 1
                    cert = self.get_peercert(ssl_sock)
                    if not cert:
                        raise socket.error(u'没有获取到证书')
                    subject = cert.get_subject()
                    if not subject.O == 'Google Inc':
                        raise ssl.SSLError(u'%s 证书的公司名称（%s）不是以 "Google" 开头' % (address[0], subject.O))
                # sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
                ssl_sock.sock = sock
                ssl_sock.xip = ipaddr
                if test:
                    self.ssl_connection_cache[GC.GAE_LISTNAME + ':443'].put((onlytime(), ssl_sock))
                    return test.put((ipaddr[0], ssl_sock.ssl_time))
                # put ssl socket object to output queobj
                queobj.put(ssl_sock)
            except NetWorkIOError as e:
                # reset a large and random timeout to the ipaddr
                self.ssl_connection_time[ipaddr] = self.max_timeout + random.random()
                # close tcp socket
                sock.close()
                # any socket.error, put Excpetions to output queobj.
                e.xip = ipaddr
                if test:
                    if not retry and e.args == (-1, 'Unexpected EOF'):
                        return _create_ssl_connection(ipaddr, timeout, test, True)
                    return test.put(e)
                queobj.put(e)

        def _close_ssl_connection(count, queobj, first_ssl_time):
            for i in xrange(count):
                ssl_sock = queobj.get()
                ssl_time_threshold = min(1, 1.5 * first_ssl_time)
                if isinstance(ssl_sock, (SSLConnection, ssl.SSLSocket)):
                    if connection_cache_key and ssl_sock.ssl_time < ssl_time_threshold:
                        self.ssl_connection_cache[connection_cache_key].put((onlytime(), ssl_sock))
                    else:
                        ssl_sock.sock.close()

        if test:
            return _create_ssl_connection(address, timeout, test)
        try:
            while connection_cache_key:
                ctime, ssl_sock = self.ssl_connection_cache[connection_cache_key].get_nowait()
                rd, _, ed = select([ssl_sock.sock], [], [ssl_sock.sock], 0.1)
                if rd or ed or time()-ctime > self.keeptime:
                    ssl_sock.sock.close()
                else:
                    ssl_sock.settimeout(timeout)
                    return ssl_sock
        except Queue.Empty:
            pass
        host, port = address
        result = None
        addresses = [(x, port) for x in dns_resolve(host)]
        for i in xrange(self.max_retry):
            addresseslen = len(addresses)
            addresses.sort(key=self.ssl_connection_time.__getitem__)
            if rangefetch:
                #按线程数量获取排序靠前的 IP
                addrs = addresses[:GC.AUTORANGE_THREADS+1]
            else:
                max_window = self.max_window
                if addresseslen > max_window:
                    window = min((max_window+1)//2 + min(i, 1), addresseslen)
                    addrs = addresses[:window] + random.sample(addresses[window:], max_window-window)
                else:
                    addrs = addresses
            queobj = Queue.Queue()
            for addr in addrs:
                thread.start_new_thread(_create_ssl_connection, (addr, timeout, queobj))
            addrslen = len(addrs)
            for i in xrange(addrslen):
                result = queobj.get()
                if isinstance(result, Exception):
                    addr = result.xip
                    #临时移除 badip
                    try:
                        addresses.remove(addr)
                    except Exception:
                        pass
                    if i == 0:
                        #only output first error
                        logging.warning(u'%s create_ssl_connection %r 返回 %r，重试', addr[0], host, result)
                else:
                    thread.start_new_thread(_close_ssl_connection, (addrslen-i-1, queobj, result.ssl_time))
                    return result
            if i == self.max_retry - 1:
                if 'google' in hostname:
                    testgaeip()
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

    def _request(self, sock, method, path, protocol_version, headers, payload, bufsize=8192, crlf=None):
        need_crlf = bool(crlf)
        if need_crlf:
            fakehost = 'www.' + ''.join(random.choice(('bcdfghjklmnpqrstvwxyz','aeiou')[x&1]) for x in xrange(random.randint(5,20))) + random.choice(['.net', '.com', '.org'])
            request_data = 'GET / HTTP/1.1\r\nHost: %s\r\n\r\n\r\n\r\r' % fakehost
        else:
            request_data = ''
        request_data += '%s %s %s\r\n' % (method, path, protocol_version)
        request_data += ''.join('%s: %s\r\n' % (k.title(), v) for k, v in headers.items())
        if self.proxy:
            _, username, password, _ = parse_proxy(self.proxy)
            if username and password:
                request_data += 'Proxy-Authorization: Basic %s\r\n' % base64.b64encode(('%s:%s' % (username, password)).encode()).decode().strip()
        request_data += '\r\n'
        if not isinstance(request_data, bytes):
            request_data = request_data.encode()

        sock.sendall(request_data + payload)
        #if isinstance(payload, bytes):
        #    sock.sendall(request_data.encode() + payload)
        #elif hasattr(payload, 'read'):
        #    sock.sendall(request_data)
        #    sock.sendall(payload.read())
        #else:
        #    raise TypeError('http_util.request(payload) must be a string or buffer, not %r' % type(payload))

        if need_crlf:
            try:
                response = httplib.HTTPResponse(sock)
                response.begin()
                response.read()
            except Exception as e:
                logging.exception('crlf skip read')
                raise e

        response = httplib.HTTPResponse(sock) if PY3 else httplib.HTTPResponse(sock, buffering=True)
        response.begin()

        response.xip = sock.xip
        response.sock = sock
        return response

    def request(self, method, url, payload=None, headers={}, bufsize=8192, crlf=None, connection_cache_key=None, timeout=None, rangefetch=None, realurl=None):
        scheme, netloc, path, _, query, _ = urlparse.urlparse(url)
        if netloc.rfind(':') <= netloc.rfind(']'):
            # no port number
            host = netloc
            port = 443 if scheme == 'https' else 80
        else:
            host, _, port = netloc.rpartition(':')
            port = int(port)
        if query:
            path += '?' + query

        if 'Host' not in headers:
            headers['Host'] = host
        if payload:
            if not isinstance(payload, bytes):
                payload = payload.encode()
            if 'Content-Length' not in headers:
                headers['Content-Length'] = str(len(payload))

        for i in xrange(self.max_retry):
            sock = None
            ssl_sock = None
            ip = ''
            try:
                if scheme == 'https':
                    ssl_sock = self.create_ssl_connection((host, port), timeout or self.max_timeout, cache_key=connection_cache_key, rangefetch=rangefetch)
                    crlf = 0
                else:
                    sock = self.create_connection((host, port), timeout or self.max_timeout, cache_key=connection_cache_key)
                response =  self._request(ssl_sock or sock, method, path, self.protocol_version, headers, payload, bufsize=bufsize, crlf=crlf)
                return response
            except Exception as e:
                if ssl_sock:
                    ip = ssl_sock.xip[0]
                    ssl_sock.sock.close()
                elif sock:
                    ip = sock.xip[0]
                    sock.close()
                if hasattr(e, 'xip'):
                    ip = e.xip[0]
                    logging.warning(u'%s create_%sconnection %r 失败：%r', ip, '' if port == 80 else 'ssl_', realurl or url, e)
                else:
                    logging.warning(u'%s _request "%s %s" 失败：%r', ip, method, realurl or url, e)
            if i == self.max_retry - 1:
                logging.warning(u'%s request "%s %s" 失败', ip, method, realurl or url)
                if realurl:
                    _, realhost, _, _, _, _ = urlparse.urlparse(realurl)
                    if realhost not in testip.tested:
                        logging.warning(u'request：%r 触发 IP 检测' % realhost)
                        testip.tested[realhost] = True
                        testgaeip()
                return None

http_util = HTTPUtil(max_window=GC.LINK_WINDOW, max_timeout=GC.LINK_TIMEOUT, proxy=GC.proxy)
from GAEUpdata import testgaeip
thread.start_new_thread(http_util.check_connection_cache, ())
