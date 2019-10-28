# coding:utf-8

import socket
import errno
from OpenSSL import SSL, crypto
from select import select
from ssl import (
    _DEFAULT_CIPHERS, _RESTRICTED_SERVER_CIPHERS,
    _dnsname_match, _ipaddress_match )
try:
    from ssl import _inet_paton as ip_address # py3.7+
except ImportError:
    from ipaddress import ip_address
_DEFAULT_CIPHERS += ':!SSLv3'
_RESTRICTED_SERVER_CIPHERS += ':!SSLv3'
zero_errno = errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTSOCK
zero_EOF_error = -1, 'Unexpected EOF'
def_ciphers = _DEFAULT_CIPHERS.encode()
res_ciphers = _RESTRICTED_SERVER_CIPHERS.encode()

class SSLConnection:
    '''API-compatibility wrapper for Python OpenSSL's Connection-class.'''

    def __init__(self, context, sock):
        self._sock = sock
        self._connection = SSL.Connection(context, sock)

    def __getattr__(self, name):
        return getattr(self._connection, name)

    def __iowait(self, io_func, *args, **kwargs):
        timeout = self._sock.gettimeout()
        fd = self._sock.fileno()
        while self._connection:
            try:
                return io_func(*args, **kwargs)
            except (SSL.WantReadError, SSL.WantX509LookupError):
                rd, _, ed = select([fd], [], [fd], timeout)
                if ed:
                    raise socket.error(ed)
                if not rd:
                    raise socket.timeout('The read operation timed out')
            except SSL.WantWriteError:
                _, wd, ed = select([], [fd], [fd], timeout)
                if ed:
                    raise socket.error(ed)
                if not wd:
                    raise socket.timeout('The write operation timed out')
            except SSL.SysCallError as e:
                if e.args[0] in socket._blocking_errnos:
                    rd, wd, ed = select([fd], [fd], [fd], timeout)
                    if ed:
                        raise socket.error(ed)
                    if not rd and not wd:
                        raise socket.timeout('The socket operation timed out')
                else:
                    raise

    def accept(self):
        sock, addr = self._sock.accept()
        client = SSLConnection(self._context, sock)
        client.set_accept_state()
        return client, addr

    def session_reused(self):
        return SSL._lib.SSL_session_reused(self._ssl) == 1

    def get_session(self):
        session = SSL._lib.SSL_get1_session(self._ssl)
        if session != SSL._ffi.NULL:
            return SSL._ffi.gc(session, SSL._lib.SSL_SESSION_free)

    def set_session(self, session):
        SSL._lib.SSL_set_session(self._ssl, session)

    def do_handshake(self):
        with self._context.lock:
            with self._sock.iplock:
                name = '_session' + (':' in self._sock._key and '6' or '4')
                session = getattr(self._context, name, None)
                if session is not None:
                    self.set_session(session)
                self.__iowait(self._connection.do_handshake)
                if session is None or not self.session_reused():
                    setattr(self._context, name, self.get_session())

    def do_handshake_server_side(self):
        self.set_accept_state()
        self.__iowait(self._connection.do_handshake)

    def connect(self, addr):
        self.__iowait(self._connection.connect, addr)

    def send(self, data, flags=0):
        if data:
            try:
                return self.__iowait(self._connection.send, data)
            except SSL.ZeroReturnError as e:
                if self._connection.get_shutdown():
                    raise ConnectionAbortedError(errno.ECONNABORTED, 'Software caused connection abort')
                else:
                    return 0
        else:
            return 0

    write = send

    def sendall(self, data, flags=0):
        total_sent = 0
        total_to_send = len(data)
        if not hasattr(data, 'tobytes'):
            data = memoryview(data)
        while total_sent < total_to_send:
            sent = self.send(data[total_sent:total_sent + 32768]) # 32K
            total_sent += sent

    def recv(self, bufsiz, flags=None):
        pending = self._connection.pending()
        if pending:
            return self._connection.recv(min(pending, bufsiz))
        try:
            return self.__iowait(self._connection.recv, bufsiz, flags)
        except SSL.ZeroReturnError:
            if self._connection.get_shutdown() | SSL.RECEIVED_SHUTDOWN:
                return b''
            raise
        except SSL.SysCallError as e:
            if e.args == zero_EOF_error or e.args[0] in zero_errno:
                return b''
            raise

    read = recv

    def recv_into(self, buffer, nbytes=None, flags=None):
        pending = self._connection.pending()
        if pending:
            return self._connection.recv_into(buffer)
        try:
            return self.__iowait(self._connection.recv_into, buffer, nbytes, flags)
        except SSL.ZeroReturnError:
            if self._connection.get_shutdown() | SSL.RECEIVED_SHUTDOWN:
                return 0
            raise
        except SSL.SysCallError as e:
            if e.args == zero_EOF_error or e.args[0] in zero_errno:
                return 0
            raise

    readinto = recv_into

    def close(self):
        if hasattr(self._sock, 'close'):
            self._sock.close()
            self._sock = None

    def makefile(self, *args, **kwargs):
        return socket.socket.makefile(self, *args, **kwargs)

class CertificateError(SSL.Error):
    pass

# https://www.openssl.org/docs/manmaster/man3/X509_verify_cert_error_string.html
CertificateErrorTab = {
    10: lambda cert: 'time expired: %s' % cert.get_notAfter().decode(),
    18: lambda cert: 'self signed, issuer: %s' % str(cert.get_issuer())[18:-2],
    19: lambda cert: 'self signed, issuer: %s' % str(cert.get_issuer())[18:-2],
    20: lambda cert: 'untrusted CA, issuer: %s' % str(cert.get_issuer())[18:-2]
}

def match_hostname(cert, hostname):
    try:
        host_ip = ip_address(hostname)
    except ValueError:
        # Not an IP address (common case)
        host_ip = None
    dnsnames = []
    san = cert.get_subject_alt_name() or ()
    for key, value in san:
        if key == 'DNS':
            if host_ip is None and _dnsname_match(value, hostname):
                return
            dnsnames.append(value)
        elif key == 'IP Address':
            if host_ip is not None and _ipaddress_match(value, host_ip):
                return
            dnsnames.append(value)
    if not dnsnames:
    # The subject is only checked when there is no dNSName entry in subjectAltName
    # XXX according to RFC 2818, the most specific Common Name must be used.
        value = cert.get_subject().commonName
        if _dnsname_match(value, hostname):
            return
        dnsnames.append(value)
    if len(dnsnames) > 1:
        raise CertificateError(-1, "hostname %r doesn't match either of %s"
                % (hostname, ', '.join(map(repr, dnsnames))))
    elif len(dnsnames) == 1:
        raise CertificateError(-1, "hostname %r doesn't match %r"
                % (hostname, dnsnames[0]))
    else:
        raise CertificateError(-1, "no appropriate commonName or "
                "subjectAltName fields were found")

def get_subject_alt_name(self):
    for i in range(self.get_extension_count()):
        ext = self.get_extension(i)
        if ext._nid == SSL._lib.NID_subject_alt_name:
            return tuple(s.split(':', 1) for s in ext._subjectAltNameString().split(', '))

crypto.X509.get_subject_alt_name = get_subject_alt_name
