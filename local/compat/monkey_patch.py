# coding:utf-8

from local.common.decorator import clean_after_invoked

@clean_after_invoked
def replace_logging():
    import local.clogging as clogging
    clogging.replace_logging()
    clogging.addLevelName(15, 'TEST', clogging.COLORS.GREEN)
    clogging.preferredEncoding = 'cp936'

@clean_after_invoked
def patch_stdout():
    import io
    import sys
    sys.stdout = io.TextIOWrapper(sys.stdout.detach(),
                                  encoding=sys.stdout.encoding,
                                  errors='backslashreplace',
                                  line_buffering=True)

def patch_gevent_socket():
    #使用 libuv-cffi 事件循环时，重复 gevent.socket.send 操作可能会被阻塞
    #没找到真正的原因，暂时这么处理，CPU 使用会增加 50-100%
    from gevent.socket import socket
    from .openssl import SSLConnection

    def send(self, *args, **kwargs):
        sent = self._send(*args, **kwargs)
        self._wait(self._write_event)
        return sent

    if not hasattr(socket, '_send'):
        socket._send = socket.send
        socket.send = send

    if not hasattr(SSLConnection, '_send'):
        SSLConnection._send = SSLConnection.send
        SSLConnection.send = send

def revert_gevent_socket_patch():
    #如果 gevent.socket.send 操作不会阻塞，可撤销补丁
    from gevent.socket import socket
    from .openssl import SSLConnection

    if hasattr(socket, '_send'):
        socket.send = socket._send
        del socket._send

    if hasattr(SSLConnection, '_send'):
        SSLConnection.send = SSLConnection._send
        del SSLConnection._send

@clean_after_invoked
def patch_select():
    # libuv-cffi 的 bug 问题越来越大，暂时这么处理
    import select as mselect

    def select(rlist, wlist, xlist, timeout=None):
        res = _select(rlist, wlist, xlist, timeout)
        if timeout == 0 or not any(res):
            return res
        return _select(rlist, wlist, xlist, 0)

    _select = mselect.select
    mselect.select = select

@clean_after_invoked
def patch_time():
    import time
    if hasattr(time, 'clock_gettime') and hasattr(time, 'CLOCK_BOOTTIME'):
        time.mtime = lambda: time.clock_gettime(time.CLOCK_BOOTTIME)
    else:
        time.mtime = time.monotonic

@clean_after_invoked
def patch_builtins():
    import builtins

    #重写了类方法 __getattr__ 时，修正 hasattr
    NOATTR = object()
    builtins.gethasattr = lambda o, a: getattr(o, a, NOATTR) != NOATTR

    class classlist(list): pass
    builtins.classlist = classlist

@clean_after_invoked
def patch_configparser():
    import logging
    from configparser import _UNSET, NoSectionError, NoOptionError, RawConfigParser
    from collections.abc import Iterable

    #去掉 lower 以支持选项名称大小写共存
    RawConfigParser.optionxform = lambda s, opt: opt

    #添加空值（str）作为 get 的 fallback
    #支持指定 get 结果空值的 fallback
    RawConfigParser._get = RawConfigParser.get

    def get(self, section, option, *, raw=False, vars=None, fallback=_UNSET):
        value = self._get(section, option, raw=raw, vars=vars, fallback='')
        if not value and fallback is not _UNSET:
            return fallback
        return value

    RawConfigParser.get = get

    #支持指定 getint、getfloat、getboolean 非法值的 fallback
    def _get_conv(self, section, option, conv, *, raw=False, vars=None,
                  fallback=_UNSET, **kwargs):
        value = self._get(section, option, raw=raw, vars=vars, fallback='')
        try:
            value = conv(value)
            if value or value in (0, False) or fallback is _UNSET:
                return value
        except ValueError as e:
            if value:
                logging.warning('配置错误 [%s/%s] = %r：%r',
                                section, option, value, e)
            if fallback is _UNSET:
                raise
        try:
            return conv(fallback)
        except ValueError as e:
            if conv == self._convert_to_boolean:
                return bool(fallback)
            elif not value:
                logging.debug('默认值配置错误 [%s/%s] = %r：%r',
                                section, option, fallback, e)
                return value
            else:
                raise

    RawConfigParser._get_conv = _get_conv

    #添加 getlist、gettuple，分隔符为 |
    def _convert_to_list(self, value):
        # list 是可变序列，不直接返回
        if not value:
            return []
        if isinstance(value, str):
            value = (v.strip() for v in value.split('|') if v.strip())
        if isinstance(value, Iterable):
            return list(value)
        else:
            return [value]

    def _convert_to_tuple(self, value):
        # tuple 是不可变序列，直接返回
        if isinstance(value, tuple):
            return value
        if not value:
            return ()
        if isinstance(value, str):
            value = (v.strip() for v in value.split('|') if v.strip())
        if isinstance(value, Iterable):
            return tuple(value)
        else:
            return value,

    def getlist(self, section, option, *, raw=False, vars=None,
                   fallback=_UNSET, **kwargs):
        return self._get_conv(section, option, self._convert_to_list,
                              raw=raw, vars=vars, fallback=fallback, **kwargs)

    def gettuple(self, section, option, *, raw=False, vars=None,
                   fallback=_UNSET, **kwargs):
        return self._get_conv(section, option, self._convert_to_tuple,
                              raw=raw, vars=vars, fallback=fallback, **kwargs)

    RawConfigParser._convert_to_list = _convert_to_list
    RawConfigParser._convert_to_tuple = _convert_to_tuple
    RawConfigParser.getlist = getlist
    RawConfigParser.gettuple = gettuple

    #默认编码 utf8
    _read = RawConfigParser.read
    RawConfigParser.read = lambda s, f, encoding='utf8': _read(s, f, encoding)

@clean_after_invoked
def patch_dnslib():
    import dnslib

    #提高兼容性
    # https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
    QTYPE = {
        0: 'NONE',  # Reserved
        1: 'A',
        2: 'NS',
        3: 'MD',
        4: 'MF',
        5: 'CNAME',
        6: 'SOA',
        7: 'MB',
        8: 'MG',
        9: 'MR',
        10: 'NULL',
        11: 'WKS',
        12: 'PTR',
        13: 'HINFO',
        14: 'MINFO',
        15: 'MX',
        16: 'TXT',
        17: 'RP',
        18: 'AFSDB',
        19: 'X25',
        20: 'ISDN',
        21: 'RT',
        22: 'NSAP',
        23: 'NSAP_PTR',
        24: 'SIG',
        25: 'KEY',
        26: 'PX',
        27: 'GPOS',
        28: 'AAAA',
        29: 'LOC',
        30: 'NXT',
        33: 'SRV',
        35: 'NAPTR',
        36: 'KX',
        37: 'CERT',
        38: 'A6',
        39: 'DNAME',
        41: 'OPT',
        42: 'APL',
        43: 'DS',
        44: 'SSHFP',
        45: 'IPSECKEY',
        46: 'RRSIG',
        47: 'NSEC',
        48: 'DNSKEY',
        49: 'DHCID',
        50: 'NSEC3',
        51: 'NSEC3PARAM',
        52: 'TLSA',
        53: 'SMIMEA',
        55: 'HIP',
        56: 'NINFO',
        59: 'CDS',
        60: 'CDNSKEY',
        61: 'OPENPGPKEY',
        62: 'CSYNC',
        63: 'ZONEMD',
        64: 'SVCB',
        65: 'HTTPS',
        99: 'SPF',
        103: 'UNSPEC',
        108: 'EUI48',
        109: 'EUI64',
        249: 'TKEY',
        250: 'TSIG',
        251: 'IXFR',
        252: 'AXFR',
        253: 'MAILB',
        254: 'MAILA',
        255: 'ANY',
        256: 'URI',
        257: 'CAA',
        258: 'AVC',
        259: 'DOA',
        260: 'AMTRELAY',
        32768: 'TA',
        32769: 'DLV'
    }
    RCODE = {
        0: 'NOERROR',
        1: 'FORMERR',
        2: 'SERVFAIL',
        3: 'NXDOMAIN',
        4: 'NOTIMP',
        5: 'REFUSED',
        6: 'YXDOMAIN',
        7: 'YXRRSET',
        8: 'NXRRSET',
        9: 'NOTAUTH',
        10: 'NOTZONE',
        11: 'DSOTYPENI',
        16: 'BADVERS',
        #16: 'BADSIG',
        17: 'BADKEY',
        18: 'BADTIME',
        19: 'BADMODE',
        20: 'BADNAME',
        21: 'BADALG',
        22: 'BADTRUNC',
        23: 'BADCOOKIE'
    }
    dnslib.QTYPE.forward.update(QTYPE)
    dnslib.QTYPE.reverse.update((v,k) for (k,v) in QTYPE.items())
    dnslib.RCODE.forward.update(RCODE)
    dnslib.RCODE.reverse.update((v,k) for (k,v) in RCODE.items())
