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
    from collections import Iterable

    #去掉 lower 以支持选项名称大小写共存
    RawConfigParser.optionxform = lambda s, opt: opt

    #添加空值（str）作为 get 的 fallback，不影响 _get_conv
    #支持指定 get 结果空值的 fallback
    RawConfigParser._get = RawConfigParser.get

    def get(self, section, option, *, raw=False, vars=None, fallback=_UNSET):
        try:
            value = self._get(section, option, raw=raw, vars=vars)
        except (NoSectionError, NoOptionError):
            value = ''
        if not value and fallback is not _UNSET:
            return fallback
        return value

    RawConfigParser.get = get

    #支持指定 getint、getfloat、getboolean 非法值的 fallback
    def _get_conv(self, section, option, conv, *, raw=False, vars=None,
                  fallback=_UNSET, **kwargs):
        try:
            value = self._get(section, option, raw=raw, vars=vars, **kwargs)
            value = conv(value)
            if value or value in (0, False):
                return value
            if fallback is _UNSET:
                return value
            else:
                raise ValueError
        except (NoSectionError, NoOptionError, ValueError) as e:
            if isinstance(e, ValueError) and value:
                logging.warning('配置错误 [%s/%s] = %r：%r',
                                section, option, value, e)
            if fallback is _UNSET:
                raise
        try:
            return conv(fallback)
        except ValueError:
            if conv == self._convert_to_boolean:
                return bool(fallback)
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
