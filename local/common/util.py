# coding:utf-8

import os
import string
import _thread
import threading
import collections
import logging
from time import time, sleep
from threading import _start_new_thread as start_new_thread

LockType = _thread.LockType, threading.Lock, threading._CRLock, threading._PyRLock
_lock_decorator_cache = {}

def make_lock_decorator(lock=None, rlock=False):
    if isinstance(lock, str):
        try:
            return _lock_decorator_cache[lock]
        except KeyError:
            pass
    elif lock is None:
        if rlock:
            lock = threading.RLock()
        else:
            lock = threading.Lock()
    elif isinstance(lock, LockType):
        raise ValueError('lock parameter must be a lock name string or instance.')

    def lock_decorator(func):
        def newfunc(*args, **kwargs):
            if isinstance(lock, str):
                _lock = getattr(args[0], lock)
            else:
                _lock = lock
            _lock.acquire()
            try:
                return func(*args, **kwargs)
            finally:
                _lock.release()
        return newfunc

    if isinstance(lock, str):
        _lock_decorator_cache[lock] = lock_decorator
    return lock_decorator

NONEKEY = object()
FAILOBJ = object()
_lock_i_lock = make_lock_decorator('lock')

class LRUCache:
    # Modified from http://pypi.python.org/pypi/lru/
    #最近最少使用缓存，支持过期时间设置

    def __init__(self, max_items, expire=None):
        self.cache = {}
        self.max_items = int(max_items)
        self.expire = expire
        self.key_expire = {}
        self.key_noexpire = set()
        self.key_order = collections.deque()
        self.lock = threading.Lock()
        if expire:
            start_new_thread(self._cleanup, ())

    @_lock_i_lock
    def __delitem__(self, key):
        if key in self.cache:
            self.key_order.remove(key)
            if key in self.key_expire:
                del self.key_expire[key]
            if key in self.key_noexpire:
                del self.key_noexpire[key]
            del self.cache[key]
        else:
            raise KeyError(key)

    def __setitem__(self, key, value):
        self.set(key, value)

    def __getitem__(self, key):
        value = self.get(key, FAILOBJ)
        if value is FAILOBJ:
            raise KeyError(key)
        else:
            return value

    @_lock_i_lock
    def __contains__(self, key):
        self._expire_check(key)
        return key in self.cache

    @_lock_i_lock
    def __len__(self):
        return len(self.key_order)

    @_lock_i_lock
    def set(self, key, value, expire=False, noexpire=False):
        if noexpire:
            expire = False
            self.key_noexpire.add(key)
        elif key in self.key_noexpire:
            expire = False
        else:
            expire = expire or self.expire
        if expire:
            self.key_expire[key] = int(time()) + expire
        elif key in self.key_expire:
            del self.key_expire[key]
        self._mark(key)
        self.cache[key] = value

    @_lock_i_lock
    def get(self, key, value=None):
        self._expire_check(key)
        if key in self.cache:
            self._mark(key)
            return self.cache[key]
        else:
            return value

    @_lock_i_lock
    def getstate(self, key):
        contains = key in self.cache
        value = self.cache.get(key)
        self._expire_check(key)
        expired = key not in self.cache
        return contains, expired, value

    @_lock_i_lock
    def pop(self, key=NONEKEY):
        if key is not NONEKEY:
            self._expire_check(key)
            if key in self.cache:
                self._mark(key)
                value = self.cache[key]
                self.key_order.remove(key)
                if key in self.key_expire:
                    del self.key_expire[key]
                if key in self.key_noexpire:
                    del self.key_noexpire[key]
                del self.cache[key]
                return value
            else:
                raise KeyError(key)
        #未指明 key 时不检查抛出项是否过期，慎用！
        #返回元组 (key, value)
        if self.key_order:
            key = self.key_order.pop()
            value = self.cache[key]
            if key in self.key_noexpire:
                del self.key_noexpire[key]
            if key in self.key_expire:
                del self.key_expire[key]
            del self.cache[key]
            return key, value
        else:
            raise IndexError('pop from empty LRUCache')

    def _expire_check(self, key):
        key_expire = self.key_expire
        if key in key_expire:
            now = int(time())
            timeleft = key_expire[key] - now
            if timeleft <= 0:
                self.key_order.remove(key)
                del key_expire[key]
                del self.cache[key]
            elif timeleft < 8:
                #为可能存在的紧接的调用保持足够的反应时间
                key_expire[key] = now + 8

    def _mark(self, key):
        key_order = self.key_order
        cache = self.cache
        if key in cache:
            key_order.remove(key)
        key_order.appendleft(key)
        while len(key_order) > self.max_items:
            key = key_order.pop()
            if key in self.key_noexpire:
                key_order.appendleft(key)
            else:
                if key in self.key_expire:
                    del self.key_expire[key]
                del cache[key]

    def _cleanup(self):
        #按每秒一个的频率循环检查并清除靠后的 l/m 个项目中的过期项目
        lock = self.lock
        key_order = self.key_order
        key_expire = self.key_expire
        key_noexpire = self.key_noexpire
        cache = self.cache
        max_items = self.max_items
        m = 4
        n = 1
        while True:
            sleep(1)
            with lock:
                l = len(key_order)
                if l:
                    if l // m < n:
                        n = 1
                    key = key_order[-n]
                    if key in key_noexpire:
                        del key_order[-n]
                        key_order.appendleft(key)
                    elif key_expire[key] <= int(time()):
                        del key_order[-n]
                        del key_expire[key]
                        del cache[key]
                        n += 1

    @_lock_i_lock
    def clear(self):
        self.cache.clear()
        self.key_expire.clear()
        self.key_noexpire.clear()
        self.key_order.clear()

class LimiterEmpty(OSError):
    pass

class LimiterFull(OSError):
    pass

timeout_interval = 0.1

class Limiter:
    'A queue.Queue-like class use for count and limit.'

    def __init__(self, maxsize=1):
        if maxsize < 1:
            raise ValueError('The maxsize can not be less than 1.')
        self.maxsize = maxsize
        self.lock = threading.Lock()
        self.__qsize = 0

    @_lock_i_lock
    def qsize(self):
        return self.__qsize

    @_lock_i_lock
    def empty(self):
        return not self.__qsize

    @_lock_i_lock
    def full(self):
        return self.maxsize <= self.__qsize

    def push(self, block=True, timeout=None):
        if not block:
            pass
        elif timeout is None:
            endtime = None
        elif timeout < 0:
            raise ValueError("'timeout' must be a non-negative number")
        else:
            endtime = time() + timeout
        while True:
            with self.lock:
                if self.__qsize < self.maxsize:
                    self.__qsize += 1
                    break
            if not block or endtime and endtime - time() <= 0.0:
                raise LimiterFull(-1)
            sleep(timeout_interval)

    def pop(self, block=True, timeout=None):
        if not block:
            pass
        elif timeout is None:
            endtime = None
        elif timeout < 0:
            raise ValueError("'timeout' must be a non-negative number")
        else:
            endtime = time() + timeout
        while True:
            with self.lock:
                if self.__qsize > 0:
                    self.__qsize -= 1
                    break
            if not block or endtime and endtime - time() <= 0.0:
                raise LimiterEmpty(-1)
            sleep(timeout_interval)

MESSAGE_TEMPLATE = '''
<html><head>
<meta http-equiv="content-type" content="text/html;charset=utf-8">
<title>$title</title>
<style><!--
body {font-family: arial,sans-serif}
div.nav {margin-top: 1ex}
div.nav A {font-size: 10pt; font-family: arial,sans-serif}
span.nav {font-size: 10pt; font-family: arial,sans-serif; font-weight: bold}
div.nav A,span.big {font-size: 12pt; color: #0000cc}
div.nav A {font-size: 10pt; color: black}
A.l:link {color: #6f6f6f}
A.u:link {color: green}
//--></style>
</head>
<body text=#000000 bgcolor=#ffffff>
<table border=0 cellpadding=2 cellspacing=0 width=100%>
<tr><td bgcolor=#3366cc><font face=arial,sans-serif color=#ffffff><b>Message</b></td></tr>
<tr><td> </td></tr></table>
<blockquote>
<H1>$banner</H1>
$detail
<p>
</blockquote>
<table width=100% cellpadding=0 cellspacing=0><tr><td bgcolor=#3366cc><img alt="" width=1 height=4></td></tr></table>
</body></html>
'''
MESSAGE_TEMPLATE = string.Template(MESSAGE_TEMPLATE).substitute

def message_html(title, banner, detail=''):
    return MESSAGE_TEMPLATE(title=title, banner=banner, detail=detail)

def spawn_later(seconds, target, *args, **kwargs):
    def wrap(*args, **kwargs):
        sleep(seconds)
        try:
            target(*args, **kwargs)
        except Exception as e:
            logging.warning('%s.%s 错误：%s', target.__module__, target.__name__, e)
    start_new_thread(wrap, args, kwargs)

def spawn_loop(seconds, target, *args, **kwargs):
    def wrap(*args, **kwargs):
        while True:
            sleep(seconds)
            try:
                target(*args, **kwargs)
            except Exception as e:
                logging.warning('%s.%s 错误：%s', target.__module__, target.__name__, e)
    start_new_thread(wrap, args, kwargs)

def wait_exit(msg, exc_info=False, wait=30, code=-1, *msgargs):
    logging.error(msg, exc_info=exc_info, *msgargs)
    print(u'\n按回车键或 %d 秒后自动退出……' % wait)
    spawn_later(wait, os._exit, code)
    try:
        raw_input()
    except:
        input()
    os._exit(code)
