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

_lock_i_lock = make_lock_decorator('lock')

class LRUCache:
    # Modified from http://pypi.python.org/pypi/lru/
    #最近最少使用缓存，支持过期时间设置
    __marker = object()
    __marker2 = object()

    def __init__(self, max_items, expire=0):
        # expire == 0：最近最少使用过期
        # expire >  0：最近最少使用过期 + 时间过期
        self.cache = {}
        self.key_order = collections.deque()
        self.max_items = int(max_items)
        self.expire = int(expire)
        self.lock = threading.Lock()
        if self.expire > 0:
            start_new_thread(self._cleanup, ())

    @_lock_i_lock
    def __delitem__(self, key):
        del self.cache[key]
        self.key_order.remove(key)

    def __setitem__(self, key, value):
        _ve = self.cache.get(key)
        if _ve is not None:
            if _ve[1] < 0:
                self.set(key, value, -1)
                return
        self.set(key, value)

    def __getitem__(self, key):
        value = self.get(key, self.__marker)
        if value is self.__marker:
            raise KeyError(key)
        else:
            return value

    @_lock_i_lock
    def __contains__(self, key):
        if self._expire_check(key):
            return False
        return key in self.cache

    @_lock_i_lock
    def __len__(self):
        return len(self.key_order)

    @_lock_i_lock
    def set(self, key, value, expire=None):
        # expire is False or /
        # expire <  0：永不过期，只能在这里设置
        # expire == 0：最近最少使用过期
        # expire >  0：最近最少使用过期 + 时间过期
        if expire is None:
            expire = self.expire
        elif expire is False:
            expire = -1
        else:
            expire = int(expire)
        if expire > 0:
            expire += int(time())
        cache = self.cache
        key_order = self.key_order
        max_items = self.max_items
        if key in cache:
            key_order.remove(key)
        key_order.appendleft(key)
        cache[key] = value, expire
        while len(key_order) > max_items:
            key = key_order.pop()
            value, expire = cache[key]
            if expire < 0:
                key_order.appendleft(key)
            else:
                del cache[key]

    @_lock_i_lock
    def get(self, key, value=None):
        if key in self.cache and not self._expire_check(key):
            self.key_order.remove(key)
            self.key_order.appendleft(key)
            value = self.cache[key][0]
        return value

    @_lock_i_lock
    def getstate(self, key):
        contains = key in self.cache
        value = self.cache.get(key)
        expired = self._expire_check(key)
        return contains, expired, value if value is None else value[0]

    def setpadding(self, key, padding=__marker2):
        #设置填充占位
        self[key] = padding

    def gettill(self, key, padding=__marker2, timeout=30):
        #获取非填充占位值
        n = 0
        timeout_interval = 0.01
        timeout = int(timeout / timeout_interval)
        value = self.get(key)
        while value is padding:
            n += 1
            if n > timeout:
                return None
            sleep(timeout_interval)
            value = self.cache[key][0]
        return value

    @_lock_i_lock
    def pop(self, key, value=__marker):
        try:
            if self._expire_check(key):
                raise KeyError(key)
            value = self.cache.pop(key)[0]
        except KeyError:
            if value is self.__marker:
                raise
        else:
            self.key_order.remove(key)
        return value

    @_lock_i_lock
    def popitem(self, last=True):
        if last:
            index = -1
            pop = self.key_order.pop
        else:
            index = 0
            pop = self.key_order.popleft
        try:
            while True:
                if not self._expire_check(index=index):
                    break
            key = pop()
        except IndexError:
            raise IndexError('popitem from empty LRUCache')
        value = self.cache.pop(key)[0]
        return key, value

    def _expire_check(self, key=__marker, index=None):
        if key is self.__marker and isinstance(index, int):
            key = self.key_order[index]
        cache = self.cache
        if key in cache:
            value, expire = cache[key]
            if expire > 0:
                now = int(time())
                timeleft = expire - now
                if timeleft <= 0:
                    del cache[key]
                    if isinstance(index, int):
                        del self.key_order[index]
                    else:
                        self.key_order.remove(key)
                    return True
                elif timeleft < 8:
                    #为可能存在的紧接的调用保持足够的反应时间
                    cache[key] = value, now + 8

    def _cleanup(self):
        #按每秒一次的频率循环检查并清除靠后的 l/m 个项目中的过期项目
        m = 4
        n = 1
        lock = self.lock
        key_order = self.key_order
        cache = self.cache
        clean_items = self.max_items // m
        while True:
            sleep(1)
            with lock:
                l = len(key_order) // m
                if l < clean_items:
                    n = 1
                    continue
                if n > l:
                    n = 1
                now = int(time())
                while True:
                    try:
                        key = key_order[-n]
                    except IndexError:
                        break
                    value, expire = self.cache[key]
                    if expire < 0:
                        del key_order[-n]
                        key_order.appendleft(key)
                        #终止全部都是永不过期项目的极端情况
                        break
                    elif 0 < expire <= now:
                        del key_order[-n]
                        del cache[key]
                    else:
                        n += 1
                        break

    @_lock_i_lock
    def clear(self):
        self.cache.clear()
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

    def push(self, block=True, timeout=None, maxsize=None):
        if not block:
            pass
        elif timeout is None:
            endtime = None
        elif timeout < 0:
            raise ValueError("'timeout' must be a non-negative number")
        else:
            endtime = time() + timeout
        maxsize = maxsize or self.maxsize
        while True:
            with self.lock:
                if self.__qsize < maxsize:
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

class LimitBase:
    '''Base limiter via dict key.

    _key:        dict key which marking objects
    limiters:    limiters in dict
    max_per_key: allow objects max size per key
    timeout:     push and pop method timedout
    lock:        a threading.Lock Instance
    '''

    _key = None

    def __init__(self, key, max_per_key=None, timeout=None):
        max_per_key = max_per_key or self.max_per_key
        timeout = timeout or self.timeout
        with self.lock:
            try:
                limiter = self.limiters[key]
            except KeyError:
                self.limiters[key] = limiter = Limiter(max_per_key)
        limiter.push(timeout=timeout, maxsize=max_per_key)
        self._key = key

    def __del__(self):
        if self._key:
            self._key, key = None, self._key
            try:
                limiter = self.limiters[key]
            except KeyError:
                pass
            else:
                limiter.pop(block=False)
                start_new_thread(self.clearup, (key,))
            return True

    @classmethod
    def clearup(cls, key):
        sleep(timeout_interval)
        try:
            with cls.lock:
                if cls.limiters[key].empty():
                    del cls.limiters[key]
        except KeyError:
            pass

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
