# coding:utf-8

import os
import string
import weakref
import threading
import collections
import logging
from time import mtime, sleep
from threading import _start_new_thread as start_new_thread
from .decorator import make_lock_decorator


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
            expire += int(mtime())
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
                now = int(mtime())
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
                l = len(key_order)
                if l < clean_items:
                    n = 1
                    continue
                l = l // m
                if n > l:
                    n = 1
                now = int(mtime())
                while True:
                    try:
                        key = key_order[-n]
                    except IndexError:
                        break
                    expire = self.cache[key][1]
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

class LimiterFull(OSError):
    pass

class Limiter:
    timeout_interval = 0.1

    def __init__(self, maxsize=1):
        if maxsize < 1:
            raise ValueError('The maxsize can not be less than 1.')
        self.maxsize = maxsize
        self.lock = threading.Lock()
        self.__lock_push = threading.Lock()
        self.__qsize = 0

    def qsize(self):
        return self.__qsize

    def empty(self):
        if self.__lock_push.locked():
            return False
        else:
            return self.__qsize == 0

    def full(self):
        return self.__qsize >= self.maxsize

    @_lock_i_lock
    def _push(self, maxsize):
        if self.__qsize < maxsize:
            self.__qsize += 1
            return True

    def push(self, block=True, timeout=None, maxsize=None):
        if block:
            if timeout is None:
                timeout = -1
            else:
                if timeout < 0:
                    raise ValueError("'timeout' must be a non-negative number")
                elif timeout == 0:
                    block = False
                else:
                    endtime = mtime() + timeout
        maxsize = maxsize or self.maxsize
        limited = not self._push(maxsize)
        if limited and block and self.__lock_push.acquire(timeout=timeout):
            try:
                while limited:
                    if timeout > 0:
                        timeout = endtime - mtime()
                        if timeout <= 0:
                            break
                    sleep(self.timeout_interval)
                    limited = not self._push(maxsize)
            finally:
                self.__lock_push.release()
        if limited:
            raise LimiterFull

    @_lock_i_lock
    def pop(self):
        if self.__qsize > 0:
            self.__qsize -= 1
            return True

class finalize:
    __slots__ = 'weakref', 'func', 'args', 'kwargs'

    def __init__(self, obj, func, *args, **kwargs):
        self.weakref = weakref.ref(obj, self)
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def __call__(self, _=None):
        self.func, func = None, self.func
        if func:
            self.args, args = None, self.args
            self.kwargs, kwargs = None, self.kwargs
            func(*args, **kwargs)
            return True


class LimitBase:
    '''Base limiter.

    Don't modify the following properties in subclass:
    _limiter:             limiter, set by Class.init, modify it via _limiterFactory

    Subclass could customize the following properties:
    _limiterFactory:      classmethod. add what properties you need to the limiter
    maxsize:              allow objects max size
    timeout:              push block timedout, 'None' means block forever
    '''

    maxsize = 1
    timeout = None

    @classmethod
    def _limiterFactory(cls):
        return Limiter(cls.maxsize)

    @classmethod
    def init(cls):
        if not hasattr(cls, '_limiter'):
            if cls.maxsize <= 0:
                cls.maxsize = 1
            cls._limiter = cls._limiterFactory()

    def __init__(self, maxsize=None, timeout=None):
        self.push(maxsize, timeout)
        self._finalize = finalize(self, self.pop)

    def close(self):
        return self._finalize()

    @classmethod
    def push(cls, maxsize=None, timeout=None):
        maxsize = maxsize or cls.maxsize
        timeout = timeout or cls.timeout
        try:
            cls._limiter.push(timeout=timeout, maxsize=maxsize)
        except LimiterFull:
            raise LimiterFull(-1, cls)
        return True

    @classmethod
    def pop(cls):
        if not cls._limiter.pop():
            logging.debug('%s.pop with empty limiter', cls, stack_info=True)

    @classmethod
    def full(cls):
        return cls._limiter.full()

class LimitDictBase:
    '''Base limiters via dict key.

    Don't modify the following properties in subclass:
    _limiter:             limiter, set by Class.__init__, modify it via _limiterFactory
    _key:                 dict key which marking objects

    Subclass could customize the following properties:
    _limiterFactory:      classmethod. add what properties you need to the limiter
    _limiters:            limiters in dict, set by Class.init
    lock:                 a threading.Lock Instance, set by Class.init
    maxsize:              allow objects max size per key
    timeout:              push block timedout, 'None' means block forever
    '''

    maxsize = 1
    timeout = None

    @classmethod
    def _limiterFactory(cls):
        return Limiter(cls.maxsize)

    @classmethod
    def init(cls):
        if not hasattr(cls, '_limiters'):
            if cls.maxsize <= 0:
                cls.maxsize = 1
            cls._limiters = {}
        if not hasattr(cls, 'lock'):
            cls.lock = threading.Lock()

    def __init__(self, key, maxsize=None, timeout=None):
        self._limiter = self.push(key, maxsize, timeout)
        self._key = key
        self._finalize = finalize(self, self.pop, key)

    def close(self):
        return self._finalize()

    @classmethod
    def _get_limiter(cls, key):
        limiter = cls._limiters.get(key)
        return limiter and limiter()

    @classmethod
    def _clear(cls, wref):
        weakref._remove_dead_weakref(cls._limiters, wref.key)

    @classmethod
    def push(cls, key, maxsize=None, timeout=None):
        maxsize = maxsize or cls.maxsize
        timeout = timeout or cls.timeout
        with cls.lock:
            limiter = cls._get_limiter(key)
            if limiter is None:
                limiter = cls._limiterFactory()
                cls._limiters[key] = weakref.KeyedRef(limiter, cls._clear, key)
        try:
            limiter.push(timeout=timeout, maxsize=maxsize)
        except LimiterFull:
            raise LimiterFull(-1, (cls, key))
        return limiter

    @classmethod
    def pop(cls, key):
        limiter = cls._get_limiter(key)
        if limiter is None or not limiter.pop():
            logging.debug('%s.pop %r with empty limiter', cls, key, stack_info=True)

    @classmethod
    def full(cls, key):
        limiter = cls._get_limiter(key)
        if limiter is None:
            return False
        else:
            return limiter.full()

MESSAGE_TEMPLATE = '''\
<html><head>
<meta http-equiv="content-type" content="text/html;charset=utf-8">
<title>$title</title>
<style><!--
body {
    font-family: arial,sans-serif;
    background-color: #ffffff;
}
.header {
    background-color: #3366cc;
    width: 100%;
}
.header span {
    font-size: 16pt;
    font-weight: bold;
    color: #ffffff;
    padding: 8px 20px;
    width: 100%;
}
blockquote {font-size: 150%;}
.foot {
    background-color: #3366cc;
    width: 100%;
    height: 6px;
}
//--></style>
</head>
<body>
<div class=header><span>Message</span></div>
<div><blockquote>
<H1>$banner</H1>
$detail
</blockquote></div>
<div class=foot><span></span></div>
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

def wait_exit(msg, *msgargs, exc_info=False, wait=30, code=-1):
    logging.error(msg, exc_info=exc_info, *msgargs)
    print(u'\n按回车键或 %d 秒后自动退出……' % wait)
    spawn_later(wait, os._exit, code)
    try:
        raw_input()
    except:
        input()
    os._exit(code)
