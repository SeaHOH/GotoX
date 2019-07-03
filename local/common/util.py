# coding:utf-8

import os
import string
import threading
import collections
import logging
from time import time, sleep
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
                l = len(key_order)
                if l < clean_items:
                    n = 1
                    continue
                l = l // m
                if n > l:
                    n = 1
                now = int(time())
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

    Don't modify the following properties in subclass:
    _key:                 dict key which marking objects
    _limiters_cache:      store the idle limiters
    _limiters_cache_size: max number of the idle limiters

    Subclass must customize the following properties:
    limiters:             limiters in dict
    max_per_key:          allow objects max size per key
    timeout:              push and pop method timedout
    lock:                 a threading.Lock Instance
    '''

    _key = None
    _limiters_cache = []
    _limiters_cache_size = 128

    def __init__(self, key, max_per_key=None, timeout=None):
        self.push(key, max_per_key, timeout)
        self._key = key

    #主要使用 close 来解除限制，可避免只使用 __del__ 时需频繁地主动 GC
    def __del__(self):
        self.close()

    def close(self):
        with self.lock:
            self._key, key = None, self._key
        if key:
            self.pop(key)
            return True

    def get_limite_lock(self):
        try:
            return self.limiters[self._key].lock
        except KeyError:
            return self.lock

    @classmethod
    def push(cls, key, max_per_key=None, timeout=None):
        max_per_key = max_per_key or cls.max_per_key
        timeout = timeout or cls.timeout
        exist = None
        with cls.lock:
            try:
                limiter = cls.limiters[key]
                exist = True
            except KeyError:
                if cls._limiters_cache:
                    limiter = cls._limiters_cache.pop()
                    limiter.maxsize = max_per_key
                else:
                    limiter = Limiter(max_per_key)
                #确保正确计数，及避免在 lock 释放后 limiter 可能被 clearup 删除
                limiter._Limiter__qsize = 1
                cls.limiters[key] = limiter
        if exist:
            limiter.push(timeout=timeout, maxsize=max_per_key)
        return True

    @classmethod
    def pop(cls, key):
        try:
            cls.limiters[key].pop(block=False)
            if cls.limiters[key].empty():
                cls.clearup(key)
        except:
            cls.clearup(key)

    @classmethod
    def full(cls, key):
        try:
            return cls.limiters[key].full()
        except KeyError:
            return False

    @classmethod
    def clearup(cls, key):
        start_new_thread(cls._clearup, (key,))

    @classmethod
    def _clearup(cls, key):
        sleep(timeout_interval)
        try:
            with cls.lock:
                if cls.limiters[key].empty():
                    limiter = cls.limiters.pop(key)
                    if len(cls._limiters_cache) < cls._limiters_cache_size:
                        cls._limiters_cache.append(limiter)
        except KeyError:
            pass

MESSAGE_TEMPLATE = '''
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
<p></blockquote></div>
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

def wait_exit(msg, exc_info=False, wait=30, code=-1, *msgargs):
    logging.error(msg, exc_info=exc_info, *msgargs)
    print(u'\n按回车键或 %d 秒后自动退出……' % wait)
    spawn_later(wait, os._exit, code)
    try:
        raw_input()
    except:
        input()
    os._exit(code)
