# coding:utf-8

def dummy(*args, **kwargs): pass

def clean_after_invoked(func):
    result = None
    def newfunc(*args, **kwargs):
        nonlocal result
        if func.__globals__[func.__code__.co_name] is not dummy:
            try:
                result = func(*args, **kwargs)
            finally:
                func.__globals__[func.__code__.co_name] = dummy
        return result

    return newfunc

import _thread
import threading

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
    elif not isinstance(lock, (_thread.LockType, threading.Lock,
                               threading._CRLock, threading._PyRLock)):
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
