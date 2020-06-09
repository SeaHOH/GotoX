# coding:utf-8

import time
import _thread
import threading
from functools import partial

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

def sole_invoked(func=None, blocking=False):

    def newfunc(*args, **kwargs):
        nonlocal result
        if lock.acquire(blocking=blocking):
            try:
                result = func(*args, **kwargs)
            finally:
                lock.release()
        return result

    if callable(func):
        result = None
        lock = threading.Lock()
        return newfunc
    else:
        return partial(sole_invoked, blocking=blocking)

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

import sys
import weakref
from copy import _copy_dispatch

class _readonly(type):
    def __setattr__(self, name, value):
        raise TypeError("can't set attributes of class %r" % self.__name__)

class propertyb(metaclass=_readonly):

    class __doc__:
        '''Similar to built-in type property. More see help(property).

        Provides new 'fxxxget' parameters and 'xxxgetter' methods.
        (xxx is one of types: int , str, bool.)

        fxxxget is a function to be used for getting an attribute value of xxx,
        get xxx value via code 'xxx(attribute)', because __xxx__ method of the
        attribute value has been covered with fxxxget.
        If fget return a xxx type, then fxxxget will be ignored.
        If no fget and only one fxxxget supplied, then return xxx value directly.

        Notice:
        Sometimes fxxxget will fail (no raise), you must test it working before
        using.
        Unlike property, propertyb.*ter methods always returns a same instance.
        '''

        __slots__ = ()
        docs = weakref.WeakKeyDictionary()

        def __set__(self, inst, value):
            if value is not None:
                self.docs[inst] = value

        def __get__(self, inst, owner):
            if inst is None:
                return self.__doc__
            return self.docs.get(inst) or inst.fget.__doc__

    class __isabstractmethod__:
        __slots__ = ()
        str = "<attribute '__isabstractmethod__' of %r objects>" % \
              sys._getframe(1).f_locals.get('__qualname__')

        def __repr__(self):
            return self.str

        def __set__(self, inst, value):
            pass

        def __get__(self, inst, owner):
            if inst is None:
                return self
            name = '__isabstractmethod__'
            return getattr(inst.fget, name, False) or \
                   getattr(inst.fset, name, False) or \
                   getattr(inst.fdel, name, False) or \
                   getattr(inst.fintget, name, False) or \
                   getattr(inst.fstrget, name, False) or \
                   getattr(inst.fboolget, name, False)

    __doc__ = __doc__()
    __isabstractmethod__ = __isabstractmethod__()
    __slots__ = ('fget', 'fset', 'fdel', 'fintget', 'fstrget', 'fboolget',
                 '__weakref__')

    def __init__(self, fget=None, fset=None, fdel=None, doc=None,
                fintget=None, fstrget=None, fboolget=None):
        self.__doc__ = doc
        self.getter(fget)
        self.setter(fset)
        self.deleter(fdel)
        self.intgetter(fintget)
        self.strgetter(fstrget)
        self.boolgetter(fboolget)

    def __repr__(self):
        name = '__qualname__'
        wrapped = getattr(self.fget, name, False) or \
                  getattr(self.fset, name, False) or \
                  getattr(self.fdel, name, False) or \
                  getattr(self.fintget, name, False) or \
                  getattr(self.fstrget, name, False) or \
                  getattr(self.fboolget, name, False)
        if wrapped:
            return '<%s object at %s wrapper for %s method>' % (
                   type(self).__name__, hex(id(self)), wrapped)
        else:
            return '<%s object at %s>' % (
                   type(self).__name__, hex(id(self)))

    def __setattr__(self, name, value):
        if name == '__isabstractmethod__' or \
                name != '__doc__' and name in self.__slots__:
            raise AttributeError('%r object attribute %r is read-only'
                                % (type(self).__name__, name))
        object.__setattr__(self, name, value)

    def __get__(self, inst, owner):
        'Return an attribute of instance, which is of type owner.'
        if inst is None:
            return self
        if self.fget:
            res = self.fget(inst)
            fint = self.fintget and not isinstance(res, int)
            fstr = self.fstrget and not isinstance(res, str)
            fbool = self.fboolget and not isinstance(res, bool)
            if fint or fstr or fbool:
                rescls = type(res)

                class crescls(rescls):
                    def __getattr__(ss, name):
                        return getattr(res, name)
                    if fint:
                        def __int__(ss):
                            return int(self.fintget(inst))
                    if fstr:
                        def __str__(ss):
                            return str(self.fstrget(inst))
                    if fbool:
                        def __bool__(ss):
                            return bool(self.fboolget(inst))

                if rescls in _copy_dispatch:
                    try:
                        return crescls(res)
                    except:
                        pass
                else:
                    reductor = getattr(res, '__reduce_ex__', None)
                    if reductor:
                        info = reductor(4)
                        if isinstance(info, tuple) and 1 < len(info) < 6:
                            info = list(info)
                            info[1] = crescls,
                            info = tuple(info)
                    else:
                        reductor = getattr(res, '__reduce__', None)
                        if reductor:
                            info = reductor()
                            if isinstance(info, tuple) and 1 < len(info) < 6:
                                info = list(info)
                                info[1] = (crescls,) + info[1]
                                info = tuple(info)
                        else:
                            info = None
                    if info and not isinstance(info, str):
                        try:
                            return _reconstruct(res, info, 0)
                        except:
                            pass
                print('Warning: %s fxxxget failed!' % self, file=sys.stderr)
            return res
        elif self.fintget is self.fstrget is self.fboolget is None:
            raise AttributeError('unreadable attribute of %s object'
                                % type(inst).__name__)
        elif self.fintget is self.fstrget is None:
            return bool(self.fboolget(inst))
        elif self.fintget is self.fboolget is None:
            return str(self.fstrget(inst))
        elif self.fstrget is self.fboolget is None:
            return int(self.fintget(inst))
        else:
            class rescls:
                if self.fintget:
                    def __int__(ss):
                        return int(self.fintget(inst))
                if self.fstrget:
                    def __str__(ss):
                        return str(self.fstrget(inst))
                if self.fboolget:
                    def __bool__(ss):
                        return bool(self.fboolget(inst))

            return rescls()

    def getter(self, fget):
        'Descriptor to change the getter.'
        object.__setattr__(self, 'fget', fget)
        return self

    def __set__(self, inst, value):
        'Set an attribute of instance to value.'
        if self.fset:
            self.fset(inst, value)
        else:
            raise AttributeError("can't set attribute of %s object"
                                % type(inst).__name__)

    def setter(self, fset):
        'Descriptor to change the setter.'
        object.__setattr__(self, 'fset', fset)
        return self

    def __delete__(self, inst):
        'Delete an attribute of instance.'
        if self.fdel:
            self.fdel(inst)
        else:
            raise AttributeError("can't delete attribute of %s object"
                                % type(inst).__name__)

    def deleter(self, fdel):
        'Descriptor to change the deleter.'
        object.__setattr__(self, 'fdel', fdel)
        return self

    def intgetter(self, fintget):
        'Descriptor to change the intgetter.'
        object.__setattr__(self, 'fintget', fintget)
        return self

    def strgetter(self, fstrget):
        'Descriptor to change the strgetter.'
        object.__setattr__(self, 'fstrget', fstrget)
        return self

    def boolgetter(self, fboolget):
        'Descriptor to change the boolgetter.'
        object.__setattr__(self, 'fboolget', fboolget)
        return self
