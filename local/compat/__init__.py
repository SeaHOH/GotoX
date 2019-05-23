# coding:utf-8

def dummy(*args, **kwargs): pass

def clean_after_invoked(func):
    def newfunc(*args, **kwargs):
        try:
            func(*args, **kwargs)
        finally:
            func.__globals__[func.__code__.co_name] = dummy

    return newfunc

import os
import sys
from local.common.path import py_dir, packages
from .monkey_patch import *

def wait_exit(*args, **kwargs):
    replace_logging()
    from local.common.util import wait_exit
    wait_exit(*args, **kwargs)

_ver = sys.version_info
PY3 = _ver[0] == 3
#PY35 = PY3 and _ver[1] == 5
if not PY3:
    wait_exit(u'请使用 Python 3 系列版本运行本程序！')

#这段代码负责添加依赖库路径，不要改变位置
# Windows 使用发布版本自带的 Python 不用重复添加
if os.path.dirname(sys.executable) != py_dir:
    import glob
    #放在最后，优先导入当前运行 Python 已安装模块
    sys.path.append(packages)
    sys.path.extend(glob.glob(os.path.join(packages, '*.egg')))

@clean_after_invoked
def init():
    try:
        import gevent
        import gevent.monkey
        gevent.monkey.patch_all(os=False, signal=False, subprocess=False, Event=True)
    except ImportError:
        wait_exit('无法找到 gevent 或者与 Python 版本不匹配，'
                  '请安装 gevent-1.0.0 以上版本，'
                  '或将相应 .egg 放到 %r 文件夹！', packages, exc_info=True)
    except TypeError:
        gevent.monkey.patch_all(os=False)

    replace_logging()
    patch_builtins()
    patch_configparser()

    import logging

    if gevent.__version__ < '1.0.0':
        logging.warning('警告：请更新 gevent 至 1.0.0 以上版本！')

    try:
        import OpenSSL
    except ImportError:
        wait_exit('无法找到 pyOpenSSL，请安装 pyOpenSSL-16.0.0 以上版本，'
                  '或将相应 .egg 放到 %r 文件夹！', packages, exc_info=True)

    try:
        import dnslib
    except ImportError:
        wait_exit('无法找到 dnslib，请安装 dnslib-0.8.3 以上版本，'
                  '或将相应 .egg 放到 %r 文件夹！', packages, exc_info=True)
