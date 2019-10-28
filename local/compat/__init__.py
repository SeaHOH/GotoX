# coding:utf-8

import os
import sys
from local.common.cconfig import cconfig
from local.common.path import py_dir, config_dir, data_dir, packages

from .monkey_patch import *

def wait_exit(*args, **kwargs):
    replace_logging()
    patch_time()
    from local.common.util import wait_exit
    wait_exit(*args, **kwargs)

PY3 = sys.version_info.major == 3
if not PY3:
    import time
    print(u'请使用 Python 3 系列版本运行本程序！\n30 秒后自动退出……')
    time.sleep(30)
    os._exit(-1)

#这段代码负责添加依赖库路径，不要改变位置
# Windows 使用发布版本自带的 Python 不用重复添加
if os.path.dirname(sys.executable) != py_dir:
    import glob
    #放在最后，优先导入当前运行 Python 已安装模块
    sys.path.append(packages)
    sys.path.extend(glob.glob(os.path.join(packages, '*.egg')))

@clean_after_invoked
def single_instance(name):
    lock_file = os.path.join(data_dir, name + '.lock')

    def unlock():
        lock.close()
        os.remove(lock_file)

    while True:
        try:
            lock = open(lock_file, 'xb', 0)
        except FileExistsError:
            try:
                os.remove(lock_file)
            except:
                wait_exit('已经有一个 %s 实例正在运行中。', name)
        else:
            import atexit
            atexit.register(unlock)
            break

looptype = None

def get_looptype():
    global looptype
    if allown_gevent_patch and looptype is None:
        import gevent
        loopobj = gevent.get_hub().loop
        try:
            assert isinstance(loopobj, gevent.libuv.loop.loop), ''
            looptype = 'libuv-cffi-' + gevent.libuv.loop.get_version().split('-')[-1]
            return looptype
        except:
            pass
        try:
            assert isinstance(loopobj, gevent.libev.corecext.loop), ''
            looptype = 'libev-cext-' + gevent.libev.corecext.get_version().split('-')[-1]
            return looptype
        except:
            pass
        try:
            assert isinstance(loopobj, gevent.libev.corecffi.loop), ''
            looptype = 'libev-cffi-' + gevent.libev.corecffi.get_version().split('-')[-1]
            return looptype
        except:
            pass
    if looptype is None:
        looptype = 'none'
    return looptype

@clean_after_invoked
def init():
    global allown_gevent_patch

    patch_stdout()

    argv = set(sys.argv[1:])
    allown_gevent_patch = 'nogevent' not in argv
    if allown_gevent_patch:
        #设置优先使用的事件循环类型，优先应用命令行参数
        #用法: python start.py looptype
        # http://www.gevent.org/loop_impls.html
        if 'libuv' in argv or 'libuv-cffi' in argv:
            looptype = 'libuv-cffi'
        elif 'libev-cffi' in argv:
            looptype = 'libev-cffi'
        elif 'libev' in argv or 'libev-cext' in argv:
            looptype = 'libev-cext'
        else:
            gloop_conf = os.path.join(config_dir, 'gloop.conf')
            gloop = cconfig('gloop', conf=gloop_conf)
            gloop.add(['libuv-cffi', 'libev-cext', 'libev-cffi', 'nogevent'])
            gloop.load()
            allown_gevent_patch = not gloop.check('nogevent')
            if allown_gevent_patch:
                if gloop.check('libuv-cffi'):
                    looptype = 'libuv-cffi'
                elif gloop.check('libev-cffi'):
                    looptype = 'libev-cffi'
                elif gloop.check('libev-cext'):
                    looptype = 'libev-cext'
                else:
                    looptype = None
            gloop.close()

    if allown_gevent_patch:
        try:
            import gevent
        except ImportError:
            wait_exit('无法找到 gevent 或者与 Python 版本不匹配，'
                      '请安装 gevent-1.3.0 以上版本，'
                      '或将相应 .egg 放到 %r 文件夹！\n'
                      '或者使用 nogevent 参数重新启动。', packages, exc_info=True)
        if looptype:
            try:
                gevent._config.Loop.default.insert(0, looptype)
            except:
                pass
        try:
            import gevent.monkey
            gevent.monkey.patch_all(os=False, ssl=False, subprocess=False, signal=False)
        except TypeError:
            gevent.monkey.patch_all(os=False)
        if get_looptype().startswith('libuv') and sys.platform.startswith('win'):
            patch_gevent_socket()

    replace_logging()
    patch_time()
    patch_builtins()
    patch_configparser()

    import logging

    if allown_gevent_patch and gevent.__version__ < '1.3.0':
        logging.warning('警告：请更新 gevent 至 1.3.0 以上版本！')

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
