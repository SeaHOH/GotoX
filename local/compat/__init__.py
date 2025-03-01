# coding:utf-8

import os
import sys
from ..common.cconfig import cconfig
from ..common.path import py_dir, config_dir, data_dir, packages

from .monkey_patch import *

def wait_exit(*args, **kwargs):
    replace_logging()
    patch_time()
    from ..common.util import wait_exit
    wait_exit(*args, **kwargs)

PY3 = sys.version_info.major == 3
if not PY3:
    import time
    print(u'请使用 Python 3 系列版本运行本程序!\n30 秒后自动退出……')
    time.sleep(30)
    os._exit(-1)

#这段代码负责添加依赖库路径，不要改变位置
# Windows 使用发布版本自带的 Python 不用重复添加
local_py = os.path.dirname(sys.executable) != py_dir
if local_py:
    import glob
    #放在最后，优先导入当前运行 Python 已安装模块
    sys.path.append(packages)
    sys.path.extend(glob.glob(os.path.join(packages, 'helpers-*.egg')))
    sys.path.extend(glob.glob(os.path.join(packages, '*-none-any.egg')))

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
            assert isinstance(loopobj, gevent.libuv.loop.loop)
            looptype = 'libuv-cffi-' + gevent.libuv.loop.get_version().split('-')[-1]
            return looptype
        except:
            pass
        try:
            assert isinstance(loopobj, gevent.libev.corecext.loop)
            looptype = 'libev-cext-' + gevent.libev.corecext.get_version().split('-')[-1]
            return looptype
        except:
            pass
        try:
            assert isinstance(loopobj, gevent.libev.corecffi.loop)
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
            wintray_conf = os.path.join(config_dir, 'win_tray.conf')
            wintray = cconfig('wintray', conf=wintray_conf)
            gloop = wintray.add_child('gloop')
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
            wintray.close()

    if allown_gevent_patch:
        try:
            import gevent
        except ImportError:
            wait_exit('无法找到 gevent 或者与 Python 版本不匹配，'
                      '请安装 gevent-21.1.0 或以上版本' f'''{local_py and '' or
                     f'，或将相应 .egg 放到 "{packages}" 文件夹'}!\n'''
                      '或者使用 nogevent 参数重新启动。', packages, exc_info=True)
        # libuv-cffi 的 bug 问题越来越大，暂时调整默认顺序不使用它
        if looptype is None:
            looptype = 'libev-cext'
        if looptype:
            try:
                gevent._config.Loop.default.remove(looptype)
                gevent._config.Loop.default.insert(0, looptype)
            except:
                pass
        import gevent.monkey
        gevent.monkey.patch_all(os=False, ssl=False, subprocess=False, signal=False)
        if get_looptype().startswith('libuv') and sys.platform.startswith('win'):
            patch_gevent_socket()
            patch_select()

    replace_logging()

    import logging

    if allown_gevent_patch and gevent.__version__ < '21.1.0':
        logging.warning('警告：请更新 gevent 至 21.1.0 或以上版本!')

    try:
        import _cffi_backend  # memimport: pyOpenSSL/cryptography 依赖
    except ImportError:
        pass

    try:
        import OpenSSL
    except ImportError:
        wait_exit('无法找到 pyOpenSSL，请安装 pyOpenSSL-21.0.0 或以上版本'
                  f'''{local_py and '' or
                 f'，或将相应 .egg 放到 "{packages}" 文件夹'}!''',
                  exc_info=True)

    import OpenSSL._util
    try:
        OpenSSL._util.lib.SSL_CTX_set_cert_store
    except AttributeError:
        wait_exit('pyOpenSSL 依赖 cryptography 版本不兼容，请安装非 40.0.0 - '
                  '40.0.1 版本的 cryptography' f'''{local_py and '' or
                 f'，或将相应 .egg 放到 "{packages}" 文件夹'}!''')

    try:
        import dnslib
    except ImportError:
        wait_exit('无法找到 dnslib，请安装 dnslib-0.9.12 或以上版本，'
                 f'或将相应 .egg 放到 "{packages}" 文件夹!', exc_info=True)

    try:
        import socks
    except ImportError:
        wait_exit('无法找到 PySocks，请安装 PySocks-1.7.1，'
                 f'或将相应 .egg 放到 "{packages}" 文件夹!', exc_info=True)

    patch_http_client()
    patch_time()
    patch_builtins()
    patch_configparser()
    patch_dnslib()
    patch_socks()

    try:
        from threading import _start_joinable_thread
    except ImportError:
        pass
    else:
        import _thread, threading
        threading._start_new_thread = _thread.start_new_thread
        
