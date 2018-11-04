# coding:utf-8

import os
import sys
from local.path import py_dir, packages

#这段代码负责添加依赖库路径，不要改变位置
# Windows 使用发布版本自带的 Python 不用重复添加
if os.path.dirname(sys.executable) != py_dir:
    import glob
    #放在最后，优先导入当前运行 Python 已安装模块
    sys.path.append(packages)
    sys.path.extend(glob.glob(os.path.join(packages, '*.egg')))

from local import clogging as logging

logging.replace_logging()
logging.addLevelName(15, 'TEST', logging.COLORS.GREEN)

try:
    import gevent
    import gevent.monkey
    gevent.monkey.patch_all(os=False, signal=False, subprocess=False, Event=True)
except ImportError:
    logging.warning('无法找到 gevent 或者与 Python 版本不匹配，请安装 gevent-1.0.0 以上版本，或将相应 .egg 放到 %r 文件夹！\n正在退出……', packages)
    sys.exit(-1)
except TypeError:
    gevent.monkey.patch_all(os=False)
    logging.warning('警告：请更新 gevent 至 1.0.0 以上版本！')

try:
    import OpenSSL
except ImportError:
    logging.exception('无法找到 pyOpenSSL，请安装 pyOpenSSL-16.0.0 以上版本，或将相应 .egg 放到 %r 文件夹！\n正在退出……', packages)
    sys.exit(-1)

try:
    import dnslib
except ImportError:
    logging.error(u'无法找到 dnslib，请安装 dnslib-0.8.3 以上版本，或将相应 .egg 放到 %r 文件夹！', packages)
    sys.exit(-1)

_ver = sys.version_info
PY3 = _ver[0] == 3
#PY35 = PY3 and _ver[1] == 5
if not PY3:
    logging.error('请使用 Python 3 系列版本运行本程序！\n正在退出……')
    sys.exit(-1)

import queue as Queue
import _thread as thread
import http.server as BaseHTTPServer
import http.client as httplib
import urllib.request as urllib2
import urllib.parse as urlparse
import socketserver as SocketServer
from configparser import RawConfigParser, ConfigParser

#去掉 lower 以支持选项名称大小写共存
RawConfigParser.optionxform = lambda s, opt: opt

#默认编码
_read = ConfigParser.read
ConfigParser.read = lambda s, f, encoding='utf8': _read(s, f, encoding)

#重写了类方法 __getattr__ 时，修正 hasattr
hasattr = lambda o, a: getattr(o, a, None) != None
