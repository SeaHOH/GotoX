# coding:utf-8

import os
import sys
from local.common.path import py_dir, packages

def wait_exit(*args, **kwargs):
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

try:
    import gevent
    import gevent.monkey
    gevent.monkey.patch_all(os=False, signal=False, subprocess=False, Event=True)
except ImportError:
    wait_exit('无法找到 gevent 或者与 Python 版本不匹配，请安装 gevent-1.0.0 '
              '以上版本，或将相应 .egg 放到 %r 文件夹！', packages, exc_info=True)
except TypeError:
    gevent.monkey.patch_all(os=False)
    from local import clogging as logging
    logging.warning('警告：请更新 gevent 至 1.0.0 以上版本！')

from local import clogging as logging

logging.replace_logging()
logging.addLevelName(15, 'TEST', logging.COLORS.GREEN)

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


import builtins
from configparser import (
    _UNSET, NoSectionError, NoOptionError, RawConfigParser, ConfigParser)

#去掉 lower 以支持选项名称大小写共存
RawConfigParser.optionxform = lambda s, opt: opt

#支持指定 getint、getfloat、getboolean 非法值的 fallback
def _get_conv(self, section, option, conv, *, raw=False, vars=None,
              fallback=_UNSET, **kwargs):
    try:
        return self._get(section, conv, option, raw=raw, vars=vars, **kwargs)
    except (NoSectionError, NoOptionError, ValueError):
        if fallback is _UNSET:
            raise
        if isinstance(conv, type):
            return conv(fallback)
        else:
            return bool(fallback)

RawConfigParser._get_conv = _get_conv

#默认编码
_read = ConfigParser.read
ConfigParser.read = lambda s, f, encoding='utf8': _read(s, f, encoding)

#重写了类方法 __getattr__ 时，修正 hasattr
NOATTR = object()
builtins.gethasattr = lambda o, a: getattr(o, a, NOATTR) != NOATTR

class classlist(list): pass
builtins.classlist = classlist
