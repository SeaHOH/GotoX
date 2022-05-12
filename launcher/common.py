# coding: utf-8

import os
import sys
import ssl
import time
import socket
from urllib.request import urlopen, Request

def get_dirname(path):
    return os.path.dirname(os.path.realpath(path))

file_dir = get_dirname(__file__)
root_dir = os.path.dirname(file_dir)
py_dir = os.path.join(root_dir, 'python')
icon_gotox = os.path.join(root_dir, 'gotox.ico')
config_dir = os.path.join(root_dir, 'config')
direct_ipdb = os.path.join(root_dir, 'data', 'directip.db')
direct_domains = os.path.join(root_dir, 'data', 'directdomains.txt')
config_filename = os.path.join(config_dir, 'Config.ini')
config_user_filename = os.path.join(config_dir, 'Config.user.ini')
config_auto_filename = os.path.join(config_dir, 'ActionFilter.ini')
# GotoX CA
ca1 = os.path.join(root_dir, 'cert', 'CA.crt')
# APNIC 和 GitHub 使用的 CA
ca2 = os.path.join(root_dir, 'cert', 'cacert-ds.pem')
gcontext = None
logging = None
logger = None


if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from local.compat import single_instance, replace_logging, patch_configparser
from local.common.cconfig import cconfig
from local.common.decorator import propertyb

def load_config():
    patch_configparser()
    import re
    from configparser import ConfigParser

    _LOGLv = {
        0 : logging.WARNING,
        1 : logging.INFO,
        2 : logging.TEST,
        3 : logging.DEBUG
        }

    CONFIG = ConfigParser(dict_type=dict, inline_comment_prefixes=('#', ';'))
    CONFIG._optcre = re.compile(r'(?P<option>[^=\s]+)\s*(?P<vi>=?)\s*(?P<value>.*)')
    CONFIG.read([config_filename, config_user_filename])
    LISTEN_IP = CONFIG.get('listen', 'ip')
    if LISTEN_IP == '0.0.0.0':
        LISTEN_IP = '127.0.0.1'
    elif LISTEN_IP == '::':
        LISTEN_IP = '::1'
    elif LISTEN_IP == '':
        LINK_PROFILE = CONFIG.get('link', 'profile')
        if LINK_PROFILE not in ('ipv4', 'ipv6', 'ipv46'):
            LINK_PROFILE = 'ipv4'
        LISTEN_IP = '127.0.0.1' if '4' in LINK_PROFILE else '::1'
    LISTEN_AUTOPORT = CONFIG.getint('listen', 'autoport', fallback=8087)
    LISTEN_ACTPORT = CONFIG.getint('listen', 'actport', fallback=8086)
    LISTEN_ACTTYPE = CONFIG.get('listen', 'act', fallback='cfw').upper()
    LISTEN_AUTO = '%s:%d' % (LISTEN_IP, LISTEN_AUTOPORT)
    LISTEN_ACT = '%s:%d' % (LISTEN_IP, LISTEN_ACTPORT)
    LOG_PRINT = CONFIG.getboolean('log', 'print', fallback=True)
    LOG_LEVEL = _LOGLv[min(CONFIG.getint('log', 'level', fallback=1), 3)]
    log_config = {'level': LOG_LEVEL}
    if not LOG_PRINT:
        log_config['stream'] = logging.NULL_STREAM
    logging.basicConfig(**log_config)
    AUTO_PROXY = CONFIG.getint('misc', 'autoproxy')

    return LISTEN_AUTO, LISTEN_ACT, LISTEN_ACTTYPE, AUTO_PROXY

def getlogger(use_print=False):
    global logging, logger
    if logging is None:
        if use_print:
            class logging:
                def info(s, *args):
                    print(s % args)
                warning = debug = info
            logger = logging
        else:
            replace_logging()
            import logging
            logger = logging.getLogger('[launcher]')
    return logger

try:
    startfile = os.startfile
except AttributeError:
    def startfile(filename):
        from subprocess import call
        if sys.platform.startswith('darwin'):
            operation = 'open'
        elif os.name == 'posix':
            operation = 'xdg-open'
        call((operation, filename))

class DataSource:
    datefmt = None

    def __init__(self, manager, name, url, parser, fullname=None):
        if isinstance(manager, DataSourceManager):
            self.parent = None
            self._generations = 1
            self._sign = 1 << manager.sign_bit
            self._cconfig = cconfig(name.lower(), conf=manager.ext_conf)
        elif isinstance(manager, self.__class__):
            parent = manager
            manager = parent.manager
            generations = parent._generations + 1
            if generations > manager.max_generations:
                raise ValueError(
                        'DataSource.__init__ "generations=%d" 超过最大值：%d'
                        % (generations, manager.max_generations))
            self._generations = generations
            self._sign = 0
            self._cconfig = cconfig(name.lower(), parent)
            parent._children[name.lower()] = self
            parser = parser or parent.parser
        else:
            raise TypeError('DataSource.__init__ "manager" 类型错误：%s'
                            % manager.__class__)
        self.manager = manager
        self.url = url
        self.parser = parser
        self.fullname = fullname or name
        self.req = None
        self.update = None
        self.itemlist = []

    def __getattr__(self, name):
        return getattr(self._cconfig, name)

    def add_child(self, name, url, parser=None, fullname=None):
        return self.__class__(self, name, url, parser, fullname)

    @property
    def sign(self):
        return self._sign

    @propertyb
    def update(self):
        return '%s-%s' % (self.name, self._update)

    @update.boolgetter
    def update(self):
        return self._update

    @update.setter
    def update(self, value):
        self._update = value

    def clear_data(self):
        self.itemlist.clear()
        for child_ds in self.get_children():
            child_ds.clear_data()

    def __get_other_sign(self, other):
        if isinstance(other, self.__class__):
            other = other.sign
        return other

    def __and__(self, other):
        return self.__get_other_sign(other) & self.sign

    def __xor__(self, other):
        return self.__get_other_sign(other) ^ self.sign

    def __or__(self, other):
        return self.__get_other_sign(other) | self.sign

    __rand__ = __and__
    __rxor__ = __xor__
    __ror__ = __or__

    def __raise_noit_err(self, other):
        raise NotImplementedError

    __iand__ = __ixor__ = __ior__ = __raise_noit_err

class DataSourceManager:
    ext_conf = os.path.join(config_dir, 'dsext.conf')
    max_generations = 2

    def __init__(self):
        self._sign_all = 0
        self._sign_bit = 0
        self._valid = {}
        self._conf = cconfig('ds', conf=self.ext_conf)

    def add(self, name, url, parser, fullname=None):
        self._conf.add(name)
        ds = DataSource(self, name, url, parser, fullname)
        self._valid['--' + name.lower()] = ds
        self._sign_all |= ds.sign
        self._sign_bit += 1
        return ds

    def get(self, name):
        return self._valid.get('--' + name.lower())

    @property
    def sign_bit(self):
        return self._sign_bit

    @property
    def sign_all(self):
        return self._sign_all

    def check(self, name):
        return self._conf.check(name)

    def set(self, name, save=False):
        self._conf.set(name, 1, save)

    def switch(self, name, save=False):
        self._conf.switch(name, save)

    def load(self, filename=None):
        if filename:
            self.ext_conf = filename
        self._conf.load(filename=filename)
        for ds in self.sources():
            ds.load(filename=filename)

    def save(self, filename=None):
        if filename:
            self.ext_conf = filename
        self._conf.save(filename=filename)
        for ds in self.sources():
            ds.save(filename=filename)

    def get_source(self, *args):
        kwargs = parse_cmds(*args)
        data_source = 0
        if '--all' in kwargs:
            data_source = self._sign_all
        for par in self._valid:
            if par in kwargs:
                data_source |= self._valid[par].sign
                for name in kwargs[par]:
                    self._valid[par].set(name)
        return data_source

    def clear_source_data(self):
        for ds in self.sources():
            ds.clear_data()

    def sources(self):
        return self._valid.values()

    @property
    def data_source(self):
        data_source = 0
        for ds in self.sources():
            if self._conf.check(ds.name):
                data_source |= ds
        return data_source

def parse_cmds(*args):
    args = list(args)
    kwargs = {}
    while args and not args[0].startswith('-'):
        del args[0]
    cmd = ''
    for arg in args:
        if arg.startswith('-'):
            cmd = arg
            kwargs[cmd] = []
        else:
            kwargs[cmd].append(arg)
    return kwargs

def create_context(cafiles=[], capaths=[], cadatas=[]):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= getattr(ssl._ssl, 'OP_NO_COMPRESSION', 0)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.set_ciphers(ssl._RESTRICTED_SERVER_CIPHERS)
    for cafile in cafiles:
        if os.path.isfile(cafile):
            context.load_verify_locations(cafile=cafile)
    for capath in capaths:
        if os.path.isdir(capath):
            context.load_verify_locations(capath=capath)
    for cadata in cadatas:
        if cadata:
            context.load_verify_locations(cadata=cadata)
    return context

def download(req, context=None):
    #显式加载 CA，确保正常使用
    global gcontext
    if context is None:
        if gcontext is None:
            gcontext = create_context(cafiles=[ca1, ca2])
        context = gcontext
    retry_delay = 10
    max_retries = 4
    retry_times = 0
    timeout = 8
    l = 0
    while True:
        err = None
        try:
            fd = urlopen(req, timeout=timeout, context=context)
        except Exception as e:
            err = e
        else:
            l = int(fd.headers.get('Content-Length', 0))
        if l:
            break
        retry_times += 1
        if retry_times > max_retries:
            logger.warning('请求网址 %r 时，重试 %d 次后仍然失败。'
                            % (req.full_url, max_retries))
            logger.warning('请忽略下面这个错误跟踪，并检查是否需要'
                            '更改自动代理规则（ActionFilter.ini）。')
            raise err or OSError('连接失败', 0)
        logger.debug('获取更新数据失败，%d 秒后重试' % retry_delay)
        time.sleep(retry_delay)
    return fd, l

def download_as_list(ds):
    #支持续传
    logger.info('开始下载 %s 列表' % ds.fullname)
    if ds.req is None:
        ds.req = Request(ds.url)
    ds.req.headers['Range'] = 'bytes=0-'
    if ds.datefmt is None:
        ds.update = None
    else:
        ds.update = time.strftime(ds.datefmt, time.localtime(time.time()))
    ds.itemlist.clear()
    read = 0
    fd, l = download(ds.req)
    while True:
        _read = ds.parser(fd, ds)
        if _read is None:
            read = l
        else:
            read += _read
        fd.close()
        if read >= l:
            break
        #下载失败续传
        #往回跳过可能的缺损条目
        read = max(read - 100, 0)
        ds.req.headers['Range'] = 'bytes=%d-' % read
        logger.debug('%s 列表下载中断，续传：%d/%d' % (ds.fullname, read, l))
        fd, _ = download(ds.req)
    logger.info(ds.fullname + ' 列表下载完毕')
    return ds.itemlist

def set_proxy(proxy_addr):
    try:
        ip, port = proxy_addr.split(':')
        socket.create_connection((ip, int(port)), timeout=1).close()
        os.environ['HTTPS_PROXY'] = os.environ['HTTP_PROXY'] = proxy_addr
        logger.info('\n代理地址 %r 已设置成功。' % proxy_addr)
        return True
    except:
        os.environ.pop('HTTP_PROXY', None)
        os.environ.pop('HTTPS_PROXY', None)

def parse_set_proxy(data_source):
    use_proxy = None
    if '-p' in sys.argv:
        try:
            proxy_addr = sys.argv[sys.argv.index('-p') + 1]
        except IndexError:
            print('\n代理地址读取失败，退出脚本...')
            sys.exit(-1)
        if not set_proxy(proxy_addr):
            print('\n代理地址 %r 设置失败，退出脚本...' % proxy_addr)
            sys.exit(-1)
        if data_source == 0:
            print('进入交互模式\n')
            return True
    elif '-d' in sys.argv:
        if data_source == 0:
            print('进入交互模式\n')
            return False
    else:
        use_proxy = input('进入交互模式\n\n是否设置代理（Y/N）：')
        use_proxy = use_proxy.upper() == 'Y'

    if use_proxy:
        print('\n开始设置代理，仅支持 HTTP 代理，格式："主机名(IP 或域名):端口"')
    while use_proxy:
        proxy_addr = input('\n请输入代理地址，'
                     '留空使用 "127.0.0.1:8087"：\n') or '127.0.0.1:8087'
        if set_proxy(proxy_addr):
            break
        else:
            use_proxy = input('\n当前代理 %r 无法链接，是否继续设置代理（Y/N）：' % proxy_addr)
            use_proxy = use_proxy.upper() == 'Y'
    if use_proxy is False:
        print('\n跳过代理设置')
    return use_proxy

Tips1 = '''
 ***********************************************
 *   请选择存放目录：                          *
 *                      数据目录 ------ 按 1   *
 *                      当前目录 ------ 按 2   *
 *                      退出 ---------- 按 0   *
 ***********************************************
'''

def select_path(*path):
    n = input(Tips1)
    try:
        n = int(n)
    except:
        print('输入错误！')
        return
    if n == 0:
        sys.exit(0)
    elif n == 1:
        return path[0]
    elif n == 2:
        return path[1]
    else:
        print('输入错误！')
