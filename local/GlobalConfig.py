# coding:utf-8
'''Global Config Module'''


import os
import sys
import re
import logging
from configparser import ConfigParser
from .common.decompress import _brotli
from .common.path import get_realpath, config_dir, data_dir, log_dir
from .common.net import isip, isipv6
from .common.util import wait_exit
#from .common.proxy import get_system_proxy, parse_proxy

_LOGLv = {
    0 : logging.WARNING,
    1 : logging.INFO,
    2 : logging.TEST,
    3 : logging.DEBUG
    }

_SSLv = {
    'SSLv2'   : 1,
    'SSLv3'   : 2,
    'SSLv23'  : 3,
    'TLS'     : 3,
    'TLSv1'   : 4,
    'TLSv1.1' : 5,
    'TLSv1.2' : 6
    }

def _servers_2_addresses(servers, default_port):
    for server in servers:
        if server[:1] == '[':
            addr, delim, port = server[1:].partition(']:')
            if not delim:
                addr = addr[:-1]
        elif '.' in server:
            addr, _, port = server.partition(':')
        else:
            if isipv6(server):
                yield server, default_port
            continue
        if isip(addr):
            try:
                port = int(port)
            except:
                port = default_port
            yield addr, port

def servers_2_addresses(servers, default_port):
    default_port = int(default_port)
    return tuple(_servers_2_addresses(servers, default_port))

#load config from proxy.ini
#ENV_CONFIG_PREFIX = 'GOTOX_'
CONFIG = ConfigParser(dict_type=dict, inline_comment_prefixes=('#', ';'))
CONFIG._optcre = re.compile(r'(?P<option>[^=\s]+)\s*(?P<vi>=?)\s*(?P<value>.*)')

class GC:

    GEVENT_LOOP = None

    CONFIG_FILENAME = os.path.join(config_dir, 'Config.ini')
    CONFIG_USER_FILENAME = os.path.join(config_dir, 'Config.user.ini')
    CONFIG_IPDB = os.path.join(data_dir, 'ip.use')
    CONFIG.read([CONFIG_FILENAME, CONFIG_USER_FILENAME, CONFIG_IPDB])

    #load config from environment
    #for key, value in os.environ.items():
    #    m = re.match(r'^%s([A-Z]+)_([A-Z\_\-]+)$' % ENV_CONFIG_PREFIX, key)
    #    if m:
    #        CONFIG.set(m.group(1).lower(), m.group(2).lower(), value)

    MISC_CHECKPROCESS = CONFIG.getboolean('misc', 'checkprocess', fallback=True)
    MISC_CHECKSYSCA = CONFIG.getboolean('misc', 'checksysca', fallback=True)
    MISC_GEVENTPATCH = CONFIG.getboolean('misc', 'geventpatch', fallback=False)
    MISC_REVERTGEVENTPATCH = CONFIG.getboolean('misc', 'revertgeventpatch', fallback=False)

    LISTEN_IP = CONFIG.get('listen', 'ip')
    LISTEN_IPHOST = CONFIG.get('listen', 'iphost')
    if not LISTEN_IPHOST:
        if LISTEN_IP in ('0.0.0.0', ''):
            LISTEN_IPHOST = '127.0.0.1'
        elif LISTEN_IP == '::':
            LISTEN_IPHOST = '::1'
        else:
            LISTEN_IPHOST = LISTEN_IP
    LISTEN_AUTOPORT = CONFIG.getint('listen', 'autoport', fallback=8087)
    LISTEN_ACTPORT = CONFIG.getint('listen', 'actport', fallback=8086)
    LISTEN_ACT = CONFIG.get('listen', 'act', fallback='cfw').upper()
    LISTEN_ACTNAME = 'do_' + LISTEN_ACT
    LISTEN_AUTH = min(CONFIG.getint('listen', 'auth', fallback=0), 2)
    LISTEN_AUTHWHITELIST = CONFIG.gettuple('listen', 'authwhitelist')
    LISTEN_AUTHUSER = CONFIG.gettuple('listen', 'authuser', fallback=':')

    LOG_VISIBLE = CONFIG.getboolean('log', 'visible', fallback=True)
    LOG_PRINT = CONFIG.getboolean('log', 'print', fallback=True)
    LOG_LEVEL = _LOGLv[min(CONFIG.getint('log', 'level', fallback=1), 3)]
    LOG_SAVE = CONFIG.getboolean('log', 'save', fallback=False)
    LOG_FILE = CONFIG.get('log', 'file', fallback='log.txt')
    LOG_FILE = get_realpath(LOG_FILE, log_dir)
    if os.path.isdir(LOG_FILE):
        LOG_FILE = os.path.join(LOG_FILE, 'log.txt')
    LOG_FILESIZE = CONFIG.getint('log', 'filesize', fallback=1024) * 1024
    LOG_ROTATION = max(CONFIG.getint('log', 'rotation', fallback=1), 1)

    LINK_PROFILE = CONFIG.get('link', 'profile')
    if LINK_PROFILE not in ('ipv4', 'ipv6', 'ipv46'):
        LINK_PROFILE = 'ipv46'
    LINK_FASTV6CHECK = CONFIG.getboolean('link', 'fastv6check', fallback=True)
    LINK_WINDOW = max(min(CONFIG.getint('link', 'window', fallback=3), 12), 2)
    LINK_MAXPERIP = max(min(CONFIG.getint('link', 'maxperip', fallback=6), 32), 3)
    LINK_RECVBUFFER = max(min(CONFIG.getint('link', 'recvbuffer', fallback=1024 * 128), 1024 * 1024 *4), 1024 * 32)
    LINK_VERIFYGPK = CONFIG.getboolean('link', 'verifygpk', fallback=True)
    LINK_LOCALSSLTXT = CONFIG.get('link', 'localssl', fallback='TLS')
    LINK_REMOTESSLTXT = CONFIG.get('link', 'remotessl', fallback='TLSv1.2')
    LINK_LOCALSSL = _SSLv[LINK_LOCALSSLTXT]
    LINK_REMOTESSL = max(_SSLv[LINK_REMOTESSLTXT], _SSLv['TLS'])
    LINK_REQUESTCOMPRESS = _brotli and CONFIG.getboolean('link', 'requestcompress', fallback=False)
    LINK_TIMEOUT = max(CONFIG.getint('link', 'timeout', fallback=5), 3)
    LINK_FWDTIMEOUT = max(CONFIG.getint('link', 'fwdtimeout', fallback=8), 3)
    LINK_KEEPTIME = CONFIG.getint('link', 'keeptime', fallback=180)
    LINK_FWDKEEPTIME = CONFIG.getint('link', 'fwdkeeptime', fallback=120)
    LINK_TEMPTIME = CONFIG.getint('link', 'temptime', fallback=900)
    LINK_TEMPTIME_S = LINK_TEMPTIME % 60
    if LINK_TEMPTIME_S:
        LINK_TEMPTIME_S = ' %d 分 %d 秒' % (LINK_TEMPTIME // 60, LINK_TEMPTIME_S)
    else:
        LINK_TEMPTIME_S = ' %d 分钟' % (LINK_TEMPTIME // 60)
    LINK_TEMPWHITELIST = CONFIG.gettuple('link', 'tempwhitelist') + ('.cloudflare.com',)

    CFW_WORKER = CONFIG.get('cfw', 'worker').strip()
    if CFW_WORKER.find('.') < 1:
        CFW_WORKER = None
    CFW_PASSWORD = CONFIG.get('cfw', 'password').strip()
    CFW_IPLIST = CONFIG.getlist('cfw', 'iplist') or None
    CFW_DECODEEMAIL = CONFIG.getboolean('cfw', 'decodeemail', fallback=False)
    CFW_TIMEOUT = max(CONFIG.getint('cfw', 'timeout', fallback=10), 3)
    CFW_KEEPALIVE = CONFIG.getboolean('cfw', 'keepalive', fallback=True)
    CFW_KEEPTIME = CONFIG.getint('cfw', 'keeptime', fallback=180)
    CFW_FETCHMAX = CONFIG.getint('cfw', 'fetchmax', fallback=2)

    GAE_APPIDS = re.findall(r'[\w\-\.]+', CONFIG.get('gae', 'appid').replace('.appspot.com', ''))
    GAE_DEBUG = CONFIG.getint('gae', 'debug', fallback=0)
    GAE_PASSWORD = CONFIG.get('gae', 'password').strip()
    GAE_PATH = CONFIG.get('gae', 'path', fallback='/_gh/')
    GAE_MAXPERIP = min(CONFIG.getint('gae', 'maxperip', fallback=2), 8)
    GAE_TIMEOUT = max(CONFIG.getint('gae', 'timeout', fallback=10), 3)
    GAE_KEEPALIVE = CONFIG.getboolean('gae', 'keepalive', fallback=True)
    GAE_KEEPTIME = CONFIG.getint('gae', 'keeptime', fallback=30)
    GAE_MAXREQUESTS = min(CONFIG.getint('gae', 'maxrequsts', fallback=2), 5)
    GAE_SSLVERIFY = CONFIG.getboolean('gae', 'sslverify', fallback=True)
    GAE_FETCHMAX = CONFIG.getint('gae', 'fetchmax', fallback=2)
    #在服务端，这个数值代表的范围大小会增加 1
    GAE_MAXSIZE = min(CONFIG.getint('gae', 'maxsize', fallback=1024 * 1024 * 4), 1024 * 1024 * 32 - 1)
    GAE_IPLIST = CONFIG.get('gae', 'iplist')
    GAE_IPLIST2P = CONFIG.get('gae', 'iplist2p', fallback='google_2p')
    GAE_SERVERNAME = CONFIG.gettuple('gae', 'servername') or None
    GAE_ENABLEPROXY = CONFIG.getboolean('gae', 'enableproxy', fallback=False)
    GAE_PROXYLIST = CONFIG.getlist('gae', 'proxylist') or None
    if not GAE_PROXYLIST:
        GAE_ENABLEPROXY = False
    if GAE_ENABLEPROXY:
        GAE_IPLIST = GAE_IPLIST2P
        GAE_TIMEOUT = max(GAE_TIMEOUT, 10)
    else:
        CONFIG.remove_option('iplist', 'google_2p')

    try:
        d = CONFIG._sections['iplist']
    except KeyError:
        IPLIST_MAP = {}
    else:
        IPLIST_MAP = {k: [x.strip() for x in v.split('|') if x.strip()] for k, v in d.items()}

    if 'google_gae' not in IPLIST_MAP:
        IPLIST_MAP['google_gae'] = []
    if 'google_gws' not in IPLIST_MAP:
        IPLIST_MAP['google_gws'] = []
    if GAE_IPLIST:
        GAE_TESTGWSIPLIST = False
        if GAE_IPLIST in IPLIST_MAP and IPLIST_MAP[GAE_IPLIST]:
            IPLIST_MAP['google_gae'] = IPLIST_MAP[GAE_IPLIST].copy()
            IPLIST_MAP['google_gws'] = IPLIST_MAP[GAE_IPLIST].copy()
        else:
            GAE_TESTGWSIPLIST = True
            logging.warning('没有找到列表 [%s]，使用默认查找 IP 模式。', GAE_IPLIST)
    else:
        GAE_TESTGWSIPLIST = True
    if GAE_ENABLEPROXY:
        GAE_TESTGWSIPLIST = False

    FILTER_ACTION = max(min(CONFIG.getint('filter', 'action', fallback=3), 4), 1)
    FILTER_SSLACTION = max(min(CONFIG.getint('filter', 'sslaction', fallback=2), 4), 1)

    PICKER_SERVERNAME = CONFIG.get('picker', 'servername', fallback='fonts.googleapis.com')
    PICKER_COMDOMAIN = CONFIG.get('picker', 'comdomain', fallback='*.googleapis.com')
    PICKER_STRICT = CONFIG.getboolean('picker', 'strict', fallback=False)
    PICKER_BLOCKTIME = CONFIG.getfloat('picker', 'blocktime', fallback=0.3)
    PICKER_TIMESBLOCK = CONFIG.getint('picker', 'timesblock', fallback=3)
    PICKER_TIMESDEL = CONFIG.getint('picker', 'timesdel', fallback=10)
    PICKER_DELASSOETED = CONFIG.getboolean('picker', 'delassoeted', fallback=False)
    PICKER_STATDAYS = max(min(CONFIG.getint('picker', 'statdays', fallback=4), 5), 2)
    PICKER_SORTSTAT = CONFIG.getboolean('picker', 'sortstat', fallback=False)
    PICKER_BLOCK = CONFIG.gettuple('picker', 'block')
    PICKER_GAE_ENABLE = LISTEN_ACT == 'GAE' and CONFIG.getboolean('picker/gae', 'enable', fallback=True)
    PICKER_GAE_MINRECHECKTIME = CONFIG.getint('picker/gae', 'minrechecktime', fallback=40)
    PICKER_GAE_MINCNT = CONFIG.getint('picker/gae', 'mincnt', fallback=5)
    PICKER_GAE_MAXTIMEOUT = CONFIG.getint('picker/gae', 'maxtimeout', fallback=3000)
    PICKER_GAE_MAXTHREADS = CONFIG.getint('picker/gae', 'maxthreads', fallback=1)
    PICKER_GWS_ENABLE = CONFIG.getboolean('picker/gws', 'enable', fallback=True)
    PICKER_GWS_MINRECHECKTIME = CONFIG.getint('picker/gws', 'minrechecktime', fallback=30)
    PICKER_GWS_MINCNT = CONFIG.getint('picker/gws', 'mincnt', fallback=8)
    PICKER_GWS_MAXTIMEOUT = CONFIG.getint('picker/gws', 'maxtimeout', fallback=1000)
    PICKER_GWS_MAXTHREADS = CONFIG.getint('picker/gws', 'maxthreads', fallback=3)

    if not PICKER_SERVERNAME or not PICKER_COMDOMAIN:
        logging.warning('没有找到 [picker/servername|comdomain]，将使用默认值。'
                        '请检查配置文件：%r，参考注释进行填写。', CONFIG_FILENAME)
        PICKER_SERVERNAME = b'fonts.googleapis.com'
        PICKER_COMDOMAIN = '*.googleapis.com'

    #PROXY_ENABLE = CONFIG.getboolean('proxy', 'enable', fallback=False)
    PROXY_ENABLE = False
    PROXY_AUTODETECT = CONFIG.getboolean('proxy', 'autodetect', fallback=False)
    PROXY_HOST = CONFIG.get('proxy', 'host')
    PROXY_PORT = CONFIG.getint('proxy', 'port')
    PROXY_USERNAME = CONFIG.get('proxy', 'username')
    PROXY_PASSWROD = CONFIG.get('proxy', 'password')

    #read proxy from system
    #if not PROXY_ENABLE and PROXY_AUTODETECT:
    #    system_proxy = get_system_proxy()
    #    if system_proxy and LISTEN_IP not in system_proxy:
    #        _, username, password, address = parse_proxy(system_proxy)
    #        proxyhost, _, proxyport = address.rpartition(':')
    #        PROXY_ENABLE = 1
    #        PROXY_USERNAME = username
    #        PROXY_PASSWROD = password
    #        PROXY_HOST = proxyhost
    #        PROXY_PORT = int(proxyport)
    if PROXY_ENABLE and PROXY_HOST and PROXY_PORT:
        proxy = 'https://%s:%s@%s:%d' % (PROXY_USERNAME or '', PROXY_PASSWROD or '', PROXY_HOST, PROXY_PORT)
    else:
        proxy = ''

    AUTORANGE_FAST_ENDSWITH = CONFIG.gettuple('autorange/fast', 'endswith')
    AUTORANGE_FAST_THREADS = CONFIG.getint('autorange/fast', 'threads', fallback=5)
    AUTORANGE_FAST_FIRSTSIZE = CONFIG.getint('autorange/fast', 'firstsize', fallback=1024 * 32)
    AUTORANGE_FAST_MAXSIZE = CONFIG.getint('autorange/fast', 'maxsize', fallback=1024 * 256)
    AUTORANGE_FAST_LOWSPEED = CONFIG.getint('autorange/fast', 'lowspeed', fallback=1024)

    AUTORANGE_BIG_ONSIZE = CONFIG.getint('autorange/big', 'onsize', fallback=1024 * 1024 * 32)
    AUTORANGE_BIG_THREADS = CONFIG.getint('autorange/big', 'threads', fallback=2)
    AUTORANGE_BIG_MAXSIZE = CONFIG.getint('autorange/big', 'maxsize', fallback=1024 * 1024 * 4)
    AUTORANGE_BIG_SLEEPTIME = CONFIG.getint('autorange/big', 'sleeptime', fallback=5)
    AUTORANGE_BIG_LOWSPEED = CONFIG.getint('autorange/big', 'lowspeed', fallback=0)

    DNS_SERVERS = servers_2_addresses(CONFIG.gettuple('dns', 'servers', fallback='8.8.8.8'), 53)
    DNS_LOCAL_SERVERS = servers_2_addresses(CONFIG.gettuple('dns', 'localservers', fallback='114.114.114.114'), 53)
    DNS_LOCAL_HOST = CONFIG.getboolean('dns', 'localhost', fallback=True)
    DNS_LOCAL_WHITELIST = CONFIG.gettuple('dns', 'localwhitelist')
    DNS_LOCAL_BLACKLIST = CONFIG.gettuple('dns', 'localblacklist')
    DNS_OVER_HTTPS = CONFIG.getboolean('dns', 'overhttps', fallback=True)
    DNS_OVER_HTTPS_SERVERS = CONFIG.gettuple('dns', 'overhttpsservers', fallback='cloudflare-dns.com')
    DNS_IP_API = CONFIG.gettuple('dns', 'ipapi')
    DNS_PRIORITY = CONFIG.getlist('dns', 'priority', fallback='overhttps|remote|system')
    DNS_BLACKLIST = set(CONFIG.getlist('dns', 'blacklist'))

    DNS_DEF_PRIORITY = ['system', 'remote', 'overhttps']
    for dnstype in DNS_PRIORITY.copy():
        if dnstype in DNS_DEF_PRIORITY:
            DNS_DEF_PRIORITY.remove(dnstype)
        else:
            DNS_PRIORITY.remove(dnstype)
    DNS_PRIORITY.extend(DNS_DEF_PRIORITY)
    if not DNS_OVER_HTTPS:
        DNS_PRIORITY.remove('overhttps')

    DNS_CACHE_ENTRIES = CONFIG.getint('dns/cache', 'entries', fallback=1024)
    DNS_CACHE_EXPIRATION = CONFIG.getint('dns/cache', 'expiration', fallback=7200)

del CONFIG
