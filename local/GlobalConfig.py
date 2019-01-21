# coding:utf-8
'''Global Config Module'''


import os
import sys
import re
import logging
from configparser import ConfigParser
from .common.decompress import _brotli
from .common.path import config_dir, data_dir
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

#load config from proxy.ini
ENV_CONFIG_PREFIX = 'GOTOX_'
CONFIG = ConfigParser(inline_comment_prefixes=('#', ';'))
CONFIG._optcre = re.compile(r'(?P<option>[^=\s]+)\s*(?P<vi>=?)\s*(?P<value>.*)')

class GC:

    CONFIG_FILENAME = os.path.join(config_dir, 'Config.ini')
    CONFIG_IPDB = os.path.join(data_dir, 'ip.use')
    CONFIG_USER_FILENAME = re.sub(r'\.ini$', '.user.ini', CONFIG_FILENAME)
    CONFIG.read([CONFIG_FILENAME, CONFIG_USER_FILENAME, CONFIG_IPDB])

    #load config from environment
    #for key, value in os.environ.items():
    #    m = re.match(r'^%s([A-Z]+)_([A-Z\_\-]+)$' % ENV_CONFIG_PREFIX, key)
    #    if m:
    #        CONFIG.set(m.group(1).lower(), m.group(2).lower(), value)

    LISTEN_IP = CONFIG.get('listen', 'ip')
    LISTEN_IPHOST = CONFIG.get('listen', 'iphost')
    if not LISTEN_IPHOST and LISTEN_IP not in ('0.0.0.0', '::'):
        LISTEN_IPHOST = LISTEN_IP
    LISTEN_GAE_PORT = CONFIG.getint('listen', 'gae_port')
    LISTEN_AUTO_PORT = CONFIG.getint('listen', 'auto_port')
    LISTEN_VISIBLE = CONFIG.getboolean('listen', 'visible')
    LISTEN_AUTH = min(CONFIG.getint('listen', 'auth'), 2)
    LISTEN_AUTHWHITELIST = CONFIG.get('listen', 'authwhitelist')
    LISTEN_AUTHWHITELIST = tuple(LISTEN_AUTHWHITELIST.split('|')) if LISTEN_AUTHWHITELIST else ()
    LISTEN_AUTHUSER = CONFIG.get('listen', 'authuser')
    LISTEN_AUTHUSER = tuple(LISTEN_AUTHUSER.split('|')) if LISTEN_AUTHUSER else (':',)
    LISTEN_DEBUGINFO = _LOGLv[min(CONFIG.getint('listen', 'debuginfo'), 3)]
    LISTEN_CHECKPROCESS = CONFIG.getboolean('listen', 'checkprocess')
    LISTEN_CHECKSYSCA = CONFIG.getboolean('listen', 'checksysca')

    GAE_APPIDS = re.findall(r'[\w\-\.]+', CONFIG.get('gae', 'appid').replace('.appspot.com', ''))
    GAE_DEBUG = CONFIG.getint('gae', 'debug')
    GAE_PASSWORD = CONFIG.get('gae', 'password').strip()
    GAE_PATH = CONFIG.get('gae', 'path')
    GAE_MAXPERIP = max(min(CONFIG.getint('gae', 'maxperip'), 8), 2)
    GAE_TIMEOUT = max(CONFIG.getint('gae', 'timeout'), 3)
    GAE_KEEPALIVE = CONFIG.getboolean('gae', 'keepalive')
    GAE_KEEPTIME = CONFIG.getint('gae', 'keeptime')
    GAE_MAXREQUESTS = min(CONFIG.getint('gae', 'maxrequsts'), 5)
    GAE_SSLVERIFY = CONFIG.getboolean('gae', 'sslverify')
    GAE_FETCHMAX = int(CONFIG.get('gae', 'fetchmax') or 2)
    #在服务端，这个数值代表的范围大小会增加 1
    GAE_MAXSIZE = min(int(CONFIG.get('gae', 'maxsize') or 1024 * 1024 * 4), 1024 * 1024 * 32 - 1)
    GAE_IPLIST = CONFIG.get('gae', 'iplist')
    GAE_IPLIST2P = CONFIG.get('gae', 'iplist2p') or 'google_2p'
    GAE_SERVERNAME = CONFIG.get('gae', 'servername').encode()
    GAE_SERVERNAME = tuple(GAE_SERVERNAME.split(b'|')) if GAE_SERVERNAME else None
    GAE_ENABLEPROXY = CONFIG.getboolean('gae', 'enableproxy')
    GAE_PROXYLIST = CONFIG.get('gae', 'proxylist')
    GAE_PROXYLIST = GAE_PROXYLIST.split('|') if GAE_PROXYLIST else None
    if not GAE_PROXYLIST:
        GAE_ENABLEPROXY = False
    if GAE_ENABLEPROXY:
        GAE_IPLIST = GAE_IPLIST2P
        GAE_TIMEOUT = max(GAE_TIMEOUT, 10)

    LINK_PROFILE = CONFIG.get('link', 'profile')
    if LINK_PROFILE not in ('ipv4', 'ipv6', 'ipv46'):
        LINK_PROFILE = 'ipv46'
    LINK_FASTV6CHECK = CONFIG.getboolean('link', 'fastv6check')
    LINK_WINDOW = max(min(CONFIG.getint('link', 'window'), 12), 2)
    LINK_MAXPERIP = max(min(CONFIG.getint('link', 'maxperip'), 32), 3)
    LINK_RECVBUFFER = max(min(CONFIG.getint('link', 'recvbuffer'), 4194304), 32768)
    LINK_VERIFYG2PK = CONFIG.getboolean('link', 'verifyg2pk')
    LINK_LOCALSSLTXT = CONFIG.get('link', 'localssl') or 'TLS'
    LINK_REMOTESSLTXT = CONFIG.get('link', 'remotessl') or 'TLSv1.2'
    LINK_LOCALSSL = _SSLv[LINK_LOCALSSLTXT]
    LINK_REMOTESSL = max(_SSLv[LINK_REMOTESSLTXT], _SSLv['TLS'])
    LINK_REQUESTCOMPRESS = _brotli and CONFIG.getboolean('link', 'requestcompress')
    LINK_TIMEOUT = max(CONFIG.getint('link', 'timeout'), 3)
    LINK_FWDTIMEOUT = max(CONFIG.getint('link', 'fwdtimeout'), 3)
    LINK_KEEPTIME = CONFIG.getint('link', 'keeptime')
    LINK_FWDKEEPTIME = CONFIG.getint('link', 'fwdkeeptime')
    LINK_TEMPTIME = CONFIG.getint('link', 'temptime')
    LINK_TEMPTIME_S = LINK_TEMPTIME % 60
    if LINK_TEMPTIME_S:
        LINK_TEMPTIME_S = ' %d 分 %d 秒' % (LINK_TEMPTIME // 60, LINK_TEMPTIME_S)
    else:
        LINK_TEMPTIME_S = ' %d 分钟' % (LINK_TEMPTIME // 60)
    LINK_TEMPWHITELIST = CONFIG.get('link', 'tempwhitelist')
    LINK_TEMPWHITELIST = tuple(LINK_TEMPWHITELIST.split('|')) if LINK_TEMPWHITELIST else ()

    IPLIST_MAP = dict((k.lower(), [x for x in v.split('|') if x]) for k, v in CONFIG.items('iplist'))

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

    FILTER_ACTION = CONFIG.getint('filter', 'action')
    FILTER_ACTION = FILTER_ACTION if FILTER_ACTION in (1, 2, 3, 4) else 3
    FILTER_SSLACTION = CONFIG.getint('filter', 'sslaction')
    FILTER_SSLACTION = FILTER_SSLACTION if FILTER_SSLACTION in (1, 2, 3, 4) else 2

    PICKER_SERVERNAME = CONFIG.get('picker', 'servername').encode()
    PICKER_COMDOMAIN = CONFIG.get('picker', 'comdomain')
    PICKER_BLOCKTIME = float(CONFIG.get('picker', 'blocktime') or 12)
    PICKER_TIMESBLOCK = int(CONFIG.get('picker', 'timesblock') or 2)
    PICKER_TIMESDEL = int(CONFIG.get('picker', 'timesdel') or 10)
    PICKER_STATDAYS = int(CONFIG.get('picker', 'statdays') or 4)
    PICKER_STATDAYS = max(min(PICKER_STATDAYS, 5), 2)
    PICKER_SORTSTAT = CONFIG.getboolean('picker', 'sortstat')
    PICKER_BLOCK = CONFIG.get('picker', 'block')
    PICKER_BLOCK = tuple(PICKER_BLOCK.split('|')) if PICKER_BLOCK else ()
    PICKER_GAE_ENABLE = CONFIG.getboolean('picker/gae', 'enable')
    PICKER_GAE_MINRECHECKTIME = int(CONFIG.get('picker/gae', 'minrechecktime') or 40)
    PICKER_GAE_MINCNT = int(CONFIG.get('picker/gae', 'mincnt') or 6)
    PICKER_GAE_MAXTIMEOUT = int(CONFIG.get('picker/gae', 'maxtimeout') or 2000)
    PICKER_GAE_MAXTHREADS = int(CONFIG.get('picker/gae', 'maxthreads') or 10)
    PICKER_GWS_ENABLE = CONFIG.getboolean('picker/gws', 'enable')
    PICKER_GWS_MINRECHECKTIME = int(CONFIG.get('picker/gws', 'minrechecktime') or 30)
    PICKER_GWS_MINCNT = int(CONFIG.get('picker/gws', 'mincnt') or 6)
    PICKER_GWS_MAXTIMEOUT = int(CONFIG.get('picker/gws', 'maxtimeout') or 1000)
    PICKER_GWS_MAXTHREADS = int(CONFIG.get('picker/gws', 'maxthreads') or 10)

    if not PICKER_SERVERNAME:
        wait_exit('没有找到 [picker/servername]，请检查配置文件：%r，参考注释进行填写。', CONFIG_FILENAME)

    #PROXY_ENABLE = CONFIG.getboolean('proxy', 'enable')
    PROXY_ENABLE = False
    PROXY_AUTODETECT = CONFIG.getint('proxy', 'autodetect') if CONFIG.has_option('proxy', 'autodetect') else 0
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
    if PROXY_ENABLE:
        proxy = 'https://%s:%s@%s:%d' % (PROXY_USERNAME or '', PROXY_PASSWROD or '', PROXY_HOST, PROXY_PORT)
    else:
        proxy = ''

    AUTORANGE_FAST_ENDSWITH = CONFIG.get('autorange/fast', 'endswith')
    AUTORANGE_FAST_ENDSWITH = tuple(AUTORANGE_FAST_ENDSWITH.split('|')) if AUTORANGE_FAST_ENDSWITH else ()
    AUTORANGE_FAST_FIRSTSIZE = CONFIG.getint('autorange/fast', 'firstsize')
    AUTORANGE_FAST_MAXSIZE = CONFIG.getint('autorange/fast', 'maxsize')
    AUTORANGE_FAST_THREADS = CONFIG.getint('autorange/fast', 'threads')
    AUTORANGE_FAST_LOWSPEED = CONFIG.getint('autorange/fast', 'lowspeed')

    AUTORANGE_BIG_ONSIZE = int(CONFIG.get('autorange/big', 'onsize') or 1024 * 1024 * 32)
    AUTORANGE_BIG_MAXSIZE = CONFIG.getint('autorange/big', 'maxsize')
    AUTORANGE_BIG_SLEEPTIME = CONFIG.getint('autorange/big', 'sleeptime')
    AUTORANGE_BIG_THREADS = CONFIG.getint('autorange/big', 'threads')
    AUTORANGE_BIG_LOWSPEED = CONFIG.getint('autorange/big', 'lowspeed')

    DNS_SERVERS = CONFIG.get('dns', 'servers')
    DNS_SERVERS = tuple(DNS_SERVERS.split('|')) if DNS_SERVERS else ('8.8.8.8',)
    DNS_LOCAL_SERVERS = CONFIG.get('dns', 'localservers')
    DNS_LOCAL_SERVERS = tuple(DNS_LOCAL_SERVERS.split('|')) if DNS_LOCAL_SERVERS else ('114.114.114.114',)
    DNS_LOCAL_HOST = CONFIG.getboolean('dns', 'localhost')
    DNS_OVER_HTTPS = CONFIG.getboolean('dns', 'overhttps')
    DNS_OVER_HTTPS_LIST = CONFIG.get('dns', 'overhttpslist') or 'google_gws'
    DNS_OVER_HTTPS_ECS = CONFIG.get('dns', 'overhttpsecs')
    DNS_IP_API = CONFIG.get('dns', 'ipapi')
    DNS_IP_API = tuple(DNS_IP_API.split('|')) if DNS_IP_API else ()
    DNS_PRIORITY = CONFIG.get('dns', 'priority').split('|')
    DNS_BLACKLIST = set(CONFIG.get('dns', 'blacklist').split('|'))

    DNS_DEF_PRIORITY = ['system', 'remote', 'overhttps']
    for dnstype in DNS_PRIORITY.copy():
        if dnstype in DNS_DEF_PRIORITY:
            DNS_DEF_PRIORITY.remove(dnstype)
        else:
            DNS_PRIORITY.remove(dnstype)
    DNS_PRIORITY.extend(DNS_DEF_PRIORITY)

    DNS_CACHE_ENTRIES = int(CONFIG.get('dns/cache', 'entries') or 1024)
    DNS_CACHE_EXPIRATION = int(CONFIG.get('dns/cache', 'expiration') or 7200)

del CONFIG
