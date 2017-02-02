# coding:utf-8
"""Global Config Module"""


import os
import sys
#import collections
import re
import fnmatch
from .compat import ConfigParser
from .common import config_dir, data_dir
#from .common.proxy import get_system_proxy, parse_proxy
from . import clogging

_LOGLv = {
    0 : clogging.WARNING,
    1 : clogging.INFO,
    2 : clogging.TEST,
    3 : clogging.DEBUG
    }

_SSLv = {
    'SSLv3'   : 1,
    'SSLv23'  : 2,
    'TLSv1'   : 3,
    'TLSv1.1' : 4,
    'TLSv1.2' : 5
    }

#load config from proxy.ini
ENV_CONFIG_PREFIX = 'GOTOX_'
CONFIG = ConfigParser()
CONFIG._optcre = re.compile(r'(?P<option>[^=\s]+)\s*(?P<vi>=?)\s*(?P<value>.*)')

class GC():

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
    LISTEN_GAE_PORT = CONFIG.getint('listen', 'gae_port')
    LISTEN_AUTO_PORT = CONFIG.getint('listen', 'auto_port')
    LISTEN_VISIBLE = CONFIG.getboolean('listen', 'visible')
    LISTEN_DEBUGINFO = _LOGLv[min(CONFIG.getint('listen', 'debuginfo'), 3)]
    LISTEN_CHECKPROCESS = CONFIG.getboolean('listen', 'checkprocess')

    GAE_APPIDS = re.findall(r'[\w\-\.]+', CONFIG.get('gae', 'appid').replace('.appspot.com', ''))
    GAE_PASSWORD = CONFIG.get('gae', 'password').strip()
    GAE_PATH = CONFIG.get('gae', 'path')
    GAE_KEEPALIVE = CONFIG.getboolean('gae', 'keepalive')
    GAE_KEEPTIME = CONFIG.getint('gae', 'keeptime')
    GAE_MAXREQUESTS = min(CONFIG.getint('gae', 'maxrequsts'), 5)
    GAE_SSLVERIFY = CONFIG.getboolean('gae', 'sslverify')
    GAE_FETCHMAX = CONFIG.get('gae', 'fetchmax') or 2
    GAE_MAXSIZE = CONFIG.get('gae', 'maxsize')
    GAE_IPLIST = CONFIG.get('gae', 'iplist')
    GAE_USEGWSIPLIST = True

    LINK_PROFILE = CONFIG.get('link', 'profile')
    if LINK_PROFILE not in ('ipv4', 'ipv6', 'ipv46'):
        LINK_PROFILE = 'ipv4'
    LINK_WINDOW = min(CONFIG.getint('link', 'window'), 2)
    LINK_OPTIONS = CONFIG.get('link', 'options')
    LINK_OPENSSL = CONFIG.getboolean('link', 'openssl')
    LINK_LOCALSSLTXT = CONFIG.get('link', 'localssl') or 'SSLv23'
    LINK_REMOTESSLTXT = CONFIG.get('link', 'remotessl') or 'TLSv1.2'
    LINK_LOCALSSL = _SSLv[LINK_LOCALSSLTXT]
    LINK_REMOTESSL = max(_SSLv[LINK_REMOTESSLTXT]+1, 4) if LINK_OPENSSL else max(_SSLv[LINK_REMOTESSLTXT], 3)
    LINK_TIMEOUT = max(CONFIG.getint('link', 'timeout'), 3)
    LINK_FWDTIMEOUT = max(CONFIG.getint('link', 'fwd_timeout'), 2)
    LINK_KEEPTIME = CONFIG.getint('link', 'keeptime')

    IPLIST_MAP = dict((k.lower(), [x for x in v.split('|') if x]) for k, v in CONFIG.items('iplist'))

    if GAE_IPLIST and GAE_IPLIST != 'google_gws':
        GAE_USEGWSIPLIST = False
        IPLIST_MAP['google_gws'] = IPLIST_MAP['google_com'] = IPLIST_MAP[GAE_IPLIST]

    FILTER_ACTION = CONFIG.getint('filter', 'action')
    FILTER_ACTION = FILTER_ACTION if FILTER_ACTION in (1, 2, 3, 4) else 3
    FILTER_SSLACTION = CONFIG.getint('filter', 'sslaction')
    FILTER_SSLACTION = FILTER_SSLACTION if FILTER_SSLACTION in (1, 2, 3, 4) else 2

    FINDER_MINIPCNT = CONFIG.getint('finder', 'minipcnt')
    FINDER_MAXTIMEOUT = CONFIG.getint('finder', 'maxtimeout') or 1000
    FINDER_THREADS = CONFIG.getint('finder', 'threads')
    FINDER_BLOCKTIME = CONFIG.getint('finder', 'blocktime')
    FINDER_TIMESBLOCK = CONFIG.getint('finder', 'timesblock')
    FINDER_STATDAYS = max(min(CONFIG.getint('finder', 'statdays'), 5), 2)
    FINDER_BLOCK = CONFIG.get('finder', 'block')
    FINDER_BLOCK = tuple(FINDER_BLOCK.split('|')) if FINDER_BLOCK else ()

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

    AUTORANGE_ENDSWITH = CONFIG.get('autorange', 'endswith')
    AUTORANGE_ENDSWITH = tuple(AUTORANGE_ENDSWITH.split('|')) if AUTORANGE_ENDSWITH else ()
    AUTORANGE_FIRSTSIZE = CONFIG.getint('autorange', 'firstsize')
    AUTORANGE_MAXSIZE = CONFIG.getint('autorange', 'maxsize')
    AUTORANGE_BUFSIZE = CONFIG.getint('autorange', 'bufsize')
    AUTORANGE_THREADS = CONFIG.getint('autorange', 'threads')
    AUTORANGE_LOWSPEED = CONFIG.getint('autorange', 'lowspeed')

    DNS_SERVERS = CONFIG.get('dns', 'servers').split('|')
    DNS_OVER_HTTPS = CONFIG.getboolean('dns', 'overhttps')
    DNS_OVER_HTTPS_LIST = CONFIG.get('dns', 'overhttpslist') or 'google_gws'
    DNS_PRIORITY = CONFIG.get('dns', 'priority').split('|')
    DNS_BLACKLIST = set(CONFIG.get('dns', 'blacklist').split('|'))

    DNS_DEF_PRIORITY = ['system', 'remote', 'overhttps']
    for dnstype in DNS_PRIORITY.copy():
        if dnstype in DNS_DEF_PRIORITY:
            DNS_DEF_PRIORITY.remove(dnstype)
        else:
            DNS_PRIORITY.remove(dnstype)
    DNS_PRIORITY.extend(DNS_DEF_PRIORITY)

    DNS_CACHE_ENTRIES = CONFIG.getint('dns/cache', 'entries') or 128
    DNS_CACHE_EXPIRATION = CONFIG.getint('dns/cache', 'expiration') or 3600

del CONFIG, fnmatch, ConfigParser
del sys.modules['fnmatch']
