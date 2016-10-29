# coding:utf-8
"""Global Config Module"""


import os
import sys
#import collections
import re
import fnmatch
from .compat import ConfigParser
from .common import config_dir
#from .common.proxy import get_system_proxy, parse_proxy

SSLv = {
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
    CONFIG_USER_FILENAME = re.sub(r'\.ini$', '.user.ini', CONFIG_FILENAME)
    CONFIG.read([CONFIG_FILENAME, CONFIG_USER_FILENAME])

    #load config from environment
    #for key, value in os.environ.items():
    #    m = re.match(r'^%s([A-Z]+)_([A-Z\_\-]+)$' % ENV_CONFIG_PREFIX, key)
    #    if m:
    #        CONFIG.set(m.group(1).lower(), m.group(2).lower(), value)

    LISTEN_IP = CONFIG.get('listen', 'ip')
    LISTEN_GAE_PORT = CONFIG.getint('listen', 'gae_port')
    LISTEN_AUTO_PORT = CONFIG.getint('listen', 'auto_port')
    LISTEN_VISIBLE = CONFIG.getint('listen', 'visible')
    LISTEN_DEBUGINFO = CONFIG.getint('listen', 'debuginfo')

    GAE_APPIDS = re.findall(r'[\w\-\.]+', CONFIG.get('gae', 'appid').replace('.appspot.com', ''))
    GAE_PASSWORD = CONFIG.get('gae', 'password').strip()
    GAE_PATH = CONFIG.get('gae', 'path')
    GAE_LISTNAME = CONFIG.get('gae', 'listname').lower()
    GAE_MAXREQUESTS = min(CONFIG.getint('gae', 'maxrequsts'), 5) * len(GAE_APPIDS)
    GAE_SSLVERIFY = CONFIG.get('gae', 'sslverify')
    GAE_FETCHMAX = CONFIG.get('gae', 'fetchmax') or 2
    GAE_MAXSIZE = CONFIG.get('gae', 'maxsize')

    LINK_PROFILE = CONFIG.get('link', 'profile')
    if LINK_PROFILE not in ('ipv4', 'ipv6', 'ipv46'):
        LINK_PROFILE = 'ipv4'
    LINK_WINDOW = CONFIG.getint('link', 'window')
    LINK_OPTIONS = CONFIG.get('link', 'options')
    LINK_OPENSSL = CONFIG.getint('link', 'openssl')
    LINK_LOCALSSLTXT = CONFIG.get('link', 'localssl')
    LINK_REMOTESSLTXT = CONFIG.get('link', 'remotessl')
    LINK_LOCALSSLTXT = LINK_LOCALSSLTXT or 'SSLv23'
    LINK_REMOTESSLTXT = LINK_REMOTESSLTXT or 'TLSv1.2'
    LINK_LOCALSSL = SSLv[LINK_LOCALSSLTXT]
    LINK_REMOTESSL = max(SSLv[LINK_REMOTESSLTXT]+1, 4) if LINK_OPENSSL else max(SSLv[LINK_REMOTESSLTXT], 3)
    LINK_TIMEOUT = max(CONFIG.getint('link', 'timeout'), 3)
    LINK_FWDTIMEOUT = max(CONFIG.getint('link', 'fwd_timeout'), 2)

    hosts_section, http_section = '%s/hosts' % LINK_PROFILE, '%s/http' % LINK_PROFILE
    #HOSTS_MAP = collections.OrderedDict((k, v or k) for k, v in CONFIG.items(hosts_section) if '\\' not in k and ':' not in k and not k.startswith('.'))
    #HOSTS_POSTFIX_MAP = collections.OrderedDict((k, v) for k, v in CONFIG.items(hosts_section) if '\\' not in k and ':' not in k and k.startswith('.'))
    #HOSTS_POSTFIX_ENDSWITH = tuple(HOSTS_POSTFIX_MAP)

    #CONNECT_HOSTS_MAP = collections.OrderedDict((k, v) for k, v in CONFIG.items(hosts_section) if ':' in k and not k.startswith('.'))
    #CONNECT_POSTFIX_MAP = collections.OrderedDict((k, v) for k, v in CONFIG.items(hosts_section) if ':' in k and k.startswith('.'))
    #CONNECT_POSTFIX_ENDSWITH = tuple(CONNECT_POSTFIX_MAP)

    #METHOD_REMATCH_MAP = collections.OrderedDict((re.compile(k).match, v) for k, v in CONFIG.items(hosts_section) if '\\' in k)
    #METHOD_REMATCH_HAS_LOCALFILE = any(x.startswith('file://') for x in METHOD_REMATCH_MAP.values())

    #HTTP_WITHGAE = set(CONFIG.get(http_section, 'withgae').split('|'))
    HTTP_CRLFSITES = CONFIG.get(http_section, 'crlfsites')
    HTTP_CRLFSITES = tuple(HTTP_CRLFSITES.split('|')) if HTTP_CRLFSITES else ()
    #HTTP_FORCEHTTPS = set(CONFIG.get(http_section, 'forcehttps').split('|'))
    #HTTP_FAKEHTTPS = set(CONFIG.get(http_section, 'fakehttps').split('|'))

    IPLIST_MAP = dict((k.lower(), v.split('|')) for k, v in CONFIG.items('iplist'))
    #IPLIST_MAP.update((k, [k]) for k, v in HOSTS_MAP.items() if k == v)

    FILTER_ACTION = CONFIG.getint('filter', 'action')
    FILTER_ACTION = FILTER_ACTION if FILTER_ACTION in (1, 2, 3, 4) else 3
    FILTER_SSLACTION = CONFIG.getint('filter', 'sslaction')
    FILTER_SSLACTION = FILTER_SSLACTION if FILTER_SSLACTION in (1, 2, 3, 4) else 2

    FINDER_MINIPCNT = CONFIG.getint('finder', 'minipcnt')
    FINDER_IPCNT = max(CONFIG.getint('finder', 'ipcnt'), FINDER_MINIPCNT)
    FINDER_MAXTIMEOUT = CONFIG.getint('finder', 'maxtimeout') or 1000
    FINDER_THREADS = CONFIG.getint('finder', 'threads')
    FINDER_BLOCKTIME = CONFIG.getint('finder', 'blocktime')
    FINDER_TIMESBLOCK = CONFIG.getint('finder', 'timesblock')
    FINDER_BLOCK = CONFIG.get('finder', 'block')
    FINDER_BLOCK = tuple(FINDER_BLOCK.split('|')) if FINDER_BLOCK else ()

    #PAC_ENABLE = CONFIG.getint('pac', 'enable')
    #PAC_IP = CONFIG.get('pac', 'ip')
    #PAC_PORT = CONFIG.getint('pac', 'port')
    #PAC_FILE = CONFIG.get('pac', 'file').lstrip('/')
    #PAC_GFWLIST = CONFIG.get('pac', 'gfwlist')
    #PAC_ADBLOCK = CONFIG.get('pac', 'adblock') if CONFIG.has_option('pac', 'adblock') else ''
    #PAC_EXPIRED = CONFIG.getint('pac', 'expired')

    #PROXY_ENABLE = CONFIG.getint('proxy', 'enable')
    PROXY_ENABLE = 0
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

    #AUTORANGE_HOSTS = CONFIG.get('autorange', 'hosts')
    #AUTORANGE_HOSTS = AUTORANGE_HOSTS.split('|') if AUTORANGE_HOSTS else []
    #AUTORANGE_HOSTS_MATCH = [re.compile(fnmatch.translate(h)).match for h in AUTORANGE_HOSTS]
    AUTORANGE_ENDSWITH = CONFIG.get('autorange', 'endswith')
    AUTORANGE_ENDSWITH = tuple(AUTORANGE_ENDSWITH.split('|')) if AUTORANGE_ENDSWITH else ()
    AUTORANGE_NOENDSWITH = CONFIG.get('autorange', 'noendswith')
    AUTORANGE_NOENDSWITH = tuple(AUTORANGE_NOENDSWITH.split('|')) if AUTORANGE_NOENDSWITH else ()
    AUTORANGE_FIRSTSIZE = CONFIG.getint('autorange', 'firstsize')
    AUTORANGE_MAXSIZE = CONFIG.getint('autorange', 'maxsize')
    AUTORANGE_WAITSIZE = CONFIG.getint('autorange', 'waitsize')
    AUTORANGE_BUFSIZE = CONFIG.getint('autorange', 'bufsize')
    AUTORANGE_THREADS = CONFIG.getint('autorange', 'threads')
    AUTORANGE_LOWSPEED = CONFIG.getint('autorange', 'lowspeed')

    DNS_ENABLE = CONFIG.getint('dns', 'enable')
    DNS_LISTEN = CONFIG.get('dns', 'listen')
    DNS_SERVERS = CONFIG.get('dns', 'servers').split('|')
    DNS_BLACKLIST = set(CONFIG.get('dns', 'blacklist').split('|'))

    #USERAGENT_ENABLE = CONFIG.getint('useragent', 'enable')
    #USERAGENT_STRING = CONFIG.get('useragent', 'string')

del CONFIG, fnmatch, ConfigParser
del sys.modules['fnmatch']
