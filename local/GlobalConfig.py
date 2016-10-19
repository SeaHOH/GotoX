# coding:utf-8
"""Global Config Module"""

class GC(): pass

import os
import sys
#import collections
import re
import fnmatch
from compat import ConfigParser
from common import config_dir, get_system_proxy, parse_proxy

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

GC.CONFIG_FILENAME = os.path.join(config_dir, 'Config.ini')
GC.CONFIG_USER_FILENAME = re.sub(r'\.ini$', '.user.ini', GC.CONFIG_FILENAME)
CONFIG.read([GC.CONFIG_FILENAME, GC.CONFIG_USER_FILENAME])

#load config from environment
#for key, value in os.environ.items():
#    m = re.match(r'^%s([A-Z]+)_([A-Z\_\-]+)$' % ENV_CONFIG_PREFIX, key)
#    if m:
#        CONFIG.set(m.group(1).lower(), m.group(2).lower(), value)

GC.LISTEN_IP = CONFIG.get('listen', 'ip')
GC.LISTEN_GAE_PORT = CONFIG.getint('listen', 'gae_port')
GC.LISTEN_AUTO_PORT = CONFIG.getint('listen', 'auto_port')
GC.LISTEN_VISIBLE = CONFIG.getint('listen', 'visible')
GC.LISTEN_DEBUGINFO = CONFIG.getint('listen', 'debuginfo')

GC.GAE_APPIDS = re.findall(r'[\w\-\.]+', CONFIG.get('gae', 'appid').replace('.appspot.com', ''))
GC.GAE_PASSWORD = CONFIG.get('gae', 'password').strip()
GC.GAE_PATH = CONFIG.get('gae', 'path')
GC.GAE_LISTNAME = CONFIG.get('gae', 'listname')
GC.GAE_MAXREQUESTS = min(CONFIG.getint('gae', 'maxrequsts'), 12)
#GC.GAE_OBFUSCATE = CONFIG.getint('gae', 'obfuscate')
GC.GAE_VALIDATE = CONFIG.getint('gae', 'validate')

GC.LINK_PROFILE = CONFIG.get('link', 'profile')
if GC.LINK_PROFILE not in ('ipv4', 'ipv6', 'ipv46'):
    GC.LINK_PROFILE = 'ipv4'
GC.LINK_WINDOW = CONFIG.getint('link', 'window')
GC.LINK_OPTIONS = CONFIG.get('link', 'options')
GC.LINK_OPENSSL = CONFIG.getint('link', 'openssl')
GC.LINK_LOCALSSLTXT = CONFIG.get('link', 'localssl')
GC.LINK_REMOTESSLTXT = CONFIG.get('link', 'remotessl')
GC.LINK_LOCALSSLTXT = GC.LINK_LOCALSSLTXT or 'SSLv23'
GC.LINK_REMOTESSLTXT = GC.LINK_REMOTESSLTXT or 'TLSv1.2'
GC.LINK_LOCALSSL = SSLv[GC.LINK_LOCALSSLTXT]
GC.LINK_REMOTESSL = max(SSLv[GC.LINK_REMOTESSLTXT]+1, 4) if GC.LINK_OPENSSL else max(SSLv[GC.LINK_REMOTESSLTXT], 3)
GC.LINK_TIMEOUT = CONFIG.getint('link', 'timeout')
GC.LINK_FWDTIMEOUT = CONFIG.getint('link', 'fwd_timeout')

hosts_section, http_section = '%s/hosts' % GC.LINK_PROFILE, '%s/http' % GC.LINK_PROFILE
#GC.HOSTS_MAP = collections.OrderedDict((k, v or k) for k, v in CONFIG.items(hosts_section) if '\\' not in k and ':' not in k and not k.startswith('.'))
#GC.HOSTS_POSTFIX_MAP = collections.OrderedDict((k, v) for k, v in CONFIG.items(hosts_section) if '\\' not in k and ':' not in k and k.startswith('.'))
#GC.HOSTS_POSTFIX_ENDSWITH = tuple(GC.HOSTS_POSTFIX_MAP)

#GC.CONNECT_HOSTS_MAP = collections.OrderedDict((k, v) for k, v in CONFIG.items(hosts_section) if ':' in k and not k.startswith('.'))
#GC.CONNECT_POSTFIX_MAP = collections.OrderedDict((k, v) for k, v in CONFIG.items(hosts_section) if ':' in k and k.startswith('.'))
#GC.CONNECT_POSTFIX_ENDSWITH = tuple(GC.CONNECT_POSTFIX_MAP)

#GC.METHOD_REMATCH_MAP = collections.OrderedDict((re.compile(k).match, v) for k, v in CONFIG.items(hosts_section) if '\\' in k)
#GC.METHOD_REMATCH_HAS_LOCALFILE = any(x.startswith('file://') for x in GC.METHOD_REMATCH_MAP.values())

#GC.HTTP_WITHGAE = set(CONFIG.get(http_section, 'withgae').split('|'))
GC.HTTP_CRLFSITES = CONFIG.get(http_section, 'crlfsites')
GC.HTTP_CRLFSITES = tuple(GC.HTTP_CRLFSITES.split('|')) if GC.HTTP_CRLFSITES else ()
#GC.HTTP_FORCEHTTPS = set(CONFIG.get(http_section, 'forcehttps').split('|'))
#GC.HTTP_FAKEHTTPS = set(CONFIG.get(http_section, 'fakehttps').split('|'))

GC.IPLIST_MAP = dict((k, v.split('|')) for k, v in CONFIG.items('iplist'))
#GC.IPLIST_MAP.update((k, [k]) for k, v in GC.HOSTS_MAP.items() if k == v)

GC.FILTER_ACTION = CONFIG.getint('filter', 'action')
GC.FILTER_SSLACTION = CONFIG.getint('filter', 'sslaction')

GC.FINDER_MINIPCNT = CONFIG.getint('finder', 'minipcnt')
GC.FINDER_IPCNT = max(CONFIG.getint('finder', 'ipcnt'), GC.FINDER_MINIPCNT)
GC.FINDER_MAXTIMEOUT = CONFIG.getint('finder', 'maxtimeout')
GC.FINDER_THREADS = CONFIG.getint('finder', 'threads')
GC.FINDER_BLOCKTIME = CONFIG.getint('finder', 'blocktime')
GC.FINDER_TIMESBLOCK = CONFIG.getint('finder', 'timesblock')
GC.FINDER_BLOCK = CONFIG.get('finder', 'block')
GC.FINDER_BLOCK = tuple(GC.FINDER_BLOCK.split('|')) if GC.FINDER_BLOCK else ()

#GC.PAC_ENABLE = CONFIG.getint('pac', 'enable')
#GC.PAC_IP = CONFIG.get('pac', 'ip')
#GC.PAC_PORT = CONFIG.getint('pac', 'port')
#GC.PAC_FILE = CONFIG.get('pac', 'file').lstrip('/')
#GC.PAC_GFWLIST = CONFIG.get('pac', 'gfwlist')
#GC.PAC_ADBLOCK = CONFIG.get('pac', 'adblock') if CONFIG.has_option('pac', 'adblock') else ''
#GC.PAC_EXPIRED = CONFIG.getint('pac', 'expired')

GC.PROXY_ENABLE = CONFIG.getint('proxy', 'enable')
GC.PROXY_AUTODETECT = CONFIG.getint('proxy', 'autodetect') if CONFIG.has_option('proxy', 'autodetect') else 0
GC.PROXY_HOST = CONFIG.get('proxy', 'host')
GC.PROXY_PORT = CONFIG.getint('proxy', 'port')
GC.PROXY_USERNAME = CONFIG.get('proxy', 'username')
GC.PROXY_PASSWROD = CONFIG.get('proxy', 'password')

#read proxy from system
#if not GC.PROXY_ENABLE and GC.PROXY_AUTODETECT:
#    system_proxy = get_system_proxy()
#    if system_proxy and GC.LISTEN_IP not in system_proxy:
#        _, username, password, address = parse_proxy(system_proxy)
#        proxyhost, _, proxyport = address.rpartition(':')
#        GC.PROXY_ENABLE = 1
#        GC.PROXY_USERNAME = username
#        GC.PROXY_PASSWROD = password
#        GC.PROXY_HOST = proxyhost
#        GC.PROXY_PORT = int(proxyport)
if GC.PROXY_ENABLE:
    GC.proxy = 'https://%s:%s@%s:%d' % (GC.PROXY_USERNAME or '', GC.PROXY_PASSWROD or '', GC.PROXY_HOST, GC.PROXY_PORT)
else:
    GC.proxy = ''

GC.AUTORANGE_HOSTS = CONFIG.get('autorange', 'hosts')
GC.AUTORANGE_HOSTS = GC.AUTORANGE_HOSTS.split('|') if GC.AUTORANGE_HOSTS else []
GC.AUTORANGE_HOSTS_MATCH = [re.compile(fnmatch.translate(h)).match for h in GC.AUTORANGE_HOSTS]
GC.AUTORANGE_ENDSWITH = CONFIG.get('autorange', 'endswith')
GC.AUTORANGE_ENDSWITH = tuple(GC.AUTORANGE_ENDSWITH.split('|')) if GC.AUTORANGE_ENDSWITH else ()
GC.AUTORANGE_NOENDSWITH = CONFIG.get('autorange', 'noendswith')
GC.AUTORANGE_NOENDSWITH = tuple(GC.AUTORANGE_NOENDSWITH.split('|')) if GC.AUTORANGE_NOENDSWITH else ()
GC.AUTORANGE_FIRSTSIZE = CONFIG.getint('autorange', 'firstsize')
GC.AUTORANGE_MAXSIZE = CONFIG.getint('autorange', 'maxsize')
GC.AUTORANGE_WAITSIZE = CONFIG.getint('autorange', 'waitsize')
GC.AUTORANGE_BUFSIZE = CONFIG.getint('autorange', 'bufsize')
GC.AUTORANGE_THREADS = CONFIG.getint('autorange', 'threads')
GC.AUTORANGE_LOWSPEED = CONFIG.getint('autorange', 'lowspeed')

GC.FETCHMAX_LOCAL = CONFIG.getint('fetchmax', 'local') if CONFIG.get('fetchmax', 'local') else 2
GC.FETCHMAX_SERVER = CONFIG.get('fetchmax', 'server')
GC.FETCHMAXSIZE = CONFIG.get('fetchmax', 'maxsize')

GC.DNS_ENABLE = CONFIG.getint('dns', 'enable')
GC.DNS_LISTEN = CONFIG.get('dns', 'listen')
GC.DNS_SERVERS = CONFIG.get('dns', 'servers').split('|')
GC.DNS_BLACKLIST = set(CONFIG.get('dns', 'blacklist').split('|'))

#GC.USERAGENT_ENABLE = CONFIG.getint('useragent', 'enable')
#GC.USERAGENT_STRING = CONFIG.get('useragent', 'string')

del CONFIG, fnmatch, ConfigParser
del sys.modules['fnmatch']
