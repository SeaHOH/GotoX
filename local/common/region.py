# coding:utf-8

import os
from . import data_dir

_17monipdb = os.path.join(data_dir, '17monipdb.dat')

if os.path.exists(_17monipdb):
    from IP import IPv4Database
    from . import LRUCache, isip, isipv4
    from .dns import dns_resolve, dns_remote_resolve
    from local.GlobalConfig import GC
    LINK_PROFILE = GC.LINK_PROFILE

    direct_region = '中国', '局域网', '保留地址'
    direct_cache = LRUCache(GC.DNS_CACHE_ENTRIES//2)
    ipdb = IPv4Database(_17monipdb, False)

    def isdirect(host):
        hostisip = isip(host)
        if hostisip:
            ips = host,
        elif host in direct_cache:
            return direct_cache[host]
        else:
            ips = ()
            if '4' in LINK_PROFILE:
                ips = dns_resolve(host)
            else:
                ips = dns_remote_resolve(host)
        ipv4 = None
        for ip in ips:
            if isipv4(ip):
                ipv4 = ip
                break
        direct = ipdb.find(ipv4).split()[0] in direct_region if ipv4 else False
        if not hostisip:
            direct_cache[host] = direct
        return direct
else:
    from local import clogging as logging
    logging.warning('无法在 %r 找到 IP 地理信息数据库，请下载后（http://www.ipip.net）放入相应位置。', _17monipdb)
    ipdb = None
    isdirect = lambda x: False
