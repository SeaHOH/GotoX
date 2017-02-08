# coding:utf-8

import os
from . import data_dir

_17monipdb = os.path.join(data_dir, '17monipdb.dat')

if os.path.exists(_17monipdb):
    from socket import gethostbyname
    import IP
    from . import isip, isipv4
    from .dns import dns, dns_resolve
    from local.GlobalConfig import GC
    LINK_PROFILE = GC.LINK_PROFILE

    ipdb = IP.IPv4Database(_17monipdb, False)

    def iscn(ip):
        ips = ()
        ipv4 = None
        try:
            if '4' in LINK_PROFILE:
                ips = dns_resolve(ip)
            elif isip(ip):
                ips = ip,
            else:
                ips = gethostbyname(ip)
            for ip in ips:
                if isipv4(ip):
                    ipv4 = ip
                    break
        except:
            pass
        if ipv4:
            return ipdb.find(ipv4).split()[0] == '中国'
else:
    from local import clogging as logging
    logging.warning('无法在 %r 找到 IP 地理信息数据库，请下载后（http://www.ipip.net）放入相应位置。', _17monipdb)
    ipdb = None
    iscn = lambda x: False
