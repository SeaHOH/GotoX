# coding:utf-8

import os
import re
import socket
import logging
from time import sleep
from threading import _start_new_thread as start_new_thread
from .net import isip, isipv4, isipv6
from .path import data_dir, launcher_dir
from .util import LRUCache
from local.GlobalConfig import GC

direct_ipdb = os.path.join(data_dir, 'directip.db')
direct_domains = os.path.join(data_dir, 'directdomains.txt')
direct_cache = LRUCache(GC.DNS_CACHE_ENTRIES//2)
local_cache = LRUCache(GC.DNS_CACHE_ENTRIES)
direct_tlds = (
    # https://icannwiki.org
    # https://en.wikipedia.org/wiki/List_of_Internet_top-level_domains
    # http://gtldresult.icann.org/application-result/applicationstatus
    # https://www.icann.org/resources/pages/registries/registries-agreements-en
    # Country code top-level domains
    'cn', 'hk', 'mo',
    # Internationalized country code top-level domains
    'xn--fiqs8s',  #中国
    'xn--fiqz9s',  #中國
    'xn--j6w193g', #香港
    'xn--mix082f', #澳门
    'xn--mix891f', #澳門
    # Internationalized geographic top-level domains
    'xn--1qqw23a', #佛山 Guangzhou YU Wei Information Technology Co., Ltd.
    'xn--xhq521b', #广东 Guangzhou YU Wei Information Technology Co., Ltd.
    # ICANN-era generic top-level domains
    'anquan',  #安全 QIHOO 360 TECHNOLOGY CO. LTD.
    'cyou',    #畅游 Beijing Gamease Age Digital Technology Co., Ltd.
    'ren',     #人人 Beijing Qianxiang Wangjing Technology Development Co.
    'top',     # Jiangsu Bangning
    'wang',    #网 Zodiac Wang Limited
    'shouji',  #手机 QIHOO 360 TECHNOLOGY CO. LTD.
    'tushu',   #图书 Amazon Registry Services, Inc.
    'wanggou', #网购 Amazon Registry Services, Inc.
    'weibo',   #微博 Sina Corporation
    'xihuan',  #喜欢 QIHOO 360 TECHNOLOGY CO. LTD.
    'yun',     #云 QIHOO 360 TECHNOLOGY CO. LTD.
    'xin',     # Elegant Leader Limited
    # Internationalized generic top-level domains
    'xn--zfr164b',    #政务 China Organizational Name Administration Center
    'xn--55qw42g',    #公益 China Organizational Name Administration Center
    'xn--io0a7i',     #网络 Computer Network Information Center of Chinese Academy of Sciences (CNNIC)
    'xn--55qx5d',     #公司 Computer Network Information Center of Chinese Academy of Sciences (CNNIC)
    'xn--vuq861b',    #信息 Beijing Tele-info Network Technology Co., Ltd.
    'xn--kput3i ',    #手机 Beijing RITT-Net Technology Development Co., Ltd.
    'xn--efvy88h',    #新闻 Guangzhou  YU  Wei  Information  Technology  Co.,  Ltd.
    'xn--9krt00a',    #微博 Sina Corporation
    'xn--45q11c',     #八卦 Zodiac Gemini Limited
    'xn--3bst00m',    #集团 Eagle  Horizon  Limited
    'xn--hxt814e',    #网店 Zodiac Taurus Limited
    'xn--czru2d',     #商城 Zodiac Aquarius Limited
    'xn--30rr7y',     #慈善 Excellent First Limited
    'xn--9et52u',     #时尚 Rise  Victory  Limited
    'xn--6qq986b3xl', #我爱你 Tycoon  Treasure  Limited
    'xn--ses554g',    #网址 KNET Co., Ltd.
    'xn--rhqv96g',    #世界 Stable Tone Limited (HK)
    'xn--nyqy26a',    #健康 Stable Tone Limited (HK)
    'xn--czr694b',    #商标 Hu Yi Global Information Resources (Holding) Company. Hong Kong Limited (HK)
    'xn--imr513n',    #餐厅 Hu Yi Global Information Resources (Holding) Company. Hong Kong Limited (HK)
    'xn--otu796d',    #招聘 Dot Trademark TLD Holding Company Limited (HK)
    'xn--5tzm5g',     #网站 Global Website TLD Asia Limited (HK)
    # Brand top-level domains
    'alibaba',     #阿里巴巴 Alibaba Group Holding Limited
    'alipay',      #阿里支付 Alibaba Group Holding Limited
    'baidu',       #百度 Baidu, Inc.
    'citic',       #中信 CITIC Group
    'icbc',        #工行 Industrial and Commercial Bank of China Limited
    'sina',        #新浪 Sina Corporation
    'taobao',      #淘宝 Alibaba Group Holding Limited
    'tmall',       #天猫 Alibaba Group Holding Limited
    'unicom',      #联通 China United Network Communications Corporation Limited
    'kerryhotels', #嘉里大酒店 Kerry Trading Co. Limited (HK)
    # Internationalized brand top-level domains
    'xn--8y0a063a',         #联通 China United Network Communications Corporation Limited
    'xn--6frz82g',          #移动 China Mobile Communications Corporation
    'xn--fiq64b',           #中信 CITIC Group
    'xn--estv75g',          #工行 Industrial and Commercial Bank of China Limited
    'xn--3oq18vl8pn36a',    #大众汽车 Volkswagen (China) Investment Co., Ltd.
    'xn--5su34j936bgsg',    #香格里拉 Shangri‐La International Hotel Management Limited (HK)
    'xn--w4rs40l',          #嘉里 Kerry Trading Co. Limited (HK)
    'xn--w4r85el8fhu5dnra', #嘉里大酒店 Kerry Trading Co. Limited (HK)
    # Special-Use Domains (reserved)
    'example',
    'invalid',
    'local',
    'localhost',
    'onion',
    'test',
    )

class IPv4Database:
    #载入 IPv4 保留地址和 CN 地址数据库，数据来源：
    #    https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest
    #    https://github.com/17mon/china_ip_list/raw/master/china_ip_list.txt
    #    +---------+
    #    | 4 bytes |                     <- data length
    #    +---------------+
    #    | 224 * 4 bytes |               <- first ip number index
    #    +---------------+
    #    |  2n * 4 bytes |               <- cn ip ranges data
    #    +------------------------+
    #    | b'end' and update info |      <- end verify
    #    +------------------------+
    def __init__(self, filename):
        from struct import unpack, iter_unpack
        with open(filename, 'rb') as f:
            #读取 IP 范围数据长度 BE Ulong -> int
            data_len, = unpack('>L', f.read(4))
            #读取索引数据
            index = f.read(224 * 4)
            #读取 IP 范围数据
            data = f.read(data_len)
            #简单验证结束
            if f.read(3) != b'end':
                raise ValueError('%s 文件格式损坏！' % filename)
            #读取更新信息
            self.update = f.read().decode('ascii')
        #格式化并缓存索引数据
        #每 4 字节为一个索引范围 fip：BE short -> int，对应 IP 范围序数
        #self.index = unpack('>%dh' % (224 * 2), index)
        self.index = [i for i, in iter_unpack('>h', index)]
        #每 8 字节对应一段直连 IP 范围和一段非直连 IP 范围
        #self.data = unpack('4s' * (data_len // 4), data)
        self.data = [d for d, in iter_unpack('4s', data)]

    def __contains__(self, ip, inet_aton=socket.inet_aton):
        #转换 IP 为 BE Uint32，实际类型 bytes
        nip = inet_aton(ip)
        #确定索引范围
        fip = nip[0]
        #从 224 开始都属于保留地址
        if fip >= 224:
            return True
        fip *= 2
        lo = self.index[fip]
        if lo < 0:
            return False
        hi = self.index[fip + 1]
        #与 IP 范围比较确定 IP 位置
        data = self.data
        while lo < hi:
            mid = (lo + hi) // 2
            if data[mid] > nip:
                hi = mid
            else:
                lo = mid + 1
        #根据位置序数奇偶确定是否属于直连 IP
        return lo & 1

class DomainsTree:
    leaf = object()
    check_domain = re.compile(r'^[a-zA-z0-9\-\.]+$').match

    def __init__(self):
        self.root = {}
        self.ips = set()
        self.update = 'N/A'
        self.count_dm = 0

    @property
    def count_ip(self):
        return len(self.ips)

    def add(self, domain):
        if not domain or not isinstance(domain, str) or \
                len(domain) > 253 or \
                self.add_ip(domain) or \
                self.check_domain(domain) is None:
            return

        def clear_node(node, pname):
            for k, v in node.items():
                lname = '%s.%s' % (k, pname)
                if v is self.leaf:
                    logging.debug('移除直连域名：%s', lname)
                    self.count_dm -= 1
                else:
                    clear_node(v, lname)

        if domain[0] == '.':
            domain = domain[1:]
        domain = domain.lower()
        names = domain.split('.')
        node = self.root
        while names:
            name = names.pop()
            try:
                child = node[name]
            except KeyError:
                if names:
                    node[name] = child = {}
                else:
                    node[name] = self.leaf
                    break
            else:
                if child is self.leaf:
                    lname = domain[domain.find(name):]
                    logging.test('发现重复直连域名：%s < %s', domain, lname)
                    return
                elif not names:
                    node[name] = self.leaf
                    lname = domain[domain.find(name):]
                    logging.test('发现重复直连域名：%s > *.%s', domain, lname)
                    clear_node(child, lname)
            node = child
        self.count_dm += 1

    def add_ip(self, ip):
        if isipv6(ip):
            ip = socket.inet_pton(socket.AF_INET6, ip)
        elif not isipv4(ip):
            return
        self.ips.add(ip)
        return True

    def add_file(self, file):
        with open(file, 'r') as fd:
            has_update = None
            line = fd.readline()
            if line[:1] in '#;' and 'pdate:' in line:
                self.update = line.split('pdate:')[-1].strip()
                has_update = True
            elif line[:1] not in '#;':
                domain = line.strip()
                self.add(domain)
            for line in fd:
                if line[:1] not in '#;':
                    domain = line.strip()
                    self.add(domain)
            if has_update and line[:4] != '#end':
                logging.warning('直连域名列表文件 %r 不完整，请更新', file)

    def __contains__(self, host):
        if isipv6(host):
            host = socket.inet_pton(socket.AF_INET6, host)
        elif not isipv4(host):
            names = host.lower().split('.')
            node = self.root
            while names:
                name = names.pop()
                try:
                    child = node[name]
                except KeyError:
                    return False
                if child is self.leaf:
                    return True
                node = child
            return False
        return host in self.ips

def isdirect(host):
    if islocal(host):
        return True
    if ipdb is None:
        return False
    try:
        return direct_cache[host]
    except KeyError:
        pass
    direct = host in direct_domains_temp_tree
    if not direct:
        for ip in dns_resolve(host):
            if isipv4(ip) and ip in ipdb:
                direct = True
                break
    direct_cache[host] = direct
    return direct

def islocal(host):
    try:
        return local_cache[host]
    except KeyError:
        pass
    if host in direct_domains_black_tree:
        local_cache[host] = False
        return False
    if host in direct_domains_tree:
        local_cache[host] = True
        return True

if '4' in GC.LINK_PROFILE:
    from .dns import dns_resolve
else:
    from .dns import _dns_resolve, A

    def dns_resolve(host, qtypes=[A]):
        if isip(host):
            return host,
        return _dns_resolve(host, qtypes=qtypes, local=False)

direct_domains_temp_tree = DomainsTree()
for domain in GC.LINK_TEMPWHITELIST:
    direct_domains_temp_tree.add(domain)

direct_domains_black_tree = DomainsTree()
for domain in GC.DNS_LOCAL_BLACKLIST:
    direct_domains_black_tree.add(domain)

def load_ipdb():
    global ipdb, IPDBVer
    if os.path.exists(direct_ipdb):
        ipdb = IPv4Database(direct_ipdb)
        IPDBVer = ipdb.update
    else:
        ipdb = None
        IPDBVer = '数据库文件未安装'
        buildscript = os.path.join(launcher_dir, 'buildipdb.py')
        logging.warning('无法在找到直连 IP 数据库，Win 用户可用托盘工具下载更新，'
                        '其它系统请运行脚本 %r 下载更新。', buildscript)

def load_domains():
    global direct_domains_tree, DDTVer
    domains_tree = DomainsTree()
    if os.path.exists(direct_domains):
        domains_tree.add_file(direct_domains)
        DDTVer = '%s, domains count: %d, IPs count: %d' % (
                domains_tree.update, domains_tree.count_dm, domains_tree.count_ip)
    else:
        DDTVer = '列表文件未安装'
        buildscript = os.path.join(launcher_dir, 'builddomains.py')
        logging.warning('无法找到直连域名列表文件，Win 用户可用托盘工具下载更新，'
                        '其它系统请运行脚本 %r 下载更新。', buildscript)
    logging.test('开始添加内置直连域名列表')
    for domain in direct_tlds:
        domains_tree.add(domain)
    logging.test('开始添加用户本地域名列表')
    for domain in GC.DNS_LOCAL_WHITELIST:
        domains_tree.add(domain)
    direct_domains_tree = domains_tree

def check_modify():
    if os.path.exists(direct_ipdb):
        ipdb_mtime = os.path.getmtime(direct_ipdb)
    else:
        ipdb_mtime = 0
    if os.path.exists(direct_domains):
        domains_mtime = os.path.getmtime(direct_domains)
    else:
        domains_mtime = 0
    while True:
        sleep(10)
        if os.path.exists(direct_ipdb):
            ipdb_file_mtime = os.path.getmtime(direct_ipdb)
        else:
            ipdb_file_mtime = 0
        if ipdb_file_mtime > ipdb_mtime:
            try:
                load_ipdb()
            except Exception as e:
                logging.warning('检测到直连 IP 数据库更新，重新加载时出现错误，'
                                '请重新下载：%r', e)
            else:
                ipdb_mtime = ipdb_file_mtime
                direct_cache.clear()
                logging.warning('检测到直连 IP 数据库更新，已重新加载：%s。', IPDBVer)
        if os.path.exists(direct_domains):
            domains_file_mtime = os.path.getmtime(direct_domains)
        else:
            domains_file_mtime = 0
        if domains_file_mtime > domains_mtime:
            try:
                load_domains()
            except Exception as e:
                logging.warning('检测到直连域名列表更新，重新加载时出现错误，'
                                '请重新下载：%r', e)
            else:
                domains_mtime = domains_file_mtime
                local_cache.clear()
                direct_cache.clear()
                logging.warning('检测到直连域名列表更新，已重新加载：%s。', DDTVer)

load_ipdb()
load_domains()
start_new_thread(check_modify, ())
