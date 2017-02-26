# coding:utf-8

import os
import socket
from . import data_dir

class IPv4Database:
    #载入 17mon IPv4 地理信息数据库免费版
    #参考：http://www.ipip.net/
    #      https://github.com/lxyu/17monip
    #      https://github.com/wangtuanjie/ip17mon
    # The 17mon dat file format in bytes:
    #    -----------
    #    | 4 bytes |                     <- offset number + 1024
    #    -----------------
    #    | 256 * 4 bytes |               <- first ip number index
    #    -----------------------
    #    | offset - 1028 bytes |         <- ip index
    #    -----------------------
    #    |    data  storage    |
    #    -----------------------
    def __init__(self, filename):
        from struct import unpack
        with open(filename, 'rb') as f:
            #读取地理信息数据偏移 BE Ulong -> int
            offset, = unpack('>L', f.read(4))
            #读取索引数据
            indexIP = f.read(1024)
            #这里多减去一个 1024
            #因为储存在头部的偏移量比实际多了 1024，不知道有什么意义
            index_data_len = offset - 4 - 1024 - 1024
            self.index_data = f.read(index_data_len)
            #读取并缓存地理信息数据
            self.data = f.read()
        #格式化并缓存索引数据
        #使用 struct.unpack 一次性分割数据速度稍快
        #每 4 字节为一个索引 fip：LE Ulong -> int，对应二级索引序数
        self.index = unpack('<' + 'L' * 256, indexIP)
        #以下索引格式化多耗 50M 内存和一点时间，不使用
        #每 8 字节为一组索引，对应 IP 范围和地理信息储存位置
        # nip：BE Uint32 -> 4 bytes（实际不用转换，bytes 之间的比较就是按大端序规则）
        # pos：LE Ulong 3/4 -> int
        # len：Uint -> int
        #index_data = unpack('8s' * (index_data_len // 8), indexData)
        #index_nip = []
        #index_pos = []
        #index_len = []
        #for b in index_data:
        #    index_nip.append(b[:4])     
        #    #直接使用位运算速度快很多，减少约 20% 耗时       
        #    index_pos.append(b[4] | b[5] << 8 | b[6] << 16)
        #    index_len.append(b[7])
        #self.index_nip = tuple(index_nip)
        #self.index_pos = tuple(index_pos)
        #self.index_len = tuple(index_len)

        #获取 IP 数据库版本
        #_pos = ipdb.index_pos[-1]
        #_len = ipdb.index_len[-1]
        b1, b2, b3, _len = self.index_data[-4:]
        _pos = b1 | b2 << 8 | b3 << 16
        self.version = self.data[_pos:_pos + _len].decode('utf-8').split()[1]

    def find(self, ip):
        #转换 IP 为 BE Uint32，实际类型 bytes
        nip = socket.inet_aton(ip)
        #确定二级索引范围
        fip = nip[0]
        lo = self.index[fip]
        hi = self.index[min(fip + 1, 255)]
        #与索引的 IP 范围条目比较确定索引位置
        index_data = self.index_data
        while lo < hi:
            mid = (lo + hi) // 2
            index_off = mid * 8
            if index_data[index_off:index_off + 4] < nip:
                lo = mid + 1
            else:
                hi = mid
        #获取二级索引数据
        index_off = lo * 8 + 4
        b1, b2, b3, data_len = index_data[index_off:index_off + 4]
        data_pos = b1 | b2 << 8 | b3 << 16
        #减去最后一个制表符的长度，保证结果分割出正确的列表长度
        data = self.data[data_pos:data_pos + data_len - 1]
        #返回列表 [country, region, city]
        return data.decode('utf-8').split('\t')

_17monipdb = os.path.join(data_dir, '17monipdb.dat')

if os.path.exists(_17monipdb):
    from . import LRUCache, isip, isipv4
    from .dns import dns_resolve, dns_remote_resolve
    from local.GlobalConfig import GC

    direct_region = '中国', '局域网', '共享地址', '本地链路', '保留地址'
    indep_region = '台湾', '香港'
    direct_cache = LRUCache(GC.DNS_CACHE_ENTRIES//2)
    ipdb = IPv4Database(_17monipdb)
    IPDBVer = ipdb.version
    if '4' not in GC.LINK_PROFILE:
        dns_resolve = dns_remote_resolve

    def isdirect(host):
        hostisip = isip(host)
        if hostisip:
            ips = host,
        elif host in direct_cache:
            return direct_cache[host]
        else:
            ips = dns_resolve(host)
        ipv4 = None
        for ip in ips:
            if isipv4(ip):
                ipv4 = ip
                break
        if ipv4:
            country, region, city = ipdb.find(ipv4)
            #更改 country 以适应网络现状
            if country == '中国' and region in indep_region:
                country = region
            direct = country in direct_region
        else:
            direct = False
        if not hostisip:
            direct_cache[host] = direct
        return direct
else:
    from . import logging
    IPDBVer = '数据库文件未安装'
    logging.warning('无法在 %r 找到 IP 地理信息数据库，'
                    '请下载后（http://www.ipip.net）放入相应位置。',
                    _17monipdb)
    ipdb = None
    isdirect = lambda x: False
