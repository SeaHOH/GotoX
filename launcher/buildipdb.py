#!/usr/bin/env python3
# coding: utf-8

import os
import urllib.request
from _functools import reduce

def ip2int(ip):
    '''将 IPv4 地址转换为整数'''
    return reduce(lambda a, b: a << 8 | b, map(int, ip.split('.')))

def int2bytes2(n):
    '''将整数转换为大端序字节'''
    return bytes(map(lambda b: (n >> b & 255), (8, 0)))

def int2bytes4(n):
    '''将整数转换为大端序字节'''
    return bytes(map(lambda b: (n >> b & 255), (24, 16, 8, 0)))

Url_APNIC = 'http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest'
Url_17MON = 'https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt'
mask_dict = dict((str(2**i), i) for i in range(8, 25))
keeprange = (    '0.0.0.0/8',  #本地网络
                '10.0.0.0/8',  #私有网络
              '100.64.0.0/10', #地址共享（运营商 NAT）
               '127.0.0.0/8',  #环回地址
             '169.254.0.0/16', #链路本地
              '172.16.0.0/12', #私有网络
               '192.0.0.0/24', #保留地址（IANA）
               '192.0.2.0/24', # TEST-NET-1
             '192.88.99.0/24', # 6to4 中继
             '192.168.0.0/16', #私有网络
              '198.18.0.0/15', #网络基准测试
            '198.51.100.0/24', # TEST-NET-2
             '203.0.113.0/24', # TEST-NET-3
              #连续地址直到 IP 结束，特殊处理
              #'224.0.0.0/4',  #组播地址（D类）
              #'240.0.0.0/4',  #保留地址（E类）
            )
keeplist = []
for iprange in keeprange:
    ip, mask = iprange.split('/')
    keeplist.append((ip2int(ip), 32 - int(mask)))
update = None
g_iplist_apnic = []
g_iplist_17mon = []
g_index = {}
g_padding = int2bytes2(-1)

def save_iplist_as_db(iplist, ipdb):
    #    +---------+
    #    | 4 bytes |                     <- data length
    #    +---------------+
    #    | 224 * 4 bytes |               <- first ip number index
    #    +---------------+
    #    |  2n * 4 bytes |               <- cn ip ranges data
    #    +------------------------+
    #    | b'end' and update info |      <- end verify
    #    +------------------------+
    lastip_s = 0
    lastip_e = 0
    index = g_index
    index_n = 0
    index_fip = -1
    offset = 0
    iplist.extend(keeplist)
    #排序，不然无法处理
    iplist.sort(key=lambda x: x[0])
    #随便算一下
    buffering = len(iplist) * 8 + 224 * 4 + 64 + 4
    buffer = bytearray(buffering)
    for ip, mask in iplist:
        ip_s = ip >> mask << mask
        ip_e = (ip >> mask) + 1 << mask
        #判断连续
        if ip_s <= lastip_e:
            #判断覆盖
            if ip_e > lastip_e:
                lastip_e = ip_e
            continue
        #排除初始值
        if lastip_e:
            #一段范围分为包含和排除
            offset_t = offset + 4
            buffer[offset:offset_t] = lastip_s = int2bytes4(lastip_s)
            buffer[offset_t:] = int2bytes4(lastip_e)
            #一个索引分为开始和结束
            fip = lastip_s[0] * 2
            if fip != index_fip:
                #前一个索引结束，序数多 1
                #避免无法搜索从当前索引结尾地址到下个索引开始地址
                index[index_fip + 1] = int2bytes2(index_n)
                #当前索引开始
                index[fip] = int2bytes2(index_n)
                index_fip = fip
            index_n += 2
            offset += 8
        lastip_s = ip_s
        lastip_e = ip_e
    #添加最后一段范围
    offset_t = offset + 4
    buffer[offset:offset_t] = lastip_s = int2bytes4(lastip_s)
    buffer[offset_t:] = int2bytes4(lastip_e)
    fip = lastip_s[0] * 2
    if fip != index_fip:
        index[index_fip + 1] = int2bytes2(index_n)
        index[fip] = int2bytes2(index_n)
    index_n += 2
    offset += 8
    #添加最后一个结束索引
    index[fip + 1] = int2bytes2(index_n)
    #写入文件
    fd = open(ipdb, 'wb', buffering)
    fd.write(int2bytes4(offset))
    padding = g_padding
    for i in range(224 * 2):
        fd.write(index.get(i, padding))
    fd.write(buffer[:offset])
    fd.write(b'end')
    fd.write(update.encode('utf-8'))
    fd.close()
    #清空缓存
    g_iplist_apnic.clear()
    g_iplist_17mon.clear()
    g_index.clear()
    log('更新信息：%s' % update)
    log('包含 IP 范围条目数：%d' % (index_n // 2))
    log('保存地址：%s' % ipdb)

def download_apnic_cniplist(ipdb):
    global update
    fd = urllib.request.urlopen(Url_APNIC, timeout=5)
    iplist = g_iplist_apnic
    for line in fd:
        if update is None and line.startswith(b'2|apnic'):
            ip = line.decode().split('|')
            update = 'APNIC %s/%s' % (ip[2], ip[5])
        elif line.startswith(b'apnic|CN|ipv4'):
            ip = line.decode().split('|')
            iplist.append((ip2int(ip[3]), mask_dict[ip[4]]))
    fd.close()
    log('APNIC IP 下载完毕')
    return iplist

def download_17mon_cniplist(ipdb):
    global update
    import time
    #设定为当月第一天
    update = '17mon ' + time.strftime('%Y%m01', time.localtime(time.time()))
    fd = urllib.request.urlopen(Url_17MON, timeout=5)
    iplist = g_iplist_17mon
    for line in fd:
        ip, mask = line.decode().strip('\r\n').split('/')
        iplist.append((ip2int(ip), 32 - int(mask)))
    fd.close()
    log('17mon IP 下载完毕')
    return iplist

def download_apnic_cniplist_as_db(ipdb):
    global update
    iplist = download_apnic_cniplist(ipdb)
    update = 'CN IP from ' + update
    save_iplist_as_db(iplist, ipdb)
    update = None
    log('APNIC IP 已保存完毕')

def download_17mon_cniplist_as_db(ipdb):
    global update
    iplist = download_17mon_cniplist(ipdb)
    update = 'CN IP from ' + update
    save_iplist_as_db(iplist, ipdb)
    update = None
    log('17mon IP 已保存完毕')

def download_both_cniplist_as_db(ipdb):
    global update
    iplist = download_apnic_cniplist(ipdb)
    _update = update
    iplist.extend(download_17mon_cniplist(ipdb))
    update = 'CN IP from %s and %s' % (_update, update)
    save_iplist_as_db(iplist, ipdb)
    update = None
    log('APNIC 和 17mon IP 已保存完毕')

def test(ipdb):
    global update
    update = 'keep IP test'
    save_iplist_as_db([], ipdb)
    update = None
    log('keeep IP 已保存完毕')

if __name__ == '__main__':
    import socket
    log = print

    set_proxy = input('是否设置代理（Y/N）：')
    set_proxy = set_proxy.upper() == 'Y'
    if set_proxy:
        print('开始设置代理')
    else:
        print('\n跳过代理设置')
    addr = '127.0.0.1:8087'
    while set_proxy:
        if addr is None:
            addr = input('请输入代理地址（IP:端口）：')
        try:
            ip, port = addr.split(':')
            socket.create_connection((ip, int(port)), timeout=1).close()
            os.environ['HTTPS_PROXY'] = os.environ['HTTP_PROXY'] = addr
            print('\n代理地址 %r 已设置成功。' % addr)
            break
        except:
            set_proxy = input('当前地址 %r 无法链接，是否继续设置代理（Y/N）：' % addr)
            set_proxy = set_proxy.upper() == 'Y'
            addr = None
    if not addr and not set_proxy:
        print('\n跳过代理设置')

    __file__ = os.path.abspath(__file__)
    if os.path.islink(__file__):
        __file__ = getattr(os, 'readlink', lambda x: x)(__file__)
    file_dir = os.path.dirname(__file__)
    root_dir = os.path.dirname(file_dir)
    ipdb1 = os.path.join(root_dir, 'data', 'directip.db')
    ipdb2 = os.path.join(file_dir, 'directip.db')
    Tips = '''
********************************************
*   从 APNIC 下载，放入数据目录 --- 按 1   *
*                      当前目录 --- 按 2   *
*   从 17mon 下载，放入数据目录 --- 按 3   *
*                      当前目录 --- 按 4   *
*    全部下载合并，放入数据目录 --- 按 5   *
*                      当前目录 --- 按 6   *
*   使用保留地址测试 -------------- 按 7   *
*   退出 -------------------------- 按 0   *
********************************************
'''

    while True:
        n = input(Tips)
        try:
            n = int(n)
        except:
            pass
        if n == 0:
            break
        elif n == 1:
            download_apnic_cniplist_as_db(ipdb1)
        elif n == 2:
            download_apnic_cniplist_as_db(ipdb2)
        elif n == 3:
            download_17mon_cniplist_as_db(ipdb1)
        elif n == 4:
            download_17mon_cniplist_as_db(ipdb2)
        elif n == 5:
            download_both_cniplist_as_db(ipdb1)
        elif n == 6:
            download_both_cniplist_as_db(ipdb2)
        elif n == 7:
            test(ipdb2)
        else:
            print('输入错误！')
else:
    from local.clogging import debug as log
