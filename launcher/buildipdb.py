#!/usr/bin/env python3
# coding: utf-8

import os
import sys
sys.dont_write_bytecode = True

import struct
import socket
from common import (
    file_dir, direct_ipdb, DataSourceManager, download_as_list,
    parse_set_proxy, select_path, getlogger
    )


def ip2int(ip, unpack=struct.unpack, inet_aton=socket.inet_aton):
    '''将 IPv4 地址转换为整数'''
    return unpack('>I', inet_aton(ip))[0]

def int2bytes2(n, pack=struct.pack):
    '''将整数转换为大端序字节'''
    return pack('>H', n)

def int2bytes4(n, pack=struct.pack):
    '''将整数转换为大端序字节'''
    return pack('>I', n)

Url_APNIC = 'https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest'
Url_17MON = 'https://raw.githubusercontent.com/17mon/china_ip_list/master/china_ip_list.txt'
Url_GAOYIFAN = 'https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt'
downloading = False
mask_dict = dict((str(2**i), i) for i in range(8, 25))
# https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
keeprange = (
         '0.0.0.0/8',  #本地网络
        '10.0.0.0/8',  #私有网络
      '100.64.0.0/10', #地址共享（运营商 NAT）
       '127.0.0.0/8',  #环回地址
     '169.254.0.0/16', #链路本地
      '172.16.0.0/12', #私有网络
       '192.0.0.0/24', # IETF 协议分配
       '192.0.2.0/24', # TEST-NET-1
    '192.31.196.0/24', # AS112-v4 DNS 服务
    '192.52.193.0/24', #自动组播隧道
     '192.88.99.0/24', # 6to4 中继任播（已弃用）
     '192.168.0.0/16', #私有网络
    '192.175.48.0/24', #直接授权 AS112 DNS 服务
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

def save_iplist_as_db(ipdb, iplist, padding=b'\xff\xff'):
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
    index = {}
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
            buffer[offset:] = lastip_s = int2bytes4(lastip_s)
            buffer[offset + 4:] = int2bytes4(lastip_e)
            #一个索引分为开始和结束
            fip = lastip_s[0] * 2
            if fip != index_fip:
                #前一个索引结束，序数多 1
                #避免无法搜索从当前索引结尾地址到下个索引开始地址
                index[index_fip + 1] = index_b = int2bytes2(index_n)
                #当前索引开始
                index[fip] = index_b
                index_fip = fip
            index_n += 2
            offset += 8
        lastip_s = ip_s
        lastip_e = ip_e
    #添加最后一段范围
    buffer[offset:] = lastip_s = int2bytes4(lastip_s)
    buffer[offset + 4:] = int2bytes4(lastip_e)
    fip = lastip_s[0] * 2
    if fip != index_fip:
        index[index_fip + 1] = index_b = int2bytes2(index_n)
        index[fip] = index_b
    index_n += 2
    offset += 8
    #添加最后一个结束索引
    index[fip + 1] = int2bytes2(index_n)
    #写入文件
    fd = open(ipdb, 'wb', buffering)
    fd.write(int2bytes4(offset))
    for i in range(224 * 2):
        fd.write(index.get(i, padding))
    fd.write(buffer[:offset])
    fd.write(b'endCN IP from ')
    fd.write(update.encode('ascii'))
    fd.write(b', range count: ')
    count = str(index_n // 2)
    fd.write(count.encode('ascii'))
    fd.close()
    logging.debug('更新信息：%s' % update)
    logging.debug('包含 IP 范围条目数：%s' % count)
    logging.debug('保存地址：%s' % ipdb)

def parse_apnic_iplist(fd, ds):
    read = 0
    try:
        for line in fd:
            read += len(line)
            linesp = line.decode().split('|')
            if len(linesp) != 7:
                continue
            if linesp[2] == 'ipv4' and (linesp[1] == 'CN' or ds.check(linesp[1])):
                ds.itemlist.append((ip2int(linesp[3]), mask_dict[linesp[4]]))
            elif linesp[0] is '2' and not ds.update:
                ds.update = '%s/%s' % (linesp[2], linesp[5])
            elif linesp[2] == 'ipv6':
                #不需要 IPv6 数据，提前结束
                return
    except Exception as e:
        logging.warning('parse_apnic_iplist 解析出错：%s', e)
    return read

def parse_cidr_iplist(fd, ds):
    read = 0
    try:
        for line in fd:
            read += len(line)
            if line[:1] in b'#;':
                continue
            if b'/' in line:
                ip, mask = line.decode().strip('\r\n').split('/')
                ds.itemlist.append((ip2int(ip), 32 - int(mask)))
    except Exception as e:
        logging.warning('parse_cidr_iplist 解析出错：%s', e)
    return read

def download_cniplist_as_db(ipdb, p=1):
    global downloading, update
    if downloading:
        msg = '已经有更新直连 IP 库的任务正在进行中，请稍后再试'
        logging.warning(msg)
        return msg
    downloading = True
    iplist = []
    _update = []

    def add(ds):
        download_as_list(ds)
        iplist.extend(ds.itemlist)
        _update.append(ds.update)

    try:
        for ds in data_source_manager.sources():
            if p & ds:
                add(ds)

        update = ' and '.join(_update)
        save_iplist_as_db(ipdb, iplist)
        logging.info('直连 IP 库已保存完毕')
    except Exception as e:
        logging.warning('更新直连 IP 库 %r 失败：%s' % (ipdb, e))
    finally:
        downloading = False
        data_source_manager.clear_source_data()

def test(ipdb):
    global update
    update = 'keep IP test'
    save_iplist_as_db(ipdb, [])
    print('IP 保留地址已保存完毕')

data_source_manager = DataSourceManager()
ds_APNIC = data_source_manager.add('APNIC', Url_APNIC, parse_apnic_iplist)
ds_17MON = data_source_manager.add('17mon', Url_17MON, parse_cidr_iplist)
ds_GAOYIFAN = data_source_manager.add('GaoYiFan', Url_GAOYIFAN, parse_cidr_iplist)
ds_APNIC.add(['mo', 'hk'])
#更新一般在月初几天，由于内容不包含日期信息，故记录为获取时的日期信息
ds_17MON.datefmt = '%Y%m%d'
#每日 3:00 之后更新
ds_GAOYIFAN.datefmt = '%Y%m%d'

is_main = __name__ == '__main__'
logging = getlogger(is_main)

if is_main:
    if len(sys.argv) < 2:
        print('使用 "--help" 可查看命令行参数说明\n')
    if '--help' in sys.argv:
        print('''
用法：
    --help     显示此使用提示
    -u         生成的数据库文件不放入脚本目录而是更新到相邻的 data 目录
               交互模式下参数 "-u" 无效

    指定可用数据源，交互模式中无效

    --apnic[ mo][ hk]
               使用 APNIC 数据源
                 mo  保存澳门数据
                 hk  保存香港数据
    --17mon    使用 17mon 数据源
    --gaoyifan 使用 gaoyifan 数据源
    --all      使用以上全部数据源

    指定数据源并配合以下参数时不会进入交互模式，适用于自动／无人职守模式

    -d         跳过代理设置使用直连，使用参数 "-p" 时参数 "-d" 无效
    -p 主机名(IP 或域名):端口
               非交互模式使用 HTTP 代理，无效地址或无法链接代理时会直接结束脚本

''')
    ipdb1 = direct_ipdb
    ipdb2 = os.path.join(file_dir, 'directip.db')
    data_source = data_source_manager.get_source(*sys.argv)
    if parse_set_proxy(data_source) is None:
        ipdb = ipdb1 if '-u' in sys.argv else ipdb2
        download_cniplist_as_db(ipdb, data_source)
        sys.exit(0)

    Tips2 = '''
 ***********************************************
 *   请选择数据来源，可多选：                  *
 *                      APNIC --------- 按 1   *
 *                      17mon --------- 按 2   *
 *                      gaoyifan ------ 按 3   *
 *                      全部 ---------- 按 6   *
 *                      保存澳门数据 -- 按 7   *
 *                      保存香港数据 -- 按 8   *
 *                      测试保留地址 -- 按 9   *
 *                      退出 ---------- 按 0   *
 ***********************************************
'''

    while True:
        data_source = 0
        ds_APNIC.ext = 0

        path = select_path(ipdb1, ipdb2)
        if path:
            ipdb = path
        else:
            continue

        ns = input(Tips2)
        try:
            ns = set(int(n) for n in ns)
        except:
            print('输入错误！')
            continue
        if 0 in ns:
            break
        if 9 in ns:
            test(ipdb)
            continue
        if 6 in ns:
            data_source = data_source_manager.sign_all
        else:
            if 1 in ns:
                data_source |= ds_APNIC
            if 2 in ns:
                data_source |= ds_17MON
            if 3 in ns:
                data_source |= ds_GAOYIFAN
            if 7 in ns:
                ds_APNIC.set('mo')
            if 8 in ns:
                ds_APNIC.set('hk')
        if data_source == 0:
            print('输入错误！')
            continue

        download_cniplist_as_db(ipdb, data_source)
