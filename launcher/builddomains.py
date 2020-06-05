#!/usr/bin/env python3
# coding: utf-8

import os
import sys
sys.dont_write_bytecode = True

import time
import socket
from common import (
    file_dir, direct_domains, DataSourceManager, download_as_list,
    parse_set_proxy, select_path, getlogger
    )


Url_FCHINA = 'https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf'
Url_FAPPLE = 'https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/apple.china.conf'
downloading = False

def save_domains_as_txt(txt, domains_list):
    with open(txt, 'wb') as fd:
        for domain in domains_list:
            fd.write(domain)
            fd.write(b'\n')

def parse_dnsmasq_domains(fd, ds):
    read = 0
    try:
        for line in fd:
            read += len(line)
            if line[:1] in b'#;':
                continue
            linesp = line.split(b'/')
            if len(linesp) == 3:
                ds.itemlist.append(linesp[1])
    except Exception as e:
        logging.warning('parse_dnsmasq_domains 解析出错：%s', e)
    return read

def download_domains_as_txt(txt, p=1):
    global downloading
    if downloading:
        msg = '已经有更新直连域名列表的任务正在进行中，请稍后再试'
        logging.warning(msg)
        return msg
    downloading = True
    #数据将保存为文本，使用容易阅读的日期格式
    update = time.strftime('%Y-%m-%d', time.localtime(time.time()))
    count = 0
    domains_list = []
    domains_list.append(b'# Update: ' + update.encode())

    def add(ds):
        nonlocal count
        download_as_list(ds)
        domains_list.append(b'')
        domains_list.append(b'# ' + ds.fullname.encode())
        domains_list.append(b'# ' + ds.url.encode())
        domains_list.extend(ds.itemlist)
        count += len(ds.itemlist)

    try:
        for ds in data_source_manager.sources():
            if p & ds:
                for child_ds in ds.get_children():
                    if ds.check(child_ds.name):
                        add(child_ds)
                add(ds)

        domains_list.append(b'')
        domains_list.append(b'#end')
        save_domains_as_txt(txt, domains_list)
        logging.debug('更新信息：%s' % update)
        logging.debug('包含域名条目数：%s' % count)
        logging.debug('保存地址：%s' % txt)
        logging.info('直连域名列表已保存完毕')
    except Exception as e:
        logging.warning('更新直连域名列表 %r 失败：%s' % (txt, e))
    finally:
        downloading = False
        data_source_manager.clear_source_data()

data_source_manager = DataSourceManager()
ds_FELIX = data_source_manager.add('Felix', Url_FCHINA, parse_dnsmasq_domains, 'felixonmars/accelerated-domains.china')
ds_FAPPLE = ds_FELIX.add_child('Apple', Url_FAPPLE, fullname='felixonmars/apple.china')

is_main = __name__ == '__main__'
logging = getlogger(is_main)

if is_main:
    if len(sys.argv) < 2:
        print('使用 "--help" 可查看命令行参数说明\n')
    if '--help' in sys.argv:
        print('''
用法：
    --help     显示此使用提示
    -u         生成的直连域名列表文件不放入脚本目录而是更新到相邻的 data 目录
               交互模式下参数 "-u" 无效

    指定可用数据源，交互模式中无效

    --felix[ apple]
               使用 felixonmars 数据源
                 apple 保存 felixonmars/apple 数据源
    --all      使用以上全部数据源

    指定数据源并配合以下参数时不会进入交互模式，适用于自动／无人职守模式

    -d         跳过代理设置使用直连，使用参数 "-p" 时参数 "-d" 无效
    -p 主机名(IP 或域名):端口
               非交互模式使用 HTTP 代理，无效地址或无法链接代理时会直接结束脚本

''')

    txt1 = direct_domains
    txt2 = os.path.join(file_dir, 'directdomains.txt')
    data_source = data_source_manager.get_source(*sys.argv)
    if parse_set_proxy(data_source) is None:
        txt = txt1 if '-u' in sys.argv else txt2
        download_domains_as_txt(txt, data_source)
        sys.exit(0)

    Tips2 = '''
 ***********************************************
 *   请选择数据来源，可多选：                  *
 *                   felixonmars ------ 按 1   *
 *                   保存 apple 数据 -- 按 7   *
 *                      全部 ---------- 按 8   *
 *                      测试空白列表 -- 按 9   *
 *                      退出 ---------- 按 0   *
 ***********************************************
'''

    while True:
        data_source = 0
        ds_FELIX.ext = 0

        path = select_path(txt1, txt2)
        if path:
            txt = path
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
            download_domains_as_txt(txt, 0)
            continue
        if 8 in ns:
            data_source = data_source_manager.sign_all
        else:
            if 1 in ns:
                data_source |= ds_FELIX
            if 7 in ns:
                ds_FELIX.set('apple')
        if data_source == 0:
            print('输入错误！')
            continue

        download_domains_as_txt(txt, data_source)
