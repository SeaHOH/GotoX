#!/usr/bin/env python3
# coding: utf-8

import os
import sys
sys.dont_write_bytecode = True

import time
import socket
from urllib.request import Request
from common import (
    file_dir, root_dir, p_ALL, download_safe, get_data_source,
    parse_set_proxy, select_path, getlogger
    )


Url_FCHINA = 'https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf'
Url_FAPPLE = 'https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/apple.china.conf'
Req_FCHINA = None
Req_FAPPLE = None
p_FCHINA = 1
p_FAPPLE = 1 << 1
downloading = False

def save_domains_as_txt(txt, domains_list):
    with open(txt, 'wb') as fd:
        for domain in domains_list:
            fd.write(domain)
            fd.write(b'\n')

def download_domains(parse_domains, url):
    global Req_FCHINA, Req_FAPPLE
    if url is Url_FCHINA:
        if Req_FCHINA is None:
            Req_FCHINA = Request(url)
        req = Req_FCHINA
        name = 'accelerated-domains.china.conf'
    elif url is Url_FAPPLE:
        if Req_FAPPLE is None:
            Req_FAPPLE = Request(url)
        req = Req_FAPPLE
        name = 'apple.china.conf'
    return download_safe(name, parse_domains, req)

def parse_domains(fd, domains_list):
    read = 0
    try:
        for line in fd:
            read += len(line)
            linesp = line.split(b'/')
            if len(linesp) == 3:
                domains_list.append(linesp[1])
    except:
        pass
    return read

def download_domains_as_txt(txt, p=p_FCHINA):
    global downloading
    if downloading:
        msg = '已经有更新直连域名列表任务正在进行中，请稍后再试'
        logging.warning(msg)
        return msg
    downloading = True
    update = time.strftime('%Y-%m-%d', time.localtime(time.time()))
    count = 0
    domains_list = []
    domains_list.append(b'# Update: ' + update.encode())

    try:
        if p & p_FAPPLE:
            domains_list.append(b'')
            domains_list.append(b'# apple.china')
            domains_list.append(b'# ' + Url_FAPPLE.encode())
            _domains_list = download_domains(parse_domains, Url_FAPPLE)
            domains_list.extend(_domains_list)
            count += len(_domains_list)

        if p & p_FCHINA:
            domains_list.append(b'')
            domains_list.append(b'# accelerated-domains.china')
            domains_list.append(b'# ' + Url_FCHINA.encode())
            _domains_list = download_domains(parse_domains, Url_FCHINA)
            domains_list.extend(_domains_list)
            count += len(_domains_list)

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

    --fchina   使用 felixonmars/accelerated-domains 数据源
    --fapple   使用 felixonmars/apple 数据源
    --all      使用以上全部数据源

    指定数据源并配合以下参数时不会进入交互模式，适用于自动／无人职守模式

    -d         跳过代理设置使用直连，使用参数 "-p" 时参数 "-d" 无效
    -p 主机名(IP 或域名):端口
               非交互模式使用 HTTP 代理，无效地址或无法链接代理时会直接结束脚本

''')

    txt1 = os.path.join(root_dir, 'data', 'directdomains.txt')
    txt2 = os.path.join(file_dir, 'directdomains.txt')
    data_source_valid = {
        '--fchina': p_FCHINA,
        '--fapple': p_FAPPLE
        }
    data_source = get_data_source(data_source_valid)
    if parse_set_proxy():
        data_source = 0
    if data_source:
        txt = txt1 if '-u' in sys.argv else txt2
        download_domains_as_txt(txt, data_source)
        sys.exit(0)

    Tips2 = '''
 ***********************************************
 *   请选择数据来源，可多选：                  *
 *   felixonmars/accelerated-domains -- 按 1   *
 *   felixonmars/apple ---------------- 按 2   *
 *                      全部 ---------- 按 8   *
 *                      测试空白列表 -- 按 9   *
 *                      退出 ---------- 按 0   *
 ***********************************************
'''

    while True:
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
            data_source = p_ALL
        else:
            if 1 in ns:
                data_source |= p_FCHINA
            if 2 in ns:
                data_source |= p_FAPPLE
        if data_source == 0:
            print('输入错误！')
            continue

        download_domains_as_txt(txt, data_source)
        data_source = 0
