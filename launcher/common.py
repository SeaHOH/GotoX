#!/usr/bin/env python3
# coding: utf-8

import os
import sys
import ssl
import time
import socket
from urllib.request import urlopen


__file__ = os.path.abspath(__file__)
if os.path.islink(__file__):
    __file__ = getattr(os, 'readlink', lambda x: x)(__file__)
file_dir = os.path.dirname(__file__)
root_dir = os.path.dirname(file_dir)
# GotoX CA
ca1 = os.path.join(root_dir, 'cert', 'CA.crt')
# APNIC 和 GitHub 使用的 CA
ca2 = os.path.join(root_dir, 'cert', 'cacert-get-iprange.pem')
context = None
logging = None
p_ALL = (1 << 7) - 1

def download(req):
    #显式加载 CA，确保正常使用
    global context
    if context is None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.set_ciphers(ssl._RESTRICTED_SERVER_CIPHERS)
        if os.path.exists(ca1):
            context.load_verify_locations(ca1)
        context.load_verify_locations(ca2)
    retry_delay = 2
    max_retries = 10
    retry_times = 0
    timeout = 8
    l = 0
    while l is 0:
        fd = None
        err = None
        try:
            fd = urlopen(req, timeout=timeout, context=context)
            l = int(fd.headers.get('Content-Length', 0))
        except Exception as e:
            err = e
        if l is 0:
            if fd:
                fd.close()
            retry_times += 1
            if retry_times > max_retries:
                logging.warning('请求网址 %r 时，重试 %d 次后仍然失败。'
                                % (req.full_url, max_retries))
                logging.warning('请忽略下面这个错误跟踪，并检查是否需要'
                                '更改自动代理规则（ActionFilter.ini）。')
                #利用错误抛出终止线程
                raise OSError('链接失败', 0) if err is None else err
            logging.debug('链接直连 IP 库网址失败，%d 秒后重试' % retry_delay)
            time.sleep(retry_delay)
    return fd, l

def download_safe(name, parser, req):
    #支持续传
    logging.info('开始下载 %s IP' % name)
    req.headers['Range'] = 'bytes=0-'
    read = 0
    itemlist = []
    l = None
    while read != l:
        fd, _l = download(req)
        if l is None:
            l = _l
        _read = parser(fd, itemlist)
        if _read is None:
            read = l
        else:
            read += _read
        fd.close()
        #下载失败续传
        if read != l:
            #往回跳过可能的缺损条目
            read = max(read - 100, 0)
            req.headers['Range'] = 'bytes=%d-' % read
            logging.debug('%s 下载中断，续传：%d/%d' % (name, read, l))
    logging.info(name + ' 下载完毕')
    return itemlist


def get_data_source(data_source_valid):
    data_source = 0
    if '--all' in sys.argv:
        data_source = p_ALL
    else:
        for par in data_source_valid:
            if par in sys.argv:
                data_source |= data_source_valid[par]
    return data_source

def set_proxy(proxy_addr):
    try:
        ip, port = proxy_addr.split(':')
        socket.create_connection((ip, int(port)), timeout=1).close()
        os.environ['HTTPS_PROXY'] = os.environ['HTTP_PROXY'] = proxy_addr
        logging.info('\n代理地址 %r 已设置成功。' % proxy_addr)
        return True
    except:
        os.environ.pop('HTTP_PROXY', None)
        os.environ.pop('HTTPS_PROXY', None)

def parse_set_proxy():
    if '-p' in sys.argv:
        try:
            proxy_addr = sys.argv[sys.argv.index('-p') + 1]
        except IndexError:
            print('\n代理地址读取失败，退出脚本...')
            sys.exit(-1)
        if set_proxy(proxy_addr):
            use_proxy = None
        else:
            print('\n代理地址 %r 设置失败，退出脚本...' % proxy_addr)
            sys.exit(-1)
        if data_source == 0:
            print('进入交互模式\n')
    elif '-d' in sys.argv:
        use_proxy = False
        if data_source == 0:
            print('进入交互模式\n')
    else:
        use_proxy = input('进入交互模式\n\n是否设置代理（Y/N）：')
        use_proxy = use_proxy.upper() == 'Y'

    if use_proxy:
        print('\n开始设置代理，仅支持 HTTP 代理，格式："主机名(IP 或域名):端口"')
    while use_proxy:
        proxy_addr = input('\n请输入代理地址，'
                     '留空使用 "127.0.0.1:8087"：\n') or '127.0.0.1:8087'
        if set_proxy(proxy_addr):
            break
        else:
            use_proxy = input('\n当前代理 %r 无法链接，是否继续设置代理（Y/N）：' % proxy_addr)
            use_proxy = use_proxy.upper() == 'Y'
    if use_proxy is False:
        print('\n跳过代理设置')
    return use_proxy

Tips1 = '''
 ***********************************************
 *   请选择存放目录：                          *
 *                      数据目录 ------ 按 1   *
 *                      当前目录 ------ 按 2   *
 *                      退出 ---------- 按 0   *
 ***********************************************
'''

def select_path(*path):
    n = input(Tips1)
    try:
        n = int(n)
    except:
        print('输入错误！')
        return
    if n is 0:
        sys.exit(0)
    elif n is 1:
        return path[0]
    elif n is 2:
        return path[1]
    else:
        print('输入错误！')

def getlogger(is_main):
    global logging
    if logging is None:
        if is_main:
            class logging:
                warning = info = debug = print
        else:
            import local.clogging as logging
    return logging
