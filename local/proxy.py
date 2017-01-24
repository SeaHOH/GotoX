#!/usr/bin/env python3
# coding:utf-8
# Homepage: https://github.com/SeaHOH/GotoX
# Based on GoAgent   3.1.5 by Phus Lu <phus.lu@gmail.com>
# Based on GAppProxy 2.0.0 by Du XiaoGang <dugang.2008@gmail.com>
# Based on WallProxy 0.4.0 by Hust Moon <www.ehust@gmail.com>
# Contributor:
#      SeaHOH            <seahoh@gmail.com>
#      Hewig Xu          <hewigovens@gmail.com>
#      Ayanamist Yang    <ayanamist@gmail.com>
#      V.E.O             <V.E.O@tom.com>
#      Max Lv            <max.c.lv@gmail.com>
#      AlsoTang          <alsotang@gmail.com>
#      Christopher Meng  <i@cicku.me>
#      Yonsm Guo         <YonsmGuo@gmail.com>
#      Parkman           <cseparkman@gmail.com>
#      Ming Bai          <mbbill@gmail.com>
#      Bin Yu            <yubinlove1991@gmail.com>
#      lileixuan         <lileixuan@gmail.com>
#      Cong Ding         <cong@cding.org>
#      Zhang Youfu       <zhangyoufu@gmail.com>
#      Lu Wei            <luwei@barfoo>
#      Harmony Meow      <harmony.meow@gmail.com>
#      logostream        <logostream@gmail.com>
#      Rui Wang          <isnowfy@gmail.com>
#      Wang Wei Qiang    <wwqgtxx@gmail.com>
#      Felix Yan         <felixonmars@gmail.com>
#      Sui Feng          <suifeng.me@qq.com>
#      QXO               <qxodream@gmail.com>
#      Geek An           <geekan@foxmail.com>
#      Poly Rabbit       <mcx_221@foxmail.com>
#      oxnz              <yunxinyi@gmail.com>
#      Shusen Liu        <liushusen.smart@gmail.com>
#      Yad Smood         <y.s.inside@gmail.com>
#      Chen Shuang       <cs0x7f@gmail.com>
#      cnfuyu            <cnfuyu@gmail.com>
#      cuixin            <steven.cuixin@gmail.com>
#      s2marine0         <s2marine0@gmail.com>
#      Toshio Xiang      <snachx@gmail.com>

__version__ = '3.3.3'

import sys
sys.dont_write_bytecode = True

#这条代码负责导入依赖库路径，不要改变位置
from .common import gevent

import os
import struct
import threading
import socket
import ssl
import re
from OpenSSL import __version__ as opensslver
from . import clogging as logging
from .compat import Queue, thread, SocketServer
from .GlobalConfig import GC
from .ProxyServer import start_proxyserver
from .ProxyHandler import AutoProxyHandler

def main():
    def pre_start():
        from .ProxyServer import network_test
        from .common import isip, isipv4, isipv6
        from .common.dns import dns, _dns_remote_resolve as dns_remote_resolve
        def get_process_list():
            import collections
            Process = collections.namedtuple('Process', 'pid name exe')
            process_list = []
            if os.name == 'nt':
                import ctypes
                PROCESS_QUERY_INFORMATION = 0x0400
                PROCESS_VM_READ = 0x0010
                lpidProcess= (ctypes.c_ulong * 1024)()
                cb = ctypes.sizeof(lpidProcess)
                cbNeeded = ctypes.c_ulong()
                ctypes.windll.psapi.EnumProcesses(ctypes.byref(lpidProcess), cb, ctypes.byref(cbNeeded))
                nReturned = cbNeeded.value/ctypes.sizeof(ctypes.c_ulong())
                pidProcess = [i for i in lpidProcess][:nReturned]
                has_queryimage = hasattr(ctypes.windll.kernel32, 'QueryFullProcessImageNameA')
                for pid in pidProcess:
                    hProcess = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid)
                    if hProcess:
                        modname = ctypes.create_string_buffer(2048)
                        count = ctypes.c_ulong(ctypes.sizeof(modname))
                        if has_queryimage:
                            ctypes.windll.kernel32.QueryFullProcessImageNameA(hProcess, 0, ctypes.byref(modname), ctypes.byref(count))
                        else:
                            ctypes.windll.psapi.GetModuleFileNameExA(hProcess, 0, ctypes.byref(modname), ctypes.byref(count))
                        exe = modname.value
                        name = os.path.basename(exe)
                        process_list.append(Process(pid=pid, name=name, exe=exe))
                        ctypes.windll.kernel32.CloseHandle(hProcess)
            elif sys.platform.startswith('linux'):
                import glob
                for filename in glob.glob('/proc/[0-9]*/cmdline'):
                    pid = int(filename.split('/')[2])
                    exe_link = '/proc/%d/exe' % pid
                    if os.path.exists(exe_link):
                        exe = os.readlink(exe_link)
                        name = os.path.basename(exe)
                        process_list.append(Process(pid=pid, name=name, exe=exe))
            else:
                try:
                    import psutil
                    process_list = psutil.get_process_list()
                except Exception as e:
                    logging.exception('psutil.get_process_list() failed: %r', e)
            return process_list

        def win32dns_query_dnsserver_list():
            import ctypes, ctypes.wintypes
            DNS_CONFIG_DNS_SERVER_LIST = 6
            buf = ctypes.create_string_buffer(2048)
            ctypes.windll.dnsapi.DnsQueryConfig(DNS_CONFIG_DNS_SERVER_LIST, 0, None, None, ctypes.byref(buf), ctypes.byref(ctypes.wintypes.DWORD(len(buf))))
            ips = struct.unpack('I', buf[0:4])[0]
            out = []
            for i in range(ips):
                start = (i+1) * 4
                out.append(socket.inet_ntoa(buf[start:start+4]))
            return out

        def resolve_iplist():
            def do_resolve(host, dnsservers, queue):
                try:
                    iplist = dns_remote_resolve(host, dnsservers, GC.DNS_BLACKLIST, timeout=2)
                    queue.put((host, dnsservers, iplist or []))
                except (socket.error, OSError) as e:
                    logging.error('远程解析失败：host=%r，%r', host, e)
                    queue.put((host, dnsservers, []))
            # https://support.google.com/websearch/answer/186669?hl=zh-Hans
            google_blacklist = ['216.239.32.20', '74.125.127.102', '74.125.155.102', '74.125.39.102', '74.125.39.113', '209.85.229.138']
            for name, need_resolve_hosts in list(GC.IPLIST_MAP.items()):
                if name in ('google_gws', 'google_com', 'google_yt', 'google_gs') or all(isip(x) for x in need_resolve_hosts):
                    continue
                need_resolve_remote = [x for x in need_resolve_hosts if ':' not in x and not isipv4(x)]
                resolved_iplist = [x for x in need_resolve_hosts if x not in need_resolve_remote]
                result_queue = Queue.Queue()
                for host in need_resolve_remote:
                    for dnsserver in GC.DNS_SERVERS:
                        logging.debug('远程解析开始：host=%r，dns=%r', host, dnsserver)
                        threading._start_new_thread(do_resolve, (host, [dnsserver], result_queue))
                for _ in range(len(GC.DNS_SERVERS) * len(need_resolve_remote)):
                    try:
                        host, dnsservers, iplist = result_queue.get(timeout=2)
                        resolved_iplist += iplist or []
                        logging.debug('远程解析成功：host=%r，dns=%s，iplist=%s', host, dnsservers, iplist)
                    except Queue.Empty:
                        logging.warn('远程解析超时，尝试本地解析')
                        resolved_iplist += sum([socket.gethostbyname_ex(x)[-1] for x in need_resolve_remote], [])
                        break
                if name.startswith('google_'):
                    iplist_prefix = re.split(r'[\.:]', resolved_iplist[0])[0]
                    resolved_iplist = list(set(x for x in resolved_iplist if x.startswith(iplist_prefix)))
                else:
                    resolved_iplist = list(set(resolved_iplist))
                if name.startswith('google_'):
                    resolved_iplist = list(set(resolved_iplist) - set(google_blacklist))
                if len(resolved_iplist) == 0:
                    logging.warning('自定义 host 列表 %r 解析结果为空，请检查你的配置 %r。', name, GC.CONFIG_FILENAME)
                    sys.exit(-1)
                if GC.LINK_PROFILE == 'ipv4':
                    resolved_iplist = [ip for ip in resolved_iplist if isipv4(ip)]
                elif GC.LINK_PROFILE == 'ipv6':
                    resolved_iplist = [ip for ip in resolved_iplist if isipv6(ip)]
                logging.info('host 列表 %r 解析结果：iplist=%r', name, resolved_iplist)
                GC.IPLIST_MAP[name] = resolved_iplist

        network_test(True)
        if sys.platform == 'cygwin':
            logging.info('cygwin is not officially supported, please continue at your own risk :)')
            #sys.exit(-1)
        elif os.name == 'posix':
            try:
                import resource
                resource.setrlimit(resource.RLIMIT_NOFILE, (8192, -1))
            except ValueError:
                pass
        elif os.name == 'nt':
            import ctypes
            ctypes.windll.kernel32.SetConsoleTitleW('GotoX v%s' % __version__)
            if not GC.LISTEN_VISIBLE:
                ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
            else:
                ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 1)
        elif 0:
            blacklist = {'360safe': False,
                         'QQProtect': False, }
            softwares = [k for k, v in blacklist.items() if v]
            if softwares:
                tasklist = '\n'.join(x.name for x in get_process_list()).lower()
                softwares = [x for x in softwares if x.lower() in tasklist]
                if softwares:
                    title = 'GotoX 建议'
                    error = '某些安全软件(如 %s)可能和本软件存在冲突，造成 CPU 占用过高。\n如有此现象建议暂时退出此安全软件来继续运行 GotoX' % ','.join(softwares)
                    ctypes.windll.user32.MessageBoxW(None, error, title, 0)
                    #sys.exit(0)
        if not GC.GAE_APPIDS or GC.GAE_APPIDS[0] == 'gotox':
            logging.critical('请编辑 %r 文件，添加你的 appid 到 [gae] 配置中！', GC.CONFIG_FILENAME)
            sys.exit(-1)
        if os.name == 'nt':
            any(GC.DNS_SERVERS.insert(0, x) for x in [y for y in win32dns_query_dnsserver_list() if y not in GC.DNS_SERVERS])
        if not GC.PROXY_ENABLE:
            #logging.info('开始将 GC.IPLIST_MAP names=%s 解析为 IP 列表', list(GC.IPLIST_MAP))
            resolve_iplist()
        #if 'uvent.loop' in sys.modules and isinstance(gevent.get_hub().loop, __import__('uvent').loop.UVLoop):
        #    logging.info('Uvent enabled, patch forward_socket')
        #    AutoProxyHandler.forward_socket = AutoProxyHandler.green_forward_socket

    logging.setLevel(GC.LISTEN_DEBUGINFO)

    info = '==================================================================================\n'
    info += '* GotoX  版 本 : %s (python/%s %spyOpenSSL/%s)\n' % (__version__, sys.version.split(' ')[0], gevent and 'gevent/%s ' % gevent.__version__ or '', opensslver)
    #info += '* Uvent Version    : %s (pyuv/%s libuv/%s)\n' % (__import__('uvent').__version__, __import__('pyuv').__version__, __import__('pyuv').LIBUV_VERSION) if all(x in sys.modules for x in ('pyuv', 'uvent')) else ''
    info += '* GAE    APPID : %s\n' % '|'.join(GC.GAE_APPIDS)
    info += '* GAE 远程验证 : %s启用\n' % '已' if GC.GAE_SSLVERIFY else '未'
    info += '*  监 听 地 址 : 自动代理 - %s:%d\n' % (GC.LISTEN_IP, GC.LISTEN_AUTO_PORT)
    info += '*                GAE 代理 - %s:%d\n' % (GC.LISTEN_IP, GC.LISTEN_GAE_PORT)
    info += '* Local Proxy  : %s:%s\n' % (GC.PROXY_HOST, GC.PROXY_PORT) if GC.PROXY_ENABLE else ''
    info += '*  调 试 信 息 : %s\n' % logging._levelToName[GC.LISTEN_DEBUGINFO]
    info += '*  链 接 模 式 : 远程 - %s/%s\n' % (GC.LINK_REMOTESSLTXT, 'OpenSSL' if GC.LINK_OPENSSL else 'gevent')
    info += '*                本地 - %s/gevent\n' % GC.LINK_LOCALSSLTXT
    info += '*  链接 配置集 : %s\n' % GC.LINK_PROFILE if GC.LINK_PROFILE else ''
    info += '*  安 装 证 书 : %s\n' % AutoProxyHandler.CAfile
    info += '*  下 载 证 书 : %s 加任意字符\n' % AutoProxyHandler.CAfile
    info += '==================================================================================\n'
    sys.stdout.write(info)

    pre_start()
    del pre_start, info

    from . import CertUtil
    CertUtil.check_ca()

    start_proxyserver()

    if GC.GAE_USEGWSIPLIST:
        from .GAEUpdata import testipserver
        testipserver()
    else:
        logging.warning('正在使用固定的 GAE IP 列表［%s］，将不会进行 IP 检查。', GC.GAE_IPLIST)
        from time import sleep
        while True:
            sleep(9)

if __name__ == '__main__':
    main()
