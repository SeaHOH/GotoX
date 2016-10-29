#!/usr/bin/env python
# coding:utf-8
# Based on GoAgent   3.1.5 by Phus Lu <phus.lu@gmail.com>
# Based on GAppProxy 2.0.0 by Du XiaoGang <dugang.2008@gmail.com>
# Based on WallProxy 0.4.0 by Hust Moon <www.ehust@gmail.com>
# Contributor:
#      SeaHOH          <seahoh@gmail.com>

__version__ = '3.3.0'

import os
import sys
sys.dont_write_bytecode = True

#这条代码负责导入依赖库路径，不要改变位置
from .common import NetWorkIOError

from . import clogging as logging
try:
    import gevent
    import gevent.socket
    import gevent.server
    import gevent.queue
    import gevent.monkey
    gevent.monkey.patch_all(subprocess=True)
except ImportError:
    gevent = None
except TypeError:
    gevent.monkey.patch_all()
    logging.warning(u'警告：请更新 gevent 至 1.0 以上版本！')

import errno
import struct
import threading
import socket
import ssl
import re
import dnslib
import OpenSSL
from .compat import (
    Queue,
    thread,
    SocketServer,
    xrange
    )
from .GlobalConfig import GC
from .ProxyHandler import GAEProxyHandler, AutoProxyHandler


class LocalProxyServer(SocketServer.ThreadingTCPServer):
    """Local Proxy Server"""
    allow_reuse_address = True

    def close_request(self, request):
        try:
            request.close()
        except Exception:
            pass

    def finish_request(self, request, client_address):
        try:
            self.RequestHandlerClass(request, client_address, self)
        except NetWorkIOError as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise

    def handle_error(self, *args):
        """make ThreadingTCPServer happy"""
        exc_info = sys.exc_info()
        error = exc_info and len(exc_info) and exc_info[1]
        if isinstance(error, NetWorkIOError) and len(error.args) > 1 and 'bad write retry' in error.args[1]:
            exc_info = error = None
        else:
            del exc_info, error
            SocketServer.ThreadingTCPServer.handle_error(self, *args)

def main():
    def pre_start():
        from .common import isip, isipv4, isipv6
        from .common.dns import dns, dns_remote_resolve
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
            for i in xrange(ips):
                start = (i+1) * 4
                out.append(socket.inet_ntoa(buf[start:start+4]))
            return out

        def resolve_iplist():
            def do_resolve(host, dnsservers, queue):
                try:
                    iplist = dns_remote_resolve(host, dnsservers, GC.DNS_BLACKLIST, timeout=2)
                    queue.put((host, dnsservers, iplist or []))
                except (socket.error, OSError) as e:
                    logging.error(u'远程解析失败：host=%r，%r', host, e)
                    queue.put((host, dnsservers, []))
            # https://support.google.com/websearch/answer/186669?hl=zh-Hans
            google_blacklist = ['216.239.32.20', '74.125.127.102', '74.125.155.102', '74.125.39.102', '74.125.39.113', '209.85.229.138']
            for name, need_resolve_hosts in list(GC.IPLIST_MAP.items()):
                if all(isip(x) for x in need_resolve_hosts):
                    continue
                need_resolve_remote = [x for x in need_resolve_hosts if ':' not in x and not isipv4(x)]
                resolved_iplist = [x for x in need_resolve_hosts if x not in need_resolve_remote]
                result_queue = Queue.Queue()
                for host in need_resolve_remote:
                    for dnsserver in GC.DNS_SERVERS:
                        logging.debug(u'远程解析开始：host=%r，dns=%r', host, dnsserver)
                        threading._start_new_thread(do_resolve, (host, [dnsserver], result_queue))
                for _ in xrange(len(GC.DNS_SERVERS) * len(need_resolve_remote)):
                    try:
                        host, dnsservers, iplist = result_queue.get(timeout=2)
                        resolved_iplist += iplist or []
                        logging.debug(u'远程解析成功：host=%r，dns=%s，iplist=%s', host, dnsservers, iplist)
                    except Queue.Empty:
                        logging.warn(u'远程解析超时，尝试本地解析')
                        resolved_iplist += sum([socket.gethostbyname_ex(x)[-1] for x in need_resolve_remote], [])
                        break
                if name.startswith('google_') and name not in ('google_cn', 'google_hk'):
                    iplist_prefix = re.split(r'[\.:]', resolved_iplist[0])[0]
                    resolved_iplist = list(set(x for x in resolved_iplist if x.startswith(iplist_prefix)))
                else:
                    resolved_iplist = list(set(resolved_iplist))
                if name.startswith('google_'):
                    resolved_iplist = list(set(resolved_iplist) - set(google_blacklist))
                if len(resolved_iplist) == 0:
                    logging.error(u'host 列表 %r 解析结果为空，请重试！', name)
                    sys.exit(-1)
                if GC.LINK_PROFILE == 'ipv4':
                    resolved_iplist = [ip for ip in resolved_iplist if isipv4(ip)]
                elif GC.LINK_PROFILE == 'ipv6':
                    resolved_iplist = [ip for ip in resolved_iplist if isipv6(ip)]
                logging.info(u'host 列表 %r 解析结果：iplist=%r', name, resolved_iplist)
                GC.IPLIST_MAP[name] = resolved_iplist

        def network_test():
            from time import sleep
            haserr = None
            b = None
            while not b:
                try:
                    b = socket.gethostbyname('baidu.com')
                except:
                    if not haserr:
                        haserr = True
                        logging.error(u'网络现在不可用，将每 10 秒检测一次……')
                    sleep(10)
            if haserr:
                logging.info(u'网络已经可以使用，初始化继续……')
            try:
                AutoProxyHandler.localhosts = tuple(set(sum((x if isinstance(x, list) else [x] for x in socket.gethostbyname_ex(socket.gethostname())), list(AutoProxyHandler.localhosts))))
                AutoProxyHandler.localhosts = tuple(set([get_listen_ip()] + list(AutoProxyHandler.localhosts)))
            except:
                pass

        network_test()
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
            ctypes.windll.kernel32.SetConsoleTitleW(u'GotoX v%s' % __version__)
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
                    title = u'GotoX 建议'
                    error = u'某些安全软件(如 %s)可能和本软件存在冲突，造成 CPU 占用过高。\n如有此现象建议暂时退出此安全软件来继续运行 GotoX' % ','.join(softwares)
                    ctypes.windll.user32.MessageBoxW(None, error, title, 0)
                    #sys.exit(0)
        if not GC.GAE_APPIDS or GC.GAE_APPIDS[0] == 'gotox':
            logging.critical(u'请编辑 %r 文件，添加你的 appid 到 [gae] 配置中！', GC.CONFIG_FILENAME)
            sys.exit(-1)
        if os.name == 'nt' and not GC.DNS_ENABLE:
            any(GC.DNS_SERVERS.insert(0, x) for x in [y for y in win32dns_query_dnsserver_list() if y not in GC.DNS_SERVERS])
        if not GC.PROXY_ENABLE:
            logging.info(u'开始将 GC.IPLIST_MAP names=%s 解析为 IP 列表', list(GC.IPLIST_MAP))
            resolve_iplist()
        if 'uvent.loop' in sys.modules and isinstance(gevent.get_hub().loop, __import__('uvent').loop.UVLoop):
            logging.info('Uvent enabled, patch forward_socket')
            AutoProxyHandler.forward_socket = AutoProxyHandler.green_forward_socket
        for appid in GC.GAE_APPIDS:
            host = '%s.appspot.com' % appid
            dns[host] = GC.IPLIST_MAP[GC.GAE_LISTNAME]

    logging.disable(0 if GC.LISTEN_DEBUGINFO else logging.DEBUG)
    if 0: #测试用
        GC.LISTEN_AUTO_PORT = 1111
        GC.LISTEN_GAE_PORT = 1112
        GC.LINK_OPENSSL = 1
        #GC.IPLIST_MAP[GC.GAE_LISTNAME] = []
    info = '==================================================================================\n'
    info += u'* GotoX  版 本 : %s (python/%s %spyopenssl/%s)\n' % (__version__, sys.version.split(' ')[0], gevent and 'gevent/%s ' % gevent.__version__ or '', getattr(OpenSSL, '__version__', 'Disabled'))
    info += '* Uvent Version    : %s (pyuv/%s libuv/%s)\n' % (__import__('uvent').__version__, __import__('pyuv').__version__, __import__('pyuv').LIBUV_VERSION) if all(x in sys.modules for x in ('pyuv', 'uvent')) else ''
    info += '* GAE    APPID : %s\n' % '|'.join(GC.GAE_APPIDS)
    info += u'* GAE 远程验证 : %s\n' % u'已启用' if GC.GAE_SSLVERIFY else u'未启用'
    info += u'*  监 听 地 址 : 自动代理 - %s:%d\n' % (GC.LISTEN_IP, GC.LISTEN_AUTO_PORT)
    info += u'*                GAE 代理 - %s:%d\n' % (GC.LISTEN_IP, GC.LISTEN_GAE_PORT)
    info += '* Local Proxy  : %s:%s\n' % (GC.PROXY_HOST, GC.PROXY_PORT) if GC.PROXY_ENABLE else ''
    info += '* Debug INFO   : %s\n' % GC.LISTEN_DEBUGINFO if GC.LISTEN_DEBUGINFO else ''
    info += u'*  链 接 模 式 : 远程 - %s/%s\n' % (GC.LINK_REMOTESSLTXT, 'openssl' if GC.LINK_OPENSSL else 'gevent')
    info += u'*                本地 - %s/gevent\n' % GC.LINK_LOCALSSLTXT
    info += u'*  链接 配置集 : %s\n' % GC.LINK_PROFILE if GC.LINK_PROFILE else ''
    #if GC.PAC_ENABLE:
    #    info += '* Pac Server       : http://%s:%d/%s\n' % (GC.PAC_IP, GC.PAC_PORT, GC.PAC_FILE)
    #    info += '* Pac File         : file://%s\n' % os.path.join(cwdir, GC.PAC_FILE).replace('\\', '/')
    if GC.DNS_ENABLE:
        info += '* DNS Listen       : %s\n' % GC.DNS_LISTEN
        info += '* DNS Servers      : %s\n' % '|'.join(GC.DNS_SERVERS)
    info += u'*  安 装 证 书 : %s\n' % AutoProxyHandler.CAfile
    info += u'*  下 载 证 书 : %s 加任意字符\n' % AutoProxyHandler.CAfile
    info += '==================================================================================\n'
    sys.stdout.write(info)

    pre_start()
    del pre_start, info

    from . import CertUtil
    CertUtil.check_ca()

    from .GAEUpdata import testipserver
    thread.start_new_thread(testipserver, ())

    if GC.DNS_ENABLE:
        try:
            sys.path += ['.']
            from .dnsproxy import DNSServer
            host, port = GC.DNS_LISTEN.split(':')
            server = DNSServer((host, int(port)), dns_servers=GC.DNS_SERVERS, dns_blacklist=GC.DNS_BLACKLIST)
            thread.start_new_thread(server.serve_forever, ())
        except ImportError:
            logging.exception('GotoX DNSServer requires dnslib and gevent 1.0')
            sys.exit(-1)

    server = LocalProxyServer((GC.LISTEN_IP, GC.LISTEN_GAE_PORT), GAEProxyHandler)
    try:
        thread.start_new_thread(server.serve_forever, ())
    except SystemError as e:
        if ' (libev) select: Unknown error' in repr(e):
            logging.error('PLEASE START GotoX BY uvent.bat')
            sys.exit(-1)

    server = LocalProxyServer((GC.LISTEN_IP, GC.LISTEN_AUTO_PORT), AutoProxyHandler)
    try:
        server.serve_forever()
    except SystemError as e:
        if ' (libev) select: Unknown error' in repr(e):
            logging.error('PLEASE START GotoX BY uvent.bat')
            sys.exit(-1)

if __name__ == '__main__':
    main()
