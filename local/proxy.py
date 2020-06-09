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
# Compatible:
#      phuslu's GoProxy GAE Server (removed)
#          https://github.com/phuslu/goproxy/tree/server.gae

from . import __version__

import sys
sys.dont_write_bytecode = True

#这条代码负责添加依赖库路径，不要改变位置
from . import compat
compat.single_instance('gotox.server')
compat.init()

import logging
from .GlobalConfig import GC

try:
    from gevent import __version__ as geventver
except ImportError:
    geventver = None
else:
    GC.GEVENT_LOOP = compat.get_looptype()
    if GC.GEVENT_LOOP != 'none':
        if GC.MISC_REVERTGEVENTPATCH:
            compat.monkey_patch.revert_gevent_socket_patch()
        elif GC.MISC_GEVENTPATCH:
            compat.monkey_patch.patch_gevent_socket()

log_config = {'level': GC.LOG_LEVEL}
if not GC.LOG_PRINT:
    log_config['stream'] = logging.NULL_STREAM
if GC.LOG_SAVE:
    logfile = logging.LogFile(GC.LOG_FILE, maxsize=GC.LOG_FILESIZE, rotation=GC.LOG_ROTATION)
    log_config['logfile'] = logfile
logging.basicConfig(**log_config)

import os
import queue
from time import sleep
from threading import _start_new_thread as start_new_thread
from OpenSSL import __version__ as opensslver
from .common.cert import check_ca
from .common.dns import _dns_resolve as dns_resolve
from .common.net import isip, isipv4, isipv6
from .common.path import icon_gotox
from .common.region import IPDBVer, DDTVer
from .ProxyServer import network_test, start_proxyserver
from . import GIPManager

def main():
    def pre_start():
        def get_process_list():
            process_list = []
            if os.name != 'nt':
                return process_list
            import ctypes
            import collections
            Process = collections.namedtuple('Process', 'filename name')
            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010
            lpidProcess= (ctypes.c_ulong * 1024)()
            cb = ctypes.sizeof(lpidProcess)
            cbNeeded = ctypes.c_ulong()
            ctypes.windll.psapi.EnumProcesses(ctypes.byref(lpidProcess), cb, ctypes.byref(cbNeeded))
            nReturned = cbNeeded.value//ctypes.sizeof(ctypes.c_ulong())
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
                    path = modname.value.decode('mbcs')
                    filename = os.path.basename(path)
                    name, ext = os.path.splitext(filename)
                    process_list.append(Process(filename=filename, name=name))
                    ctypes.windll.kernel32.CloseHandle(hProcess)
            return process_list

        def resolve_iplist():
            def do_resolve(host, queobj):
                try:
                    iplist = dns_resolve(host)
                    queobj.put((host, iplist))
                except OSError as e:
                    logging.error('自定义 IP 列表解析失败：host=%r，%r', host, e)
                    queobj.put((host, None))
            # https://support.google.com/websearch/answer/186669?hl=zh-Hans
            # forcesafesearch.google.com
            google_blacklist = ['216.239.38.120', '2001:4860:4802:32::78']
            for name, need_resolve_hosts in list(GC.IPLIST_MAP.items()):
                if name in ('google_gae', 'google_gws'):
                    continue
                resolved_iplist = [x for x in need_resolve_hosts if isip(x)]
                need_resolve_hosts = [x for x in need_resolve_hosts if '.' in x and x not in resolved_iplist]
                if not need_resolve_hosts:
                    continue
                if GC.LINK_PROFILE == 'ipv4':
                    resolved_iplist = [ip for ip in resolved_iplist if isipv4(ip)]
                elif GC.LINK_PROFILE == 'ipv6':
                    resolved_iplist = [ip for ip in resolved_iplist if isipv6(ip)]
                result_queue = queue.Queue()
                for host in need_resolve_hosts:
                    logging.debug('自定义 IP 列表解析开始：host=%r', host)
                    start_new_thread(do_resolve, (host, result_queue))
                for _ in need_resolve_hosts:
                    host, iplist = result_queue.get()
                    if iplist:
                        resolved_iplist += iplist
                        logging.debug('自定义 IP 列表解析成功：host=%r，iplist=%s', host, iplist)
                if name.startswith('google_'):
                    resolved_iplist = list(set(resolved_iplist) - set(google_blacklist))
                else:
                    resolved_iplist = list(set(resolved_iplist))
                if len(resolved_iplist) == 0:
                    logging.warning('自定义 IP 列表 %r 解析结果为空，请检查你的配置 %r。', name, GC.CONFIG_FILENAME)
                else:
                    logging.info('IP 列表 %r 解析结果：iplist=%r', name, resolved_iplist)
                GC.IPLIST_MAP[name] = resolved_iplist

        network_test(first=True)
        if sys.platform == 'cygwin':
            logging.info('cygwin is not officially supported, please continue at your own risk :)')
        elif os.name == 'posix':
            try:
                import resource
                resource.setrlimit(resource.RLIMIT_NOFILE, (8192, -1))
            except ValueError:
                pass
        elif os.name == 'nt':
            import ctypes
            ctypes.windll.kernel32.SetConsoleTitleW('GotoX v%s' % __version__)
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if os.path.exists(icon_gotox):
                hicon = ctypes.windll.user32.LoadImageW(0, icon_gotox, 1, 0, 0, 16)
                if hicon == 0:
                    logging.warning('加载图标文件“GotoX.ico”失败。')
                else:
                    ctypes.windll.user32.SendMessageW(hwnd, 128, 0, hicon) #窗口
                    ctypes.windll.user32.SendMessageW(hwnd, 128, 1, hicon) #任务栏
            else:
                logging.warning('图标文件“GotoX.ico”丢失。')
            ctypes.windll.user32.ShowWindow(hwnd, int(GC.LOG_VISIBLE))
            if GC.MISC_CHECKPROCESS:
                blacklist = {
                    'BaiduSdSvc'   : '百毒',
                    'BaiduSdTray'  : '百毒',
                    'BaiduSd'      : '百毒',
                    'BaiduAn'      : '百毒',
                    'bddownloader' : '百毒',
                    'baiduansvx'   : '百毒',
                    '360sd'        : '360',
                    '360tray'      : '360',
                    '360Safe'      : '360',
                    'safeboxTray'  : '360',
                    '360safebox'   : '360',
                    '360se'        : '360',
                    'QQPCRTP'      : 'QQ',
                    'QQPCTray'     : 'QQ',
                    'QQProtect'    : 'QQ',
                    'kismain'      : '金山',
                    'ksafe'        : '金山',
                    'KSafeSvc'     : '金山',
                    'KSafeTray'    : '金山',
                    'KAVStart'     : '金山',
                    'KWatch'       : '金山',
                    'KMailMon'     : '金山',
                    'rstray'       : '瑞星',
                    'ravmond'      : '瑞星',
                    'rsmain'       : '瑞星',
                    'UIHost'       : '江民',
                    'KVMonXP'      : '江民',
                    'kvsrvxp'      : '江民',
                    'kvxp'         : '江民',
                    '2345MPCSafe'  : '2345',
                    'PFW'          : '天网防火墙',
                    }
                softwares = [k for k in blacklist]
                tasklist = {x.name.lower(): x for x in get_process_list()}
                softwares = [x for x in softwares if x.lower() in tasklist]
                if softwares:
                    displaylist = {}
                    for software in softwares:
                        k = blacklist[software]
                        if k not in displaylist:
                            displaylist[k] = []
                        displaylist[k].append(software)
                    displaystr = ['某些安全软件可能和本软件存在冲突，造成 CPU 占用过高。'
                                  '如有此现象建议暂时退出以下安全软件来保证 GotoX 运行：\n',]
                    for k, v in displaylist.items():
                        displaystr.append('    %s：%s'
                            % (k, '、'.join(tasklist[x.lower()].filename for x in v)))
                    title = 'GotoX 建议'
                    error = '\n'.join(displaystr)
                    logging.warning(error)
                    ctypes.windll.user32.MessageBoxW(None, error, title, 48)
        if GC.LISTEN_ACT == 'CFW':
            if not GC.CFW_WORKER:
                logging.critical('请编辑 %r 文件，添加可用的 CFWorker 域名到 [cfw] 配置中，否则无法使用 CFW 代理！', GC.CONFIG_FILENAME)
        elif GC.LISTEN_ACT == 'GAE':
            logging.critical('GAE 代理已弃用，用户需自行完成服务端部署！')
            if not GC.GAE_APPIDS:
                logging.critical('请编辑 %r 文件，添加可用的 AppID 到 [gae] 配置中，否则无法使用 GAE 代理！', GC.CONFIG_FILENAME)
        if not GC.PROXY_ENABLE:
            resolve_iplist()

    info = ['=' * 80]
    info.append(' GotoX  版 本 : %s (python/%s gevent(%s)/%s pyOpenSSL/%s)' % (__version__, sys.version.split(' ')[0], GC.GEVENT_LOOP, geventver, opensslver))
    if GC.LISTEN_ACT == 'GAE':
        info.append('\n GAE    AppID : %s' % ('|'.join(GC.GAE_APPIDS) or '请填入 AppID'))
        info.append('\n GAE 远程验证 : %s启用' % '已' if GC.GAE_SSLVERIFY else '未')
    elif GC.LISTEN_ACT == 'CFW':
        info.append('\n CFW    域 名 : %s' % (GC.CFW_WORKER or '请填入完整域名'))
    info.append('\n  监 听 地 址 : 自动代理 - %s:%d' % (GC.LISTEN_IP, GC.LISTEN_AUTOPORT))
    info.append('                %s 代理 - %s:%d' % (GC.LISTEN_ACT, GC.LISTEN_IP, GC.LISTEN_ACTPORT))
    info.append('\n  代 理 认 证 : %s认证' % (GC.LISTEN_AUTH == 0 and '无需' or (GC.LISTEN_AUTH == 2 and 'IP ') or 'Basic '))
    info.append('\n  调 试 信 息 : %s' % logging.getLevelName(GC.LOG_LEVEL))
    info.append('\n  保 存 日 志 : %s' % GC.LOG_FILE if GC.LOG_SAVE else '否')
    info.append('\n  连 接 模 式 : 远程 - %s' % GC.LINK_REMOTESSLTXT)
    info.append('                本地 - %s' % GC.LINK_LOCALSSLTXT)
    info.append('\n  网 络 配 置 : %s' % GC.LINK_PROFILE)
    info.append('\n  IP 数 据 库 : %s' % IPDBVer)
    info.append('\n  直 连 域 名 : %s' % DDTVer)
    info.append('\n  安 装 证 书 : 设置代理后访问 http://gotox.go/')
    info.append('=' * 80)
    info = '\n'.join(info)
    print(info)
    if GC.LOG_SAVE:
        print(info, file=logfile)

    pre_start()
    del pre_start, info

    check_ca()
    start_proxyserver()

    if GC.GAE_TESTGWSIPLIST:
        GIPManager.start_ip_check()
    else:
        if GC.GAE_IPLIST:
            logging.warning('正在使用固定的 GAE IP 列表 [%s]，每小时进行一次 IP 分类。', GC.GAE_IPLIST)
        if GC.GAE_ENABLEPROXY:
            logging.warning('正在通过前置代理使用 GAE：%s。', GC.GAE_PROXYLIST)
        else:
            start_new_thread(GIPManager.fixed_iplist, ())

    while True:
        sleep(30)
        network_test()

if __name__ == '__main__':
    main()
