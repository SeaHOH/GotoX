# coding:utf-8
#!/usr/bin/env python
__author__ = 'seahoh@gamil.com'
'''
根据 checkgoogleip 代码重新编写整合到 GotoX
从一个较大的可用 GAE IP 列表中快速筛选优质 IP
'''

import os
import sys
import threading
import socket
import ssl
import struct
import select
import random
import OpenSSL
from . import clogging as logging
from time import time, localtime, strftime
from .common import cert_dir, data_dir, NetWorkIOError, isip, isipv4, isipv6
from .ProxyServer import network_test
from .GlobalConfig import GC

#全局只读写数据
#最大 IP 延时，单位：毫秒
g_maxhandletimeout = GC.FINDER_MAXTIMEOUT
#扫描得到的可用 IP 数量
g_maxgaeipcnt = GC.FINDER_MINIPCNT
#最大扫描 IP 的线程数量
g_maxthreads = GC.FINDER_MAXTHREADS
#容忍 badip 的次数
g_timesblock = GC.FINDER_TIMESBLOCK
#屏蔽 badip 的时限，单位：小时
g_blocktime = GC.FINDER_BLOCKTIME * 3600
#是否允许 gvs IP: 0否，1是
g_gvs = 1
#连接超时设置，单位：秒
g_timeout = 4
g_conntimeout = 1
g_handshaketimeout = 1.5
#屏蔽列表（当前使用的新测试方法可能用不着这个了）
g_block = GC.FINDER_BLOCK #('74.125.', '173.194.', '203.208.', '113.171.')

g_ipfile = os.path.join(data_dir, 'ip.txt')
g_ipexfile = os.path.join(data_dir, 'ipex.txt')
g_badfile = os.path.join(data_dir, 'ip_bad.txt')
g_badfilebak = os.path.join(data_dir, 'ip_badbak.txt')
g_statisticsfilebak = os.path.join(data_dir, 'statisticsbak')

#加各时段 IP 延时，单位：毫秒
timeToDelay = {
    '01': 0, '09':  50, '17': 100,
    '02': 0, '10':  50, '18': 100, 
    '03': 0, '11':  50, '19': 150,
    '04': 0, '12': 100, '20': 150,
    '05': 0, '13': 100, '21': 150,
    '06': 0, '14': 100, '22':  50,
    '07': 0, '15':  50, '23':  50,
    '08': 0, '16':  50, '00':   0
    }

#全局可读写数据
class g: pass

gLock = threading.Lock()

def PRINT(fmt, *args, **kwargs):
    #logging.info(strlog)
    logging.test('[%s] %s' % (threading.current_thread().name, fmt), *args, **kwargs)

def WARNING(fmt, *args, **kwargs):
    logging.debug('[%s] %s' % (threading.current_thread().name, fmt), *args, **kwargs)

if GC.LINK_PROFILE == 'ipv4':
    ipnotuse = lambda x: not isipv4(x)
elif GC.LINK_PROFILE == 'ipv6':
    ipnotuse = lambda x: not isipv6(x)
elif GC.LINK_PROFILE == 'ipv46':
    ipnotuse = lambda x: False

def readstatistics():
    def getnames():
        now = time()
        names = []
        #生成统计文件名
        for i in range(GC.FINDER_STATDAYS):
            n = strftime('%y%j', localtime(now-3600*24*i))
            name = os.path.join(data_dir, 'statistics'+n)
            names.append(name)
        #新建当日统计文件
        if not os.path.exists(names[0]):
            with open(names[0], 'w'): pass
        #删除过期的统计文件
        sfiles = [g_statisticsfilebak,]
        sfiles.extend(names)
        for file in os.listdir(data_dir):
            if file.startswith('statistics'):
                isdel = True
                for sfile in sfiles:
                    if sfile.endswith(file):
                        isdel = False
                        break
                if isdel:
                    os.remove(os.path.join(data_dir, file))
        return tuple(names)

    ipdict = {}
    ipdicttoday = None
    deledipset = set()
    g.statisticsfiles = statisticsfiles = getnames()
    for file in statisticsfiles:
        if os.path.exists(file):
            with open(file, 'r') as fd:
                for line in fd:
                    ips = [x.strip('\r\n ') for x in line.split('*')]
                    if len(ips) == 3:
                        ip = ips[0]
                        if ip.startswith(g_block):
                            continue
                        good = int(ips[1])
                        bad = int(ips[2])
                        # 小于 0 表示已删除
                        if good < 0:
                            deledipset.add(ip)
                        if ip in ipdict:
                            if ip in deledipset:
                                continue
                            cgood, cbad = ipdict[ip]
                            good += cgood
                            bad += cbad
                        ipdict[ip] = good, bad
        #复制当日统计数据
        if ipdicttoday is None:
            ipdicttoday = ipdict.copy()
    return ipdict, ipdicttoday

def savestatistics(statistics=None):
    statisticsfile = g.statisticsfiles[0]
    if os.path.exists(statisticsfile):
        if os.path.exists(g_statisticsfilebak):
            os.remove(g_statisticsfilebak)
        os.rename(statisticsfile, g_statisticsfilebak)
    statistics = statistics or g.statistics[1]
    statistics = [(ip, stats1, stats2) for ip, (stats1, stats2) in statistics.items()]
    statistics.sort(key=lambda x: -(x[1]+0.01)/(x[2]**2+0.1))
    op = 'w'
    with open(statisticsfile, op) as f:
        for ip, good, bad in statistics:
            f.write(str(ip).rjust(15))
            f.write(' * ')
            f.write(str(good).rjust(3))
            f.write(' * ')
            f.write(str(bad).rjust(3))
            f.write('\n')

#读取 checkgoogleip 输出 ip.txt
def readiplist(nowgaeset):
    #g.reloadlist = False
    now = time()
    baddict = g.baddict
    blockset = set()
    weakset = set()
    #判断是否屏蔽
    for ip, (v1, v2) in baddict.copy().items():
        if v1 > g_timesblock:
            if now - v2 > g_blocktime:
                del baddict[ip]
            else:
                blockset.add(ip)
                continue
        if not ip.startswith(g_block):
            weakset.add(ip)
    #读取待捡 IP
    ipexset = set()
    ipset = set()
    if os.path.exists(g_ipexfile):
        with open(g_ipexfile, 'r') as fd:
            for line in fd:
                if not line.startswith(g_block):
                    ipexset.add(line.strip('\r\n'))
    if os.path.exists(g_ipfile):
        with open(g_ipfile, 'r') as fd:
            for line in fd:
                if not line.startswith(g_block):
                    ipset.add(line.strip('\r\n'))
    #自动屏蔽列表、正在使用的 IP
    otherset = blockset | nowgaeset | set(g.goodlist)
    ipexset = ipexset - otherset
    ipset = ipset - otherset - ipexset
    #排除非当前配置的遗留 IP
    weakset = weakset & ipset
    ipset = ipset - weakset
    g.halfweak = len(weakset)/2
    g.readtime = now
    return list(ipexset), list(ipset), list(weakset)

def readbadlist():
    ipdict = {}
    if os.path.exists(g_badfile):
        with open(g_badfile, 'r') as fd:
            for line in fd:
                ips = [x.strip('\r\n ') for x in line.split('*')]
                if len(ips) == 3:
                    ipdict[ips[0]] = int(ips[1]), int(ips[2])
    return ipdict

def savebadlist(baddict=None):
    if os.path.exists(g_badfile):
        if os.path.exists(g_badfilebak):
            os.remove(g_badfilebak)
        os.rename(g_badfile, g_badfilebak)
    baddict = baddict or g.baddict
    op = 'w'
    with open(g_badfile, op) as f:
        for ip in baddict:
            f.write(' * '.join([ip, str(baddict[ip][0]), str(baddict[ip][1])]))
            f.write('\n')

from .HTTPUtil import http_gws

class GAE_Finder:

    httpreq = b'HEAD / HTTP/1.1\r\nHost: www.appspot.com\r\nConnection: Close\r\n\r\n'

    def __init__(self):
        pass

    def getipinfo(self, ip, conntimeout=g_conntimeout, handshaketimeout=g_handshaketimeout, timeout=g_timeout, retry=None):
        if ipnotuse(ip):
            return None, 0, False
        start_time = time()
        costtime = 0
        domain = None
        sock = None
        ssl_sock = None
        try:
            sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
            ssl_sock = http_gws.get_ssl_socket(sock, b'www.google.com')
            ssl_sock.settimeout(conntimeout)
            ssl_sock.connect((ip, 443))
            ssl_sock.settimeout(handshaketimeout)
            ssl_sock.do_handshake()
            ssl_sock.settimeout(timeout)
            handshaked_time = time() - start_time
            if handshaked_time > handshaketimeout:
                raise socket.error('handshake cost %dms timed out' % int(handshaked_time*1000))
            cert = http_gws.google_verify(ssl_sock)
            domain = cert.get_subject().CN
            if not domain:
                raise ssl.SSLError('%s 无法获取 commonName：%s ' % (ip, cert))
        except NetWorkIOError as e:
            sock.close()
            ssl_sock = None
            if not retry and e.args == (-1, 'Unexpected EOF'):
                return self.getipinfo(ip, conntimeout, handshaketimeout, timeout, True)
            WARNING('%r', e)
        code = self.getstatuscode(ssl_sock, sock, ip) if ssl_sock else ''
        costtime = int((time()-start_time)*1000)
        return domain, costtime, code in (b'302', b'200')

    def getstatuscode(self, conn, sock, ip):
        try:
            conn.send(self.httpreq)
            return conn.read(12)[-3:]
        except NetWorkIOError as e:
            WARNING('从 %s 获取响应状态时发生错误：%r', ip, e)
        finally:
            sock.close()

gae_finder = GAE_Finder()

def runfinder(ip):
    with gLock:
        #检查网络
        if g.testedcnt >= 50:
            network_test()
            g.testedcnt = 0
    ssldomain, costtime, isgaeserver = gae_finder.getipinfo(ip)
    statistics = g.statistics
    baddict = g.baddict
    with gLock:
        g.testedcnt += 1
        g.pingcnt -= 1
        remain = len(g.goodlist) + len(g.ipexlist) + len(g.iplist) + len(g.weaklist) + g.pingcnt
    #判断是否可用
    if isgaeserver:
        with gLock:
            g.testedok += 1
        if ip in baddict: #删除未到容忍次数的 badip
            del baddict[ip]
        PRINT('剩余：%s，%s，%sms，%s', str(remain).rjust(4), ip.rjust(15),
              str(costtime).rjust(4), ssldomain)
        com = ssldomain == 'www.google.com'
        #判断是否够快
        if costtime < g.maxhandletimeout:
            g.gaelist.append((ip, costtime, com))
            with gLock:
                #计数
                g.needgwscnt -= 1
                if com:
                    g.needcomcnt -= 1
        else:
            #备用
            g.gaelistbak.append((ip, costtime, com))
            for ipdict in statistics:
                if ip in ipdict:
                    good, bad = ipdict[ip]
                    ipdict[ip] = max(good - 1, 0), bad
    else:
        for ipdict in statistics:
            if ip in ipdict:
                 good, bad = ipdict[ip]
                 if good < 0: break
                 #失败次数超出预期，设置 -1 表示删除
                 s = bad/max(good, 1)
                 if s > 2 or (s > 0.6 and bad > 10):
                     ipdict[ip] = -1, 0
                 else:
                     ipdict[ip] = max(good - 1, 0), bad + 1
        if ip in baddict: # badip 容忍次数 +1
            baddict[ip] = baddict[ip][0]+1, int(time())
        else: #记录检测到 badip 的时间
            baddict[ip] = 1, int(time())
    #测试了足够多 IP 数目或达标 IP 满足数量后停止
    if g.testedok > g.testok or g.needgwscnt < 1 and g.needcomcnt < 1:
        return True

class Finder(threading.Thread):
    #线程默认运行函数
    def run(self):
        ip = randomip()
        while ip:
            if isip(ip):
                if runfinder(ip):
                    break
            else:
                with gLock:
                    g.pingcnt -= 1
            ip = randomip()

def _randomip(iplist):
    cnt = len(iplist)
    #a = random.randint(0, cnt - 1)
    #b = int(random.random() * (cnt - 0.1))
    #if random.random() > 0.7: #随机分布概率偏向较小数值
    #    n =  max(a, b)
    #else:
    #    n =  min(a, b)
    n = int(random.random() * (cnt - 0.1))
    ip = iplist[n]
    del iplist[n]
    g.pingcnt += 1
    return ip

def randomip():
    with gLock:
        g.getgood += 1
        if g.goodlist and g.getgood >= 5:
            g.getgood = 0
            return g.goodlist.pop()
        elif g.ipexlist:
            return _randomip(g.ipexlist)
        elif g.iplist:
            return _randomip(g.iplist)
        elif g.goodlist:
            return g.goodlist.pop()
        elif g.weaklist:
            return _randomip(g.weaklist)

g.running = False
#g.reloadlist = False
g.ipmtime = 0
g.ipexmtime = 0
g.statistics = readstatistics()
g.baddict = readbadlist()
def getgaeip(nowgaelist, needgwscnt, needcomcnt):
    if g.running or needgwscnt == needcomcnt == 0:
        return
    g.running = True
    #获取参数
    nowgaeset = set(nowgaelist)
    g.needgwscnt = needgwscnt
    g.needcomcnt = needcomcnt
    threads = min(needgwscnt + needcomcnt*2 + 1, g_maxthreads)
    now = time()
    #日期变更、重新加载统计文件
    if not g.statisticsfiles[0].endswith(strftime('%y%j')):
        savestatistics()
        g.statistics = readstatistics()
    # goodlist 根据统计来排序已经足够，不依据 baddict 来排除 IP
    #不然干扰严重时可能过多丢弃可用 IP
    # baddict 只用来排除没有进入统计的IP 以减少尝试次数
    statistics = g.statistics[0]
    statistics = [(ip, stats1, stats2) for ip, (stats1, stats2) in statistics.items() if ip not in nowgaeset and stats1 >= 0]
    #根据统计数据排序（bad 降序、good 升序）供 pop 使用
    statistics.sort(key=lambda x: (x[1]+0.01)/(x[2]**2+0.1))
    g.goodlist = [ip[0] for ip in statistics]
    #检查 IP 数据修改时间
    ipmtime = ipexmtime = 0
    if os.path.exists(g_ipfile):
        ipmtime = os.path.getmtime(g_ipfile)
    if os.path.exists(g_ipexfile):
        ipexmtime = os.path.getmtime(g_ipexfile)
        if now - ipexmtime > 2*3600: #两小时后删除
            os.remove(g_ipexfile)
    if ipmtime > g.ipmtime or ipexmtime > g.ipexmtime:
        # 更新过 IP 列表
        g.ipmtime = ipmtime
        g.ipexmtime = ipexmtime
        g.ipexlist, g.iplist, g.weaklist = readiplist(nowgaeset)
    elif (len(g.weaklist) <= g.halfweak or # 上一次加载 IP 时出过错的 IP
             now - g.readtime > 8*3600 or # n 小时强制重载 IP
             #g.reloadlist or
             len(g.ipexlist) == len(g.iplist) == len(g.weaklist) == 0):
        g.ipexlist, g.iplist, g.weaklist = readiplist(nowgaeset)
    del nowgaelist, nowgaeset, statistics
    g.getgood = 0
    g.gaelist = []
    g.gaelistbak = gaelistbak = []
    g.pingcnt = 0
    g.testedok = 0
    g.testedcnt = 0
    g.testok = max(needgwscnt * 8, g.needcomcnt * 16)
    g.maxhandletimeout = g_maxhandletimeout + timeToDelay[strftime('%H')]
    PRINT('==================== 开始查找 GAE IP ====================')
    PRINT('需要查找 IP 数：%d/%d，待检测 IP 数：%d', needcomcnt, max(needgwscnt, needcomcnt), len(g.goodlist)+len(g.ipexlist)+len(g.iplist)+len(g.weaklist))
    #多线程搜索
    threadiplist = []
    for i in range(threads):
        ping_thread = Finder()
        ping_thread.setDaemon(True)
        ping_thread.setName('Ping-%s' % str(i+1).rjust(2, '0'))
        ping_thread.start()
        threadiplist.append(ping_thread)
    for p in threadiplist:
        p.join()
    #结果
    savebadlist()
    savestatistics()
    m = int(g.needcomcnt)
    if m > 0 and gaelistbak:
        #补齐个数，以 google_com 为准
        gaelistbak.sort(key=lambda x: (-x[2], x[1]))
        comlistbak = gaelistbak[:m]
        gaelistbak = gaelistbak[m:]
        g.gaelist.extend(comlistbak)
        m = len(comlistbak)
    else:
        m = 0
    n = int(g.needgwscnt - m)
    if n > 0 and gaelistbak:
        #补齐个数
        gaelistbak.sort(key=lambda x: x[1])
        gwslistbak = gaelistbak[:n]
        g.gaelist.extend(gwslistbak)
        n = len(gwslistbak)
    else:
        n = 0
    gaelist = {'google_gws':[], 'google_com':[]}
    for ip in g.gaelist:
        gaelist['google_gws'].append(ip[0])
        if ip[2]:
            gaelist['google_com'].append(ip[0])
    if m > 0 or n > 0:
        PRINT('未找到足够的优质 GAE IP，添加 %d 个备选 IP：\n %s', m + n, ' | '.join(gaelist['google_gws']))
    else:
        PRINT('已经找到 %d 个新的优质 GAE IP：\n %s', len(gaelist['google_gws']), ' | '.join(gaelist['google_gws']))
    PRINT('==================== GAE IP 查找完毕 ====================')
    g.running = False

    return gaelist
