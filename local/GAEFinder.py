# coding:utf-8
'''
根据 checkgoogleip 代码重新编写整合到 GotoX
从一个较大的可用 GAE IP 列表中快速筛选优质 IP
'''

import os
import sys
import threading
import socket
import ssl
import select
import random
import OpenSSL
import logging
from shutil import copyfile
from time import time, localtime, strftime
from .path import cert_dir, data_dir
from .common import NetWorkIOError, isip, isipv4, isipv6
from .common.internet_active import internet_v4, internet_v6
from .compat.openssl import zero_EOF_error
from .ProxyServer import network_test
from .GlobalConfig import GC

exists = os.path.exists

#全局只读写数据
#最大 IP 延时，单位：毫秒
g_maxhandletimeout = GC.FINDER_MAXTIMEOUT
#扫描得到的可用 IP 数量
g_maxgaeipcnt = GC.FINDER_MINIPCNT
#最大扫描 IP 的线程数量
g_maxthreads = GC.FINDER_MAXTHREADS
#容忍 badip 的次数
g_timesblock = GC.FINDER_TIMESBLOCK
#累计容忍 badip 的次数
g_timesdel = GC.FINDER_TIMESDEL
#屏蔽 badip 的时限，单位：小时
g_blocktime = GC.FINDER_BLOCKTIME * 3600
#连接超时设置，单位：秒
g_timeout = 4
g_conntimeout = 1
g_handshaketimeout = 1.5
#屏蔽列表（当前使用的新测试方法可能用不着这个了）
g_block = GC.FINDER_BLOCK #('74.125.', '173.194.', '203.208.', '113.171.')
#扫描时使用的主机名和匹配的域名，需配对
g_servername = GC.FINDER_SERVERNAME
g_comdomain = GC.FINDER_COMDOMAIN

g_ipfile = os.path.join(data_dir, 'ip.txt')
g_ipfilebak = os.path.join(data_dir, 'ipbak.txt')
g_ipexfile = os.path.join(data_dir, 'ipex.txt')
g_ipexfilebak = os.path.join(data_dir, 'ipexbak.txt')
g_badfile = os.path.join(data_dir, 'ip_bad.txt')
g_badfilebak = os.path.join(data_dir, 'ip_badbak.txt')
g_delfile = os.path.join(data_dir, 'ip_del.txt')
g_delfilebak = os.path.join(data_dir, 'ip_delbak.txt')
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

gLock = threading.Lock()

def PRINT(fmt, *args, **kwargs):
    #logging.info(strlog)
    logging.test('[%s] %s' % (threading.current_thread().name, fmt), *args, **kwargs)

def WARNING(fmt, *args, **kwargs):
    logging.debug('[%s] %s' % (threading.current_thread().name, fmt), *args, **kwargs)

def writebytes(write):
    def newwrite(str):
        write(str.encode())
    return newwrite

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
        #with open(names[0], 'ab'): pass
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
    delset = g.delset
    g.statisticsfiles = statisticsfiles = getnames()
    for file in statisticsfiles:
        if exists(file):
            with open(file, 'r') as fd:
                for line in fd:
                    try:
                        ip, good, bad = (x.strip() for x in line.split('*'))
                    except:
                        pass
                    else:
                        if ip in delset or ip.startswith(g_block):
                            continue
                        good = int(good)
                        bad = int(bad)
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
    backupfile(statisticsfile, g_statisticsfilebak)
    statistics = statistics or g.statistics[1]
    statistics = [(ip, stats1, stats2) for ip, (stats1, stats2) in statistics.items()]
    statistics.sort(key=lambda x: -(x[1]+0.01)/(x[2]**2+0.1))
    with open(statisticsfile, 'wb') as f:
        write = writebytes(f.write)
        for ip, good, bad in statistics:
            write(str(ip).rjust(15))
            f.write(b' * ')
            write(str(good).rjust(3))
            f.write(b' * ')
            write(str(bad).rjust(3))
            f.write(b'\n')

#读取 checkgoogleip 输出 ip.txt
def readiplist(otherset):
    #g.reloadlist = False
    now = time()
    otherset.update(g.goodlist)
    baddict = g.baddict
    delset = g.delset
    ipexset = g.ipexset
    ipset = g.ipset
    source_ipexset = g.source_ipexset
    source_ipset = g.source_ipset
    weakset = set()
    deledset = set()
    #判断是否屏蔽
    for ip, (timesblock, blocktime, timesdel) in baddict.copy().items():
        if timesblock is 0:
            continue
        if timesdel > g_timesdel:
            del baddict[ip]
            deledset.add(ip)
            continue
        if now - blocktime > g_blocktime:
            baddict[ip] = 0, 0, timesdel
            continue
        if timesblock > g_timesblock:
            otherset.add(ip)
            continue
        if not ip.startswith(g_block):
            weakset.add(ip)
    #读取待捡 IP
    if not ipexset and exists(g_ipexfile):
        with open(g_ipexfile, 'r') as fd:
            for line in fd:
                ip = line.strip()
                source_ipexset.add(ip)
                if not line.startswith(g_block):
                    ipexset.add(ip)
    if not ipset and exists(g_ipfile):
        source_ipcnt = 0
        with open(g_ipfile, 'r') as fd:
            for line in fd:
                source_ipcnt += 1
                ip = line.strip()
                source_ipset.add(ip)
                if not line.startswith(g_block):
                    ipset.add(ip)
        #检测重复 IP 
        hasdupl = source_ipcnt - len(source_ipset)
        if hasdupl:
            PRINT('从主列表发现重复 IP，数量：%d。', hasdupl)
    else:
        hasdupl = False
    #移除永久屏蔽 IP
    if deledset:
        ipset -= deledset
        source_ipset -= deledset
    #检测并添加新 IP
    addset = source_ipexset - source_ipset
    if addset:
        ipset |= ipexset       #合并所有符合条件的 IP
        source_ipset |= addset
        PRINT('检测到新添加 IP，数量：%d。', len(addset))
        backupfile(g_ipfile, g_ipfilebak)
        #从永久屏蔽 IP 中移除新添加 IP
        adddeledset = deledset & addset
        if adddeledset:
            deledset -= adddeledset
    #检测并移除永久屏蔽 IP，保存扩展列表
    deledexset = source_ipexset & deledset
    if deledexset:
        ipexset -= deledexset
        source_ipexset -= deledexset
        saveipexlist()
    #添加和撤销永久屏蔽 IP，保存永久屏蔽列表
    issavedellist = False
    restoreset = delset & source_ipset
    if restoreset:
        delset -= restoreset
        issavedellist = True
        PRINT('检测到被撤销永久屏蔽的 IP，数量：%d。', len(restoreset))
    if deledset:
        delset |= deledset
        issavedellist = True
        logging.warning('检测到新的永久屏蔽 IP，数量：%d。', len(deledset))
    if issavedellist:
        savedellist()
        logging.warning('已保存永久屏蔽列表文件，数量：%d。', len(delset))
    #保存主列表
    source_ipsetlen = len(source_ipset)
    if source_ipsetlen < g_maxgaeipcnt:
        logging.warning('IP 列表文件 "%s" 包含 IP 过少，请添加。', g_ipfile)
    if hasdupl or deledset or addset:
        saveiplist()
        PRINT('已保存主列表文件，数量：%d。', source_ipsetlen)
    #排除自动屏蔽列表、正在使用的列表、good 列表
    #用等号赋值不会改变原集合内容，之前都是用非等号赋值的
    ipexset = ipexset - otherset
    ipset = ipset - otherset
    ipset -= ipexset
    #排除非当前配置的遗留 IP
    weakset = weakset - otherset
    weakset &= ipset
    ipset -= weakset
    g.halfweak = len(weakset)/2
    g.readtime = now
    return list(ipexset), list(ipset), list(weakset)

def saveipexlist(ipexset=None):
    ipexset = ipexset or g.source_ipexset
    savelist(ipexset, g_ipexfile)
    #保持修改时间不变（自动删除判断依据）
    os.utime(g_ipexfile, (g.ipexmtime, g.ipexmtime))

def saveiplist(ipset=None):
    ipset = ipset or g.source_ipset
    savelist(ipset, g_ipfile)
    g.ipmtime = os.path.getmtime(g_ipfile)

def savelist(set, file):
    with open(file, 'wb') as f:
        write = writebytes(f.write)
        for ip in set:
            write(ip)
            f.write(b'\n')

def readbadlist():
    ipdict = {}
    if exists(g_badfile):
        with open(g_badfile, 'r') as fd:
            for line in fd:
                #兼容之前的格式，下个版本会去掉
                entry = line.strip().split('*')
                entrylen = len(entry)
                if entrylen is 4:
                    ip, timesblock, blocktime, timesdel = entry
                if entrylen is 3:
                    ip, timesblock, blocktime = entry
                    timesdel = timesblock
                if entrylen > 2:
                    ipdict[ip] = int(timesblock), int(blocktime), int(timesdel)
    return ipdict

def savebadlist(baddict=None):
    baddict = baddict or g.baddict
    backupfile(g_badfile, g_badfilebak)
    with open(g_badfile, 'wb') as f:
        write = writebytes(f.write)
        for ip in baddict:
            timesblock, blocktime, timesdel = baddict[ip]
            write(ip)
            f.write(b'*')
            write(str(timesblock))
            f.write(b'*')
            write(str(blocktime))
            f.write(b'*')
            write(str(timesdel))
            f.write(b'\n')

def readdellist():
    ipset = set()
    if exists(g_delfile):
        with open(g_delfile, 'r') as fd:
            for line in fd:
                ipset.add(line.strip())
    return ipset

def savedellist(delset=None):
    delset = delset or g.delset
    backupfile(g_delfile, g_delfilebak)
    savelist(delset, g_delfile)

def backupfile(file, bakfile):
    if exists(file):
        if exists(bakfile):
            os.remove(bakfile)
        os.rename(file, bakfile)

def clearzerofile(file):
    if exists(file) and os.path.getsize(file) == 0:
        os.remove(file)

def makegoodlist(nowgaeset=()):
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

#全局可读写数据
class g:
    ipexset = set()
    ipset = set()
    source_ipexset = set()
    source_ipset = set()
    running = False
    #reloadlist = False
    ipmtime = 0
    ipexmtime = 0
    baddict = readbadlist()
    delset = readdellist()
    ipexlist = []
    iplist = []
    weaklist = []

clearzerofile(g_ipfile)
clearzerofile(g_ipfilebak)
clearzerofile(g_badfile)
clearzerofile(g_badfilebak)
#启动时备份主列表
if exists(g_ipfile):
    if not exists(g_ipfilebak):
        copyfile(g_ipfile, g_ipfilebak)
#只有启动时，才从备份恢复主列表
elif exists(g_ipfilebak):
    copyfile(g_ipfilebak, g_ipfile)
else:
    logging.error('未发现 IP 列表文件 "%s"，请创建！', g_ipfile)
#只有启动时，才从备份恢复 bad 列表
if not exists(g_badfile) and exists(g_badfilebak):
    os.rename(g_badfilebak, g_badfile)
g.statistics = readstatistics()
makegoodlist()

from .HTTPUtil import http_gws

class GAE_Finder:

    httpreq = (
        b'HEAD / HTTP/1.1\r\n'
        b'Host: www.appspot.com\r\n'
        b'Connection: Close\r\n\r\n'
    )
    redirect_res = (
        b'302 Found\r\n'
        b'Location: https://console.cloud.google.com/appengine'
    )

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
            http_gws.set_tcp_socket(sock, set_buffer=False)
            ssl_sock = http_gws.get_ssl_socket(sock, g_servername)
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
            if not retry and e.args == zero_EOF_error:
                return self.getipinfo(ip, conntimeout, handshaketimeout, timeout, True)
            WARNING('getipinfo %r', e)
        is_gae = self.check_gae_status(ssl_sock, sock, ip) if ssl_sock else False
        costtime = int((time()-start_time)*1000)
        return domain, costtime, is_gae

    def check_gae_status(self, conn, sock, ip):
        try:
            conn.send(self.httpreq)
            return conn.read(72)[-63:] == self.redirect_res
        except NetWorkIOError as e:
            WARNING('从 %s 获取服务器信息时发生错误：%r', ip, e)
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
        if ip in baddict: #重置未到容忍次数的 badip
            _, _, timesdel = baddict[ip]
            baddict[ip] = 0, 0, timesdel
        com = ssldomain == g_comdomain
        if com:
            ssldomain = '*.google.com'
            return
        PRINT('剩余：%s，%s，%sms，%s', str(remain).rjust(4), ip.rjust(15),
              str(costtime).rjust(4), ssldomain)
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
        timesdel = 0
        if ip in baddict: # badip 容忍次数 +1
            timesblock, _, timesdel = baddict[ip]
            baddict[ip] = timesblock + 1, int(time()), timesdel + 1
        else: #记录检测到 badip 的时间
            baddict[ip] = 1, int(time()), 1
        badb = baddict[ip][0]
        ipdict, ipdicttoday = statistics
        if ip in ipdict:
            #累计容忍次数超出预期，设置 -1 表示删除
            if timesdel >= g_timesdel:
                ipdict[ip] = ipdicttoday[ip] = -1, 0
            else:
                good, bad = ipdict[ip]
                if good >= 0:
                    #失败次数超出预期，设置 -1 表示删除
                    s = bad/max(good, 1)
                    if s > 2 or (s > 0.4 and bad > 10) or (s > 0.15 and badb > 10):
                        ipdict[ip] = ipdicttoday[ip] = -1, 0
                    else:
                        ipdict[ip] = max(good - 2, 0), bad + 1
                        if ip in ipdicttoday:
                            good, bad = ipdicttoday[ip]
                        else:
                            good = bad = 0
                        ipdicttoday[ip] = max(good - 2, 0), bad + 1
    #测试了足够多 IP 数目或达标 IP 满足数量后停止
    if g.testedok > g.testok or g.needgwscnt < 1 and g.needcomcnt < 1:
        return True

class Finder(threading.Thread):
    def run(self):
        ip = randomip()
        while ip:
            if internet_v6.last_stat and isipv6(ip) or internet_v4.last_stat and isipv4(ip):
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
    return ip

def randomip():
    with gLock:
        g.getgood += 1
        g.pingcnt += 1
        if g.goodlist and g.getgood >= 20:
            g.getgood = 0
            return g.goodlist.pop()
        if g.ipexlist:
            return _randomip(g.ipexlist)
        if g.iplist:
            return _randomip(g.iplist)
        if g.goodlist:
            return g.goodlist.pop()
        if g.weaklist:
            return _randomip(g.weaklist)
        g.pingcnt -= 1

def getgaeip(nowgaelist, needgwscnt, needcomcnt):
    if g.running or needgwscnt == needcomcnt == 0:
        return
    g.running = True
    #获取参数
    nowgaeset = set(nowgaelist)
    g.needgwscnt = needgwscnt
    g.needcomcnt = needcomcnt
    threads = min(needgwscnt + needcomcnt*2 + 1, g_maxthreads)
    #重建 good 列表
    makegoodlist(nowgaeset)
    #检查 IP 数据修改时间
    ipmtime = ipexmtime = 0
    if exists(g_ipfile):
        ipmtime = os.path.getmtime(g_ipfile)
        if ipmtime > g.ipmtime:
            copyfile(g_ipfile, g_ipfilebak)
            g.source_ipset.clear()
            g.ipset.clear()
    else:
        logging.error('未发现 IP 列表文件 "%s"，请创建！', g_ipfile)
    if exists(g_ipexfile):
        ipexmtime = os.path.getmtime(g_ipexfile)
        if ipexmtime > g.ipexmtime:
            copyfile(g_ipexfile, g_ipexfilebak)
            g.source_ipexset.clear()
            g.ipexset.clear()
    now = time()
    if ipmtime > g.ipmtime or ipexmtime > g.ipexmtime:
        # 更新过 IP 列表
        g.ipmtime = ipmtime
        g.ipexmtime = ipexmtime
        g.ipexlist, g.iplist, g.weaklist = readiplist(nowgaeset)
    elif (len(g.weaklist) < g.halfweak or # 上一次加载 IP 时出过错的 IP
             now - g.readtime > 8*3600 or # n 小时强制重载 IP
             #g.reloadlist or
             len(g.ipexlist) == len(g.iplist) == len(g.weaklist) == 0):
        g.ipexlist, g.iplist, g.weaklist = readiplist(nowgaeset)
    if ipexmtime:
        passtime = now - ipexmtime
        #最快两小时，最慢十二小时后删除
        if passtime > 43200 or len(g.ipexlist) == 0 and passtime > 7200:
            os.remove(g_ipexfile)
            ipexmtime = now
    g.getgood = 0
    g.gaelist = []
    g.gaelistbak = gaelistbak = []
    g.pingcnt = 0
    g.testedok = 0
    g.testedcnt = 0
    g.testok = max(needgwscnt * 8, g.needcomcnt * 16)
    g.maxhandletimeout = g_maxhandletimeout + timeToDelay[strftime('%H')]
    PRINT('==================== 开始查找 GAE IP ====================')
    PRINT('需要查找 IP 数：%d/%d，待检测 IP 数：%d + %d',
          needcomcnt,
          max(needgwscnt, needcomcnt),
          len(g.ipexlist) + len(g.iplist) + len(g.weaklist),
          len(g.goodlist))
    #多线程搜索
    threadiplist = []
    for i in range(threads):
        ping_thread = Finder()
        ping_thread.setDaemon(True)
        ping_thread.setName('Finder%s' % str(i+1).rjust(2, '0'))
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
        PRINT('未找到足够的优质 GAE IP，添加 %d 个备选 IP：\n %s',
              m + n,
              ' | '.join(gaelist['google_gws']))
    else:
        PRINT('已经找到 %d 个新的优质 GAE IP：\n %s',
              len(gaelist['google_gws']),
              ' | '.join(gaelist['google_gws']))
    PRINT('==================== GAE IP 查找完毕 ====================')
    g.running = False

    return gaelist
