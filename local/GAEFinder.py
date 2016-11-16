# coding:utf-8
#!/usr/bin/env python
__author__ = 'seahoh@gamil.com'
"""
根据 checkgoogleip 代码重新编写整合到 GotoX
从一个较大的可用 GAE IP 列表中快速筛选优质 IP
"""

import os
import sys

if __name__ == '__main__':
    sys.dont_write_bytecode = True
    import glob
    sys.path += glob.glob('%s/*.egg' % os.path.dirname(os.path.abspath(__file__)))
    try:
        import gevent
        import gevent.socket
        import gevent.monkey
        gevent.monkey.patch_all(subprocess=True)
    except ImportError:
        gevent = None
    except TypeError:
        gevent.monkey.patch_all()
        sys.stderr.write('\033[31m  Warning: Please update gevent to the latest 1.0 version!\033[0m\n')
    logging.disable(logging.DEBUG)

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
from .compat import PY3, xrange
from .GlobalConfig import GC

#全局只读写数据
#最大 IP 延时，单位：毫秒
g_maxhandletimeout = GC.FINDER_MAXTIMEOUT or 1000
#扫描得到的可用 IP 数量
g_maxgaeipcnt = GC.FINDER_MINIPCNT or 12
#扫描 IP 的线程数量
g_maxthreads = GC.FINDER_THREADS or 10
#容忍 badip 的次数
g_timesblock = GC.FINDER_TIMESBLOCK or 2
#屏蔽 badip 的时限，单位：小时
g_blocktime = GC.FINDER_BLOCKTIME or 36
g_blocktime *= 3600
#是否允许 gvs IP: 0否，1是
g_gvs = 1
#连接超时设置，单位：秒
g_timeout = 4
g_conntimeout = 1
g_handshaketimeout = 1.5
# SSL 连接是否使用 OpenSSL
g_useOpenSSL = GC.LINK_OPENSSL or 1
#屏蔽列表（通过测试、但无法使用 GAE）
g_block = GC.FINDER_BLOCK #('74.125.', '173.194.', '203.208.', '113.171.')

g_cacertfile = os.path.join(cert_dir, "cacert.pem")
g_ipfile = os.path.join(data_dir, "ip.txt")
g_ipexfile = os.path.join(data_dir, "ipex.txt")
g_badfile = os.path.join(data_dir, "ip_bad.txt")
g_badfilebak = os.path.join(data_dir, "ip_badbak.txt")
g_statisticsfilebak = os.path.join(data_dir, "statisticsbak")

#加各时段 IP 延时，单位：毫秒
timeToDelay = {    0 :   0,
         1 :   0,  2 :   0,  3 :   0,  4 :   0,  5 :   0,  6 :   0, 
         7 :   0,  8 :   0,  9 :  50, 10 :  50, 11 :  50, 12 : 100,
        13 : 100, 14 : 100, 15 :  50, 16 :  50, 17 : 100, 18 : 100, 
        19 : 150, 20 : 150, 21 : 150, 22 :  50, 23 :  50, 24 :   0
        }

#全局可读写数据
class g: pass

gLock = threading.Lock()

def PRINT(fmt, *args, **kwargs):
    #logging.info(strlog)
    logging.info('[%s] %s' % (threading.current_thread().name, fmt), *args, **kwargs)

def WARNING(fmt, *args, **kwargs):
    logging.debug('[%s] %s' % (threading.current_thread().name, fmt), *args, **kwargs)

if GC.LINK_PROFILE == 'ipv4':
    ipnotuse = lambda x: not isipv4(x)
elif GC.LINK_PROFILE == 'ipv6':
    ipnotuse = lambda x: not isipv6(x)
elif GC.LINK_PROFILE == 'ipv46':
    ipnotuse = lambda x: not isip(x)

def readstatistics():
    def getnames():
        now = time()
        names = []
        #生成统计文件名
        for i in xrange(GC.FINDER_STATDAYS):
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

    print('stats read......')
    ipdict = {}
    ipdicttoday = None
    g.statisticsfiles = statisticsfiles = getnames()
    for file in statisticsfiles:
        if os.path.exists(file):
            with open(file, 'r') as fd:
                for line in fd:
                    ips = line.split('*')
                    if len(ips) == 3:
                        ip = ips[0].strip(' ')
                        if ip in ipdict:
                            good, bad = ipdict[ip]
                            # 小于 0 表示已删除、不加载之前的数据
                            if good < 0: continue
                            good += int(ips[1].strip(' '))
                            bad += int(ips[2].strip('\r\n '))
                        else:
                            good = int(ips[1].strip(' '))
                            bad = int(ips[2].strip('\r\n '))
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
    statistics = [(ip, stats[0], stats[1]) for ip, stats in statistics.items()]
    statistics.sort(key=lambda x: (-(x[1] or 0.9)*1.7/(x[2]*x[2] or 0.1), x[2]))
    op = 'w' if PY3 else 'wb'
    with open(statisticsfile, op) as f:
        for ip in statistics:
            f.write(str(ip[0]).rjust(15))
            f.write(' * ')
            f.write(str(ip[1]).rjust(3))
            f.write(' * ')
            f.write(str(ip[2]).rjust(3))
            f.write('\n')

#读取 checkgoogleip 输出 ip.txt
def readiplist(nowgaeset):
    g.reloadlist = False
    goodset = set(g.goodlist)
    baddict = g.baddict
    blockset = set()
    weakset = set()
    #判断是否屏蔽
    for ip in baddict:
        if baddict[ip][0] > g_timesblock:
            blockset.add(ip)
        else:
            if not ip.startswith(g_block):
                weakset.add(ip)
    #读取待捡 IP
    ipexset = set()
    ipset = set()
    if os.path.exists(g_ipexfile):
        with open(g_ipexfile, "r") as fd:
            for line in fd:
                if not line.startswith(g_block):
                    ipexset.add(line.strip('\r\n'))
    if os.path.exists(g_ipfile):
        with open(g_ipfile, 'r') as fd:
            for line in fd:
                if not line.startswith(g_block):
                    ipset.add(line.strip('\r\n'))
    #自动屏蔽列表、正在使用的 IP
    ipexset = ipexset - blockset - nowgaeset - goodset
    ipset = ipset - blockset - nowgaeset - goodset - ipexset
    #排除非当前配置的遗留 IP
    weakset = weakset & (ipset | ipexset)
    ipexset = ipexset - weakset
    ipset = ipset - weakset
    g.halfweak = len(weakset)/2
    g.readtime = time()
    return list(ipexset), list(ipset), list(weakset)

def readbadlist():
    ipdict = {}
    if os.path.exists(g_badfile):
        with open(g_badfile, 'r') as fd:
            for line in fd:
                ips = line.strip('\r\n').split(' * ')
                if len(ips) == 3:
                    onblocktime = int(ips[2])
                    blockedtime = int(time()) - onblocktime
                    if blockedtime < g_blocktime:
                        ipdict[ips[0]] = int(ips[1]), onblocktime
    return ipdict

def savebadlist(baddict=None):
    if os.path.exists(g_badfile):
        if os.path.exists(g_badfilebak):
            os.remove(g_badfilebak)
        os.rename(g_badfile, g_badfilebak)
    baddict = baddict or g.baddict
    op = 'w' if PY3 else 'wb'
    with open(g_badfile, op) as f:
        for ip in baddict:
            f.write(' * '.join([ip, str(baddict[ip][0]), str(baddict[ip][1])]))
            f.write('\n')

def isgaeserver(svrname):
    svrname = svrname.lower()
    if svrname == 'gws' or (g_gvs == 1 and svrname.startswith('gvs')):
        return True
    else:
        return False

prekey='\nServer:'
def getservernamefromheader(header, headerend):
    begin = header.find(prekey, 0, headerend)
    if begin > 0: 
        begin += len(prekey)
        end = header.find('\r\n', begin)
        return header[begin:end].strip(' \t')
    return ''

from .HTTPUtil import BaseHTTPUtil, gws_ciphers
class GAE_Finder(BaseHTTPUtil):

    httpreq = b'HEAD / HTTP/1.1\r\nAccept: */*\r\nHost: www.google.com\r\nConnection: Close\r\n\r\n'
    ssl_ciphers = gws_ciphers

    def getipinfo(self, ip, retry=None):
        if ipnotuse(ip):
            return None, 0, ''
        start_time = time()
        costtime = 0
        domains = None
        servername = ''
        sock = None
        ssl_sock = None
        try:
            sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
            ssl_sock = self.get_ssl_socket(sock, b'www.google.com')
            ssl_sock.settimeout(g_conntimeout)
            ssl_sock.connect((ip, 443))
            ssl_sock.settimeout(g_handshaketimeout)
            ssl_sock.do_handshake()
            handshaked_time = time() - start_time
            ssl_sock.settimeout(g_timeout)
            if handshaked_time > g_handshaketimeout:
                raise socket.error('handshake cost %dms timed out' % int(handshaked_time*1000))
            cert = self.get_peercert(ssl_sock)
            if not cert:
                raise socket.error(u"无法从 %s 获取证书。", ip)
            domains = self.getdomains(cert)
            if not domains:
                raise ssl.SSLError(u"%s 无法获取 commonName：%s " % (ip, cert))
        except NetWorkIOError as e:
            sock.close()
            ssl_sock = None
            if not retry and e.args == (-1, 'Unexpected EOF'):
                return self.getipinfo(ip, True)
            WARNING('%r', e)
        if ssl_sock:
            servername = self.getservername(ssl_sock, sock, ip)
        costtime = int((time()-start_time)*1000)
        return domains, costtime, servername

    def getdomains(self, cert):
        for i in xrange(cert.get_extension_count()):
            extension = cert.get_extension(i)
            if extension.get_short_name() == b'subjectAltName':
                 return tuple(x[4:] for x in str(extension).split(', '))
        return (cert.get_subject().CN,)

    def getservername(self, conn, sock, ip):
        try:
            begin = time()
            conn.send(self.httpreq)
            data = conn.read(1024)
            costime = time() - begin
            if costime >= g_timeout:
                WARNING(u'获取 http 响应超时(%ss)，ip：%s', costime, ip)
                return ''
            if PY3:
                data = data.decode()
            index = data.find('\r\n\r\n')
            if index > 0:
                return getservernamefromheader(data, index)
            return ''
        except Exception as e:
            WARNING(u'从 %s 获取服务名称时发生错误：%r', ip, e)
            return ''
        finally:
            sock.close()

gae_finder = GAE_Finder(g_useOpenSSL, g_cacertfile)

def runfinder(ip):
    ssldomains, costtime, servername = gae_finder.getipinfo(ip)
    statistics = g.statistics
    baddict = g.baddict
    with gLock:
        g.pingcnt -= 1
        remain = len(g.goodlist) + len(g.ipexlist) + len(g.iplist) + len(g.weaklist) + g.pingcnt
    #判断是否可用
    if isgaeserver(servername):
        if ip in baddict: #删除未到容忍次数的 badip
            del baddict[ip]
        PRINT(u'剩余：%s，%s，%sms，%s', str(remain).rjust(4), ip.rjust(15),
              str(costtime).rjust(4), ssldomains[0])
        com = yt = gs = 0
        for domain in ssldomains:
            if com == 0 and 'google.' in domain:
                com = 1
            if yt == 0 and 'youtube.' in domain or 'ytimg' in domain:
                yt = 1
            if gs == 0 and 'gstatic.' in domain:
                gs = 1
            if com == yt == gs == 1:
                break
        #判断是否够快
        if costtime < g.maxhandletimeout:
            g.gaelist.append((ip, costtime, com, yt, gs))
            with gLock:
                #计数
                g.needgwscnt -= 1
                if com:
                    g.needcomcnt -= 1
        else:
            #备用
            g.gaelistbak.append((ip, costtime, com, yt, gs))
            for ipdict in statistics:
                if ip in ipdict:
                    ipdict[ip] = max(ipdict[ip][0]-1, 0), ipdict[ip][1]
    else:
        for ipdict in statistics:
            if ip in ipdict:
                 good, bad = ipdict[ip]
                 if good < 0: break
                 #失败次数超出预期，设置 -1 表示删除
                 if bad/max(good, 1) > 10:
                     ipdict[ip] = -1, 0
                 else:
                     ipdict[ip] = max(good-1, 0), bad+1
        if ip in baddict: # badip 容忍次数 +1
            baddict[ip] = baddict[ip][0]+1, int(time())
        else: #记录检测到 badip 的时间
            baddict[ip] = 1, int(time())
    #满足数量后停止
    if g.needcomcnt < 1 and g.needgwscnt < 1:
        return True

class Finder(threading.Thread):
    #线程默认运行函数
    def run(self):
        ip = randomip()
        while ip:
            if runfinder(ip):
                break
            ip = randomip()

def _randomip(iplist):
    cnt = len(iplist)
    a = random.randint(0, cnt - 1)
    b = int(random.random() * (cnt - 0.1))
    if random.random() > 0.7: #随机分布概率偏向较小数值
        n =  max(a, b)
    else:
        n =  min(a, b)
    ip = iplist[n]
    del iplist[n]
    g.pingcnt += 1
    return ip

def randomip():
    with gLock:
        g.getgood -= 1
        if g.goodlist and g.getgood <= 0:
            g.getgood = 3
            return g.goodlist.pop()
        elif g.ipexlist:
            return _randomip(g.ipexlist)
        elif g.iplist:
            return _randomip(g.iplist)
        elif g.goodlist:
            return g.goodlist.pop()
        elif g.weaklist:
            return _randomip(g.weaklist)
    return

g.running = False
g.reloadlist = False
g.ipmtime = 0
g.ipexmtime = 0
g.statistics = readstatistics()
g.baddict = readbadlist()
def getgaeip(nowgaelist=[], needcomcnt=0, threads=None):
    if g.running:
        return
    #获取参数
    g.running = True
    nowgaeset = set(nowgaelist)
    g.needgwscnt = needgwscnt = max(g_maxgaeipcnt - len(nowgaeset), 0)
    g.needcomcnt = needcomcnt
    if needgwscnt == needcomcnt == 0:
        g.running = False
        return
    threads = int(threads) or g_maxthreads
    #日期变更、重新加载统计文件
    if not g.statisticsfiles[0].endswith(strftime('%y%j')):
        savestatistics()
        g.statistics = readstatistics()
    statistics = g.statistics[0]
    statistics = [(ip, stats[0], stats[1]) for ip, stats in statistics.items() if ip not in nowgaeset and stats[0] >= 0]
    #根据统计数据排序（bad 降序、good 升序）供 pop 使用
    statistics.sort(key=lambda x: ((x[1] or 0.9)*1.7/(x[2]*x[2] or 0.1), -x[2]))
    g.goodlist = [ip[0] for ip in statistics]
    #检查 IP 数据修改时间
    ipmtime = ipexmtime = 0
    if os.path.exists(g_ipfile):
        ipmtime = os.path.getmtime(g_ipfile)
    if os.path.exists(g_ipexfile):
        ipexmtime = os.path.getmtime(g_ipexfile)
    if ipmtime > g.ipmtime or ipexmtime > g.ipexmtime:
        # 更新过 IP 列表
        g.ipmtime = ipmtime
        g.ipexmtime = ipexmtime
        g.ipexlist, g.iplist, g.weaklist = readiplist(nowgaeset)
    elif (len(g.weaklist) < g.halfweak or    # 上一次加载 IP 时出过错的 IP
             time() - g.readtime > 8*3600 or # n 小时强制重载 IP
             g.reloadlist or
             len(g.ipexlist) == len(g.iplist) == len(g.weaklist) == 0):
        g.ipexlist, g.iplist, g.weaklist = readiplist(nowgaeset)
    del nowgaelist, nowgaeset, statistics
    g.getgood = 0
    g.gaelist = []
    g.gaelistbak = gaelistbak = []
    g.pingcnt = 0
    g.maxhandletimeout = g_maxhandletimeout + timeToDelay[int(strftime('%H'))]
    PRINT(u'==================== 开始查找 GAE IP ====================')
    PRINT(u'需要查找 IP 数：%d/%d，待检测 IP 数：%d', needcomcnt, needgwscnt if needgwscnt > needcomcnt else needcomcnt, len(g.goodlist)+len(g.ipexlist)+len(g.iplist)+len(g.weaklist))
    #多线程搜索
    threadiplist = []
    for i in xrange(threads):
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
    m = g.needcomcnt
    if m > 0 and gaelistbak:
        #补齐个数，以 google_com 为准
        gaelistbak.sort(key=lambda x: (-x[2], x[1]))
        comlistbak, gaelistbak = gaelistbak[:m], gaelistbak[m:]
        g.gaelist.extend(comlistbak)
        m = len(comlistbak)
    else:
        m = 0
    n = g.needgwscnt - m
    if n > 0 and gaelistbak:
        #补齐个数
        gaelistbak.sort(key=lambda x: x[1])
        gwslistbak = gaelistbak[:m]
        g.gaelist.extend(gwslistbak)
        n = len(gwslistbak)
    else:
        n = 0
    gaelist = {'google_gws':[], 'google_com':[], 'google_yt':[], 'google_gs':[]}
    for ip in g.gaelist:
        gaelist['google_gws'].append(ip[0])
        if ip[2]:
            gaelist['google_com'].append(ip[0])
        if ip[3]:
            gaelist['google_yt'].append(ip[0])
        if ip[4]:
            gaelist['google_gs'].append(ip[0])
    if m > 0 or n > 0:
        PRINT(u'未找到足够的优质 GAE IP，添加 %d 个备选 IP：\n %s', m + n, ' | '.join(gaelist['google_gws']))
    else:
        PRINT(u'已经找到 %d 个新的优质 GAE IP：\n %s', len(gaelist['google_gws']), ' | '.join(gaelist['google_gws']))
    PRINT(u'==================== GAE IP 查找完毕 ====================')
    g.running = False

    return gaelist

if __name__ == '__main__':
    getgaeip()
