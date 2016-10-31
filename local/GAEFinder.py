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
from time import time, strftime
from .common import cert_dir, data_dir, NetWorkIOError
from .compat import PY3, xrange
from .GlobalConfig import GC

#全局只读写数据
#最大 IP 延时，单位：毫秒
g_maxhandletimeout = GC.FINDER_MAXTIMEOUT or 1000
#扫描得到的可用 IP 数量
g_maxgaeipcnt = GC.FINDER_IPCNT or 12
#扫描 IP 的线程数量
g_maxthreads = GC.FINDER_THREADS or 10
#容忍 badip 的次数
g_timesblock = GC.FINDER_TIMESBLOCK or 2
#屏蔽 badip 的时限，单位：小时
g_blocktime = GC.FINDER_BLOCKTIME or 36
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
g_badfile = os.path.join(data_dir, "ip_bad.txt")
g_badfilebak = os.path.join(data_dir, "ip_badbak.txt")

#加各时段 IP 延时，单位：毫秒
timeToDelay = {    0 :   0,
         1 :   0,  2 :   0,  3 :   0,  4 :   0,  5 :   0,  6 :   0, 
         7 :  50,  8 : 100,  9 :  50, 10 : 150, 11 : 250, 12 : 350,
        13 : 350, 14 : 300, 15 : 200, 16 : 250, 17 : 300, 18 : 350, 
        19 : 350, 20 : 300, 21 : 150, 22 :  50, 23 :   0, 24 :   0
        }

#全局可读写数据
class g: pass

gLock = threading.Lock()

def PRINT(fmt, *args, **kwargs):
    #logging.info(strlog)
    logging.info('[%s] %s' % (threading.current_thread().name, fmt), *args, **kwargs)

def WARNING(fmt, *args, **kwargs):
    logging.debug('[%s] %s' % (threading.current_thread().name, fmt), *args, **kwargs)

#读取 checkgoogleip 输出 ip.txt
def readiplist(badlist, nowgaelist):
    #判断是否屏蔽
    blocklist = set()
    lowlist = set()
    for ip in badlist:
        if badlist[ip][0] > g_timesblock:
            blocklist.add(ip)
        else:
            lowlist.add(ip)
    #正在使用的 IP 列外
    blocklist = blocklist - nowgaelist
    lowlist = lowlist - nowgaelist
    #整合优先检测 IP
    iplist = []
    if os.path.exists(g_ipfile + 'ex'):
            with open(g_ipfile + 'ex', "r") as fd:
                for line in fd:
                    iplist.append(line.strip('\r\n'))
    if os.path.exists(g_ipfile):
            with open(g_ipfile, 'r') as fd:
                for line in fd:
                    iplist.append(line.strip('\r\n'))
    #手动屏蔽列表
    for i in xrange(len(iplist) - 1, -1, -1):
        for ip in g_block:
            if iplist[i].startswith(ip):
                del iplist[i]
    iplist = set(iplist) - blocklist - lowlist - nowgaelist
    return list(iplist), list(lowlist)

def readbadlist():
    ipdict = {}
    if os.path.exists(g_badfile):
        with open(g_badfile, 'r') as fd:
            for line in fd:
                ips = line.strip('\r\n').split(' * ')
                if len(ips) == 3 and time() - float(ips[2]) < g_blocktime * 3600:
                    ipdict[ips[0]] = [int(ips[1]), float(ips[2])]
    return ipdict

def savebadlist(badlist=None):
    if os.path.exists(g_badfile):
        if os.path.exists(g_badfilebak):
            os.remove(g_badfilebak)
        os.rename(g_badfile, g_badfilebak)
    badlist = badlist or g.badlist
    op = 'wb'
    if PY3:
        op = 'w'
    with open(g_badfile, op) as f:
        for ip in badlist:
            f.write(' * '.join([ip, str(badlist[ip][0]), str(badlist[ip][1])]))
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

    def getssldomain(self, ip, retry=None):
        start_time = time()
        costtime = 0
        domain = None
        servername = ''
        sock = None
        ssl_sock = None
        try:
            sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
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
            subject = cert.get_subject()
            domain = subject.CN
            if domain is None:
                raise ssl.SSLError(u"%s 无法获取 commonName：%s " % (ip, subject))
        except NetWorkIOError as e:
            sock.close()
            ssl_sock = None
            if not retry and e.args == (-1, 'Unexpected EOF'):
                return self.getssldomain(ip, True)
            WARNING('%r', e)
        if ssl_sock:
            servername = self.getservername(ssl_sock, sock, ip)
        costtime = int((time() - start_time)*1000)
        return domain, costtime, servername

    def getservername(self, conn, sock, ip):
        try:
            begin = time()
            conn.send(self.httpreq)
            data = conn.read(1024)
            end = time()
            costime = int(end-begin)
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
    ssldomain, costtime, servername = gae_finder.getssldomain(ip)
    with gLock:
        g.pingcnt -= 1
        remain = len(g.iplist) + len(g.lowlist) + g.pingcnt
    #判断是否可用
    if isgaeserver(servername):
        if ip in g.badlist: #删除未到容忍次数的 badip
            del g.badlist[ip]
        PRINT(u'剩余：%s，%s，%sms，%s', str(remain).rjust(3), ip.rjust(15),
              str(costtime).rjust(4), ssldomain)
        #判断是否够快
        if costtime < g.maxhandletimeout:
            g.gaelist.append(ip)
        else:
            g.gaelistbak.append([ip, costtime]) #备用
    else:
        if ip in g.badlist: # badip 容忍次数 +1
            g.badlist[ip][0] += 1
            g.badlist[ip][1] = time()
        else: #记录检测到 badip 的时间
            g.badlist[ip] = [1, time()]
    #满足数量后停止
    if len(g.gaelist) >= g.maxgaeipcnt:
        return True

class Finder(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    #线程默认运行函数
    def run(self):
        ip = randomip()
        while ip:
            if runfinder(ip):
                break
            ip = randomip()

def _randomip(iplist):
    with gLock:
        cnt = len(iplist)
        if cnt < 1: # IP 检测完毕
            ip = False
        else:
            a = random.randint(0, cnt - 1)
            b = int(random.random() * (cnt - 0.1))
            if random.random() > 0.7: #随机分布概率偏向较小数值
                n =  max(a, b)
            else:
                n =  min(a, b)
            ip = iplist[n]
            del iplist[n]
        if ip:
            g.pingcnt += 1
    return ip

def randomip():
    ip = _randomip(g.iplist)
    if not ip:
        ip = _randomip(g.lowlist)
    return ip

g.running = False
def getgaeip(*args):
    if g.running:
        return None
    #初始化
    g.running = True
    nowtime = int(strftime('%H'))
    g.maxhandletimeout = g_maxhandletimeout + timeToDelay[nowtime]
    nowgaelist = args[0] if len(args) > 0 else set() #提取 IP 列表
    g.maxgaeipcnt = g_maxgaeipcnt - len(nowgaelist)
    g.badlist = readbadlist()
    g.iplist, g.lowlist = readiplist(g.badlist, nowgaelist)
    g.gaelist = []
    g.gaelistbak = []
    g.pingcnt = 0
    PRINT(u'==================== 开始查找 GAE IP ====================')
    PRINT(u'需要查找 IP 数：%d，待检测 IP 数：%d', g.maxgaeipcnt, len(g.iplist) + len(g.lowlist))
    #多线程搜索
    threadiplist = []
    for i in xrange(1, g_maxthreads + 1):
        ping_thread = Finder()
        ping_thread.setDaemon(True)
        ping_thread.setName('Ping-%s' % str(i).rjust(2, '0'))
        ping_thread.start()
        threadiplist.append(ping_thread)
    for p in threadiplist:
        p.join()
    #结果
    savebadlist()
    gn = len(g.gaelist)
    n = g.maxgaeipcnt - gn
    if n > 0:
        #补齐个数
        g.gaelistbak.sort(key = lambda x: x[1])
        g.gaelist += g.gaelistbak[:n]
        n -= g.maxgaeipcnt - len(g.gaelist)
        PRINT(u'未找到足够的优质 GAE IP，添加 %d 个备选 IP：\n %s', n, ' | '.join(g.gaelist))
    else:
        PRINT(u'已经找到 %d 个新的优质 GAE IP：\n %s', gn, ' | '.join(g.gaelist))
    PRINT(u'==================== GAE IP 查找完毕 ====================')
    g.running = False

    return list(set(g.gaelist) | nowgaelist)

if __name__ == '__main__':
    getgaeip()
