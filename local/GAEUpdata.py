# coding:utf-8
'''Auto check and updata GAE IP'''

import os
import sys
import threading
import re
from . import clogging as logging
from time import time, sleep, strftime
from .compat import (
    PY3,
    thread,
    ConfigParser,
    xrange,
    Queue
    )
from .common import config_dir
from .common.dns import dns
from .GlobalConfig import GC
from .ProxyServer import network_test

lLock = threading.Lock()
tLock = threading.Lock()

class testip():
    running = False
    lastactive = None
    queobj = Queue.Queue()
    lastupdata = time()
    lasttest = lastupdata - 30

def removeip(ip):
    with lLock:
        for name in GC.IPLIST_MAP:
            try:
                GC.IPLIST_MAP[name].remove(ip)
            except:
                pass
    testip.lastupdata = time()

def addtoblocklist(ip):
    removeip(ip)
    finder.badlist[ip] = [GC.FINDER_TIMESBLOCK+1, int(time())]
    savebadlist()

def _refreship(gaeip):
    with lLock:
        for name in gaeip:
            GC.IPLIST_MAP[name][:] = gaeip[name] + GC.IPLIST_MAP[name]
    testip.lastupdata = time()

def refreship(threads=None):
    threading.current_thread().setName('Ping-IP')
    #检测当前 IP 并搜索新的 IP
    network_test()
    gaeip = getgaeip(GC.IPLIST_MAP['google_gws'], GC.FINDER_MINIPCNT/3-len(GC.IPLIST_MAP['google_com']), threads)
    #更新 IP
    if gaeip and len(gaeip['google_gws']) > 0:
        _refreship(gaeip)
        #更新 proxy.user.ini
        cf = ConfigParser()
        cf.read(GC.CONFIG_IPDB)
        for name in gaeip:
            cf.set("iplist", name, '|'.join(x for x in GC.IPLIST_MAP[name]))
        cf.write(open(GC.CONFIG_IPDB, "w"))
        logging.test(u'GAE IP 更新完毕')
    if GC.IPLIST_MAP['google_gws'] < GC.FINDER_MINIPCNT:
        logging.warning(u'没有检测到足够数量符合要求的 GAE IP，请重新设定参数！')
    #更新完毕
    sleep(10)
    updataip.running = False

def updataip(threads=None):
    with tLock:
        if updataip.running: #是否更新
            return
        updataip.running = True
    thread.start_new_thread(refreship, (threads,))
updataip.running = False

def gettimeout():
    nowtime = int(strftime('%H'))
    timeout = max(GC.FINDER_MAXTIMEOUT*1.3, 1000) + min(len(GC.IPLIST_MAP['google_gws']), 20)*10 + timeToDelay[nowtime]
    return int(timeout)

def _testallgaeip():
    iplist = GC.IPLIST_MAP['google_gws']
    niplist = len(iplist or [])
    if niplist == 0:
        return updataip()
    badip = set()
    timeout = gettimeout()
    logging.test(u'连接测试开始，超时：%d 毫秒', timeout)
    network_test()
    testip.queobj.queue.clear()
    for ip in iplist:
        thread.start_new_thread(http_gws.create_ssl_connection, ((ip, 443), timeout/1000.0, testip.queobj))
    for i in xrange(niplist):
        result = testip.queobj.get()
        if isinstance(result, Exception):
            ip = result.xip[0]
            logging.warning(u'测试失败 %s：%s' % ('.'.join(x.rjust(3) for x in ip.split('.')), result.args[0]))
            badip.add(ip)
        else:
            logging.test(u'测试连接 %s: %d' %('.'.join(x.rjust(3) for x in result[0].split('.')), int(result[1]*1000)))
    #删除 bad IP
    nbadip = len(badip)
    if nbadip > 0:
        for ip in badip:
            removeip(ip)
    logging.test(u'连接测试完毕%s', u'，Bad IP 已删除' if nbadip > 0 else '')
    testip.lasttest = time()
    testip.lastactive = testip.lasttest
    testip.running = False
    #刷新开始
    if len(GC.IPLIST_MAP['google_gws']) < GC.FINDER_MINIPCNT or len(GC.IPLIST_MAP['google_com']) < GC.FINDER_MINIPCNT/3:
        updataip()

def _testonegaeip():
    ip = GC.IPLIST_MAP['google_gws'][-1]
    timeout = gettimeout()
    badip = False
    statistics = finder.statistics
    network_test()
    testip.queobj.queue.clear()
    thread.start_new_thread(http_gws.create_ssl_connection, ((ip, 443), timeout/1000.0, testip.queobj))
    result = testip.queobj.get()
    if isinstance(result, Exception):
        logging.warning(u'测试失败（超时：%d 毫秒）%s：%s，Bad IP 已删除' % (timeout,  '.'.join(x.rjust(3) for x in ip.split('.')), result.args[0]))
        removeip(ip)
        badip = True
        if ip in statistics:
            statistics[ip] = statistics[ip][0], statistics[ip][1]+1
        else:
            statistics[ip] = 0, 1
    else:
        logging.test(u'测试连接（超时：%d 毫秒）%s: %d' %(timeout,  '.'.join(x.rjust(3) for x in result[0].split('.')), int(result[1]*1000)))
        GC.IPLIST_MAP['google_gws'].insert(0, GC.IPLIST_MAP['google_gws'].pop())
        if ip in statistics:
            statistics[ip] = statistics[ip][0]+1, statistics[ip][1]
        else:
            statistics[ip] = 1, 0
    savestatistics()
    testip.lasttest = time()
    testip.running = False
    #刷新开始
    if len(GC.IPLIST_MAP['google_gws']) < GC.FINDER_MINIPCNT or len(GC.IPLIST_MAP['google_com']) < GC.FINDER_MINIPCNT/3:
        updataip(2)
    elif badip:
        _testonegaeip()

def testallgaeip(force=False):
    with tLock:
        if updataip.running:
            return
        elif force:
            if testip.running == 9:
                return
            while testip.running == 1:
                sleep(0.2)
        elif testip.running:
            return
        testip.running = 9
    thread.start_new_thread(_testallgaeip, ())
    return True

def testonegaeip():
    with tLock:
        if (updataip.running
                or time() - testip.lasttest < 10  #强制 10 秒间隔
                or testip.running):
            return
        testip.running = 1
    thread.start_new_thread(_testonegaeip, ())

def testipserver():
    while True:
        try:
            if not testip.lastactive:                    #启动时
                testallgaeip()
            elif (time() - testip.lastactive > 150/(len(GC.IPLIST_MAP['google_gws']) or 1) or # X 秒钟未使用
                    time() - testip.lasttest > 30):  #强制 X 秒钟检测
                    #and not GC.PROXY_ENABLE              #无代理
                testonegaeip()
        except Exception as e:
            logging.error(u' IP 测试守护线程错误：%r', e)
        finally:
            sleep(3)

from .GAEFinder import (
    g as finder,
    timeToDelay,
    getgaeip,
    savestatistics,
    savebadlist
    )
from .HTTPUtil import http_gws
