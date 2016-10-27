# coding:utf-8
'''Auto check and updata GAE IP'''

import os
import sys
import threading
import re
import clogging as logging
from time import time, sleep, strftime
from compat import (
    thread,
    ConfigParser,
    xrange,
    Queue
    )
from common import config_dir, testip, isip
from common.dns import dns
from GlobalConfig import GC

tLock = threading.Lock()
fLock = threading.Lock()

def addtoblocklist(ip):
    with fLock:
        badlist = readbadlist()
        badlist[ip] = [timesblock+1, time()]
        savebadlist(badlist)

def _refreship(gaeip):
        with tLock:
            GC.IPLIST_MAP[GC.GAE_LISTNAME] = gaeip
            for appid in GC.GAE_APPIDS:
                host = '%s.appspot.com' % appid
                dns[host] = gaeip
        testip.lasttest = time()

def refreship():
    threading.current_thread().setName('Ping-IP')
    #检测当前 IP 并搜索新的 IP
    with fLock:
        gaeip = getgaeip(set(GC.IPLIST_MAP[GC.GAE_LISTNAME]))
    if gaeip and len(gaeip) >= GC.FINDER_MINIPCNT:
        #更新 IP
        _refreship(gaeip)
        # IP 慢速计数归零
        http_util.outtimes = 0
        #更新 proxy.user.ini
        cf = ConfigParser()
        cf.read(GC.CONFIG_USER_FILENAME)
        cf.set("iplist", GC.GAE_LISTNAME, '|'.join(x for x in gaeip))
        cf.write(open(GC.CONFIG_USER_FILENAME, "w"))
        logging.test(u'GAE IP 更新完毕')
        testip.lastupdata = testip.lastactive = testip.lasttest
    else:
        logging.warning(u'没有检测到足够数量符合要求的 GAE IP，请重新设定参数！')
    #更新完毕
    sleep(10)
    updataip.running = False

def updataip():
    with tLock:
        if updataip.running: #是否更新
            return
        updataip.running = True
    thread.start_new_thread(refreship, ())
updataip.running = False

def _testgaeip():
    iplist = GC.IPLIST_MAP[GC.GAE_LISTNAME]
    niplist = len(iplist)
    if niplist == 0:
        return updataip()
    if testip.qcount > niplist/3:  #未完成的 GAE 请求个数
        return
    badip = set()
    nowtime = int(strftime('%H'))
    testip.timeout = max(GC.FINDER_MAXTIMEOUT*1.5, 1000) + min(niplist, 20)*50 + timeToDelay[nowtime]
    logging.test(u'连接测试开始，超时：%d 毫秒', int(testip.timeout))
    testip.timeout = testip.timeout / 1000.0
    for ip in iplist:
        thread.start_new_thread(http_util.create_ssl_connection, ((ip, 443), testip.timeout, testip.queobj))
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
        iplist = list(set(iplist) - badip)
        _refreship(iplist)
    logging.test(u'连接测试完毕%s', u'，Bad IP 已删除' if nbadip > 0 else '')
    # IP 慢速计数归零
    http_util.outtimes = 0
    testip.lasttest = time()
    testip.lastactive = testip.lasttest
    testip.running = False
    #刷新开始
    if nbadip > 3 or niplist - nbadip < GC.FINDER_MINIPCNT:
        updataip()

def testgaeip(force=False):
    with tLock:
        if updataip.running or not force and (
                time() - testip.lasttest < 30  #强制 30 秒间隔
                or testip.running ):
            return
        testip.running = True
    thread.start_new_thread(_testgaeip, ())

def testipserver():
    while True:
        if not testip.lastactive:                    #启动时
            testgaeip()
        elif (time() - testip.lastactive > 60 * 6 or # X 分钟未使用
                time() - testip.lasttest > 60 * 9):  #强制 X 分钟检测
                #and not GC.PROXY_ENABLE              #无代理
            testgaeip()
        sleep(60)

from GAEFinder import (
    g_timesblock as timesblock,
    timeToDelay,
    getgaeip,
    readbadlist,
    savebadlist
    )
from HTTPUtil import http_util
