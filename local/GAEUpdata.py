# coding:utf-8
'''Auto check and updata GAE IP'''

import os
import threading
import re
from time import time, sleep
from compat import (
    thread,
    ConfigParser,
    logging,
    Queue
    )
from common import config_dir, testip, isip, dns
from GlobalConfig import GC

tLock = threading.Lock()

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
    logging.test(u'连接测试开始')
    badip = set()
    for ip in iplist:
        thread.start_new_thread(http_util.create_ssl_connection, ((ip, 443), GC.FINDER_TESTTIMEOUT, testip.queobj))
    for i in xrange(niplist):
        result = testip.queobj.get()
        if isinstance(result, Exception):
            ip = result.xip[0]
            logging.warning(u'连接失败 %s：%r' % ('.'.join(x.rjust(3) for x in ip.split('.')), result))
            badip.add(ip)
        else:
            logging.test(u'测试连接 %s: %d' %('.'.join(x.rjust(3) for x in result[0].split('.')), int(result[1]*1000)))
    #删除 bad IP
    nbadip = len(badip)
    if nbadip > 0:
        iplist = list(set(iplist) - badip)
        _refreship(iplist)
        logging.test(u'Bad IP 删除完毕')
    logging.test(u'连接测试完毕')
    # IP 慢速计数归零
    http_util.outtimes = 0
    testip.lasttest = time()
    testip.lastactive = testip.lasttest
    testip.running = False
    #刷新开始
    if nbadip > 3 or niplist - nbadip < GC.FINDER_MINIPCNT:
        updataip()

def testgaeip():
    with tLock:
        if (time() - testip.lasttest < 30  #强制 30 秒间隔
                or updataip.running or testip.running ):
            return
        testip.running = True
    thread.start_new_thread(_testgaeip, ())

def testipserver():
    while True:
        if not testip.lastactive:                   #启动时
            testgaeip()
        elif time() - testip.lastactive > 60 * 6:   # X 分钟未使用
                #and not GC.PROXY_ENABLE             #无代理
            testgaeip()
        sleep(60)

from GAEFinder import getgaeip
from HTTPUtil import http_util
