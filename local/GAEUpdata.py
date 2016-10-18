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

#自动更新 GAE IP
class UpdataGAEIP(object):
    running = False
    tLock = threading.Lock()

    def flashstart(self, ip):
        with self.tLock:
            if self.running: #是否更新
                return
            self.running = True
        if isinstance(ip, set):
            self.ip = ip
        elif ip is None:
            self.ip = set()
        else:
            self.ip = set(ip)
        threading.current_thread().setName('Ping-IP')
        self.flashgaeip()

    def _flashgaeip(self, gaeip):
            with self.tLock:
                GC.IPLIST_MAP[GC.GAE_LISTNAME] = gaeip
                for appid in GC.GAE_APPIDS:
                    host = '%s.appspot.com' % appid
                    dns[host] = gaeip
            testip.lasttest = time()

    def flashgaeip(self):
        #检测当前 IP 并搜索新的 IP
        gaeip = getgaeip(set(GC.IPLIST_MAP[GC.GAE_LISTNAME]) - self.ip)
        if gaeip and len(gaeip) > 0:
            #更新 IP
            self._flashgaeip(gaeip)
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
            logging.warning(u'没有检测到符合要求的 GAE IP，请重新设定参数！')
        #更新完毕
        sleep(10)
        with self.tLock:
            self.running = False

updataip = UpdataGAEIP()

def flashgaeip(ip=None):
    thread.start_new_thread(updataip.flashstart, (ip,))

#测试 GAE IP
def _testgaeip():
    iplist = GC.IPLIST_MAP[GC.GAE_LISTNAME]
    niplist = len(iplist)
    if niplist < GC.FINDER_MINIPCNT:
        return flashgaeip()
    if ((time() - testip.lasttest < 30)  #强制 30 秒间隔
            or testip.qcount > niplist//3          #未完成的 GAE 请求个数
            or testip.running or updataip.running):
        return
    testip.running = True
    logging.test(u'连接测试开始')
    logging.info(' | '.join(iplist))
    badip = set()
    flaship = False
    for ip in iplist:
        thread.start_new_thread(http_util.create_ssl_connection, ((ip, 443), 5, testip.queobj))
    for i in xrange(niplist):
        result = testip.queobj.get()
        if isinstance(result, Exception):
            ip = result.xip[0]
            logging.warning(u'连接失败 %s：%r' % ('.'.join(x.rjust(3) for x in ip.split('.')), result))
            badip.add(ip)
        else:
            logging.test(u'测试连接 %s: %d' %('.'.join(x.rjust(3) for x in result[0].split('.')), int(result[1]*1000)))
    #刷新开始
    nbadip = len(badip)
    if nbadip > 3 or niplist - nbadip < GC.FINDER_MINIPCNT:
        flaship = True
        flashgaeip(badip)
    #没有刷新、删除 bad IP
    if not flaship and nbadip > 0 and not updataip.running:
        iplist = list(set(iplist) - badip)
        updataip._flashgaeip(iplist)
        logging.test(u'Bad IP 删除完毕')
    logging.info(' | '.join(iplist))
    logging.test(u'连接测试完毕')
    # IP 慢速计数归零
    http_util.outtimes = 0
    testip.lasttest = time()
    testip.lastactive = testip.lasttest
    testip.running = False

def testgaeip():
    if not testip.running:
        thread.start_new_thread(_testgaeip, tuple())

def testipserver():
    while True:
        if time() - testip.lastupdata > 3600 * 4:    #强制 4 小时更新 IP
            flashgaeip()
            testip.lastactive = testip.lasttest
        elif not testip.lastactive:                        #启动时
            _testgaeip()
        elif (time() - testip.lastactive > 60 * 6   # X 分钟未使用
                #and not GC.PROXY_ENABLE                   #无代理
                and not updataip.running):                #可以刷新 IP
            _testgaeip()
        sleep(60)

from GAEFinder import getgaeip
from HTTPUtil import http_util
