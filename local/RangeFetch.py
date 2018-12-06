# coding:utf-8
'''Range Fetch Util'''


import re
import threading
import random
import logging
from time import time, sleep
from .compat import Queue, thread, urlparse
from .common import spawn_later
from .GAEFetch import qGAE, get_appid, mark_badappid, gae_urlfetch
from .GlobalConfig import GC
from .HTTPUtil import http_gws
from .GAEUpdate import testip, testallgaeip

ssl_connection_cache = http_gws.ssl_connection_cache
getrange = re.compile(r'bytes (\d+)-(\d+)/(\d+)').search

class RangeFetch:
    '''Range Fetch Class'''

    delable = GC.GAE_TESTGWSIPLIST
    Lock = threading.Lock()
    lastactive = 0
    obj = 0

    def __init__(self, handler, headers, payload, response):
        self.tLock = threading.Lock()
        self.expect_begin = 0
        self._stopped = False
        self._last_app_status = {}
        self.lastupdate = testip.lastupdate
        self.iplist = GC.IPLIST_MAP['google_gws'].copy()

        self.handler = handler
        self.write = handler.wfile.write
        self.bufsize = handler.bufsize
        self.command = handler.command
        self.host = handler.host
        self.range_end = handler.range_end
        self.url = handler.url
        self.headers = headers
        self.payload = payload
        self.response = response

    def fetch(self):
        with RangeFetch.Lock:
            RangeFetch.obj += 1
            needtest = RangeFetch.obj is 1
        isRangeFetchBig = self.__class__ is RangeFetchBig
        response = self.response
        response_status = response.status
        response_headers = dict((k.title(), v) for k, v in response.headers.items())
        if 'Content-Range' in response_headers:
            start, end, length = tuple(int(x) for x in getrange(response_headers['Content-Range']).group(1, 2, 3))
            content_length = end + 1 - start
            del response_headers['Content-Range']
        else:
            start = end = 0
            content_length = length = int(response.headers['Content-Length'])
        _end = length - 1
        if isRangeFetchBig and content_length > GC.AUTORANGE_BIG_MAXSIZE and end - start != GC.GAE_MAXSIZE:
            #大于单线程限制且不等于服务端失败时的重试长度，放弃响应结果
            response.close()
            self.response = None
            end = start - 1
        if start is 0 and self.range_end in (0, _end) and 'Range' not in self.handler.headers:
            response_status = 200
            response_headers['Content-Length'] = str(length)
            range_end = _end
        else:
            range_end = self.range_end or _end
            response_headers['Content-Range'] = 'bytes %s-%s/%s' % (start, range_end, length)
            length = range_end + 1
            response_headers['Content-Length'] = str(length - start)

        try:
            self.handler.write(('HTTP/1.1 %s\r\n%s\r\n' % (response_status, ''.join('%s: %s\r\n' % (k, v) for k, v in response_headers.items()))))
        except Exception as e:
            logging.info('%s RangeFetch 本地连接断开：%r, %r', self.address_string(response), self.url, e)
            self.record()
            return
        logging.info('%s >>>>>>>>>>>>>>> RangeFetch 开始 %r %d-%d', self.address_string(response), self.url, start, range_end)

        #开始多线程时先测试一遍 IP
#        if isRangeFetchBig:
#            sleeptime = self.sleeptime
#            if needtest and time() - RangeFetch.lastactive > 30:
#                testallgaeip(True)
#        else:
#            sleeptime = self.sleeptime if needtest and time() - RangeFetch.lastactive > 30 and testallgaeip(True) else 0

        data_queue = Queue.PriorityQueue()
        range_queue = Queue.PriorityQueue()
        if self.response is not None:
            self.firstrange = start, end
        # py2 弃用，xrange 参数太大时会出错，range 不出错但耗时太多
        #for begin in range(end+1, length, self.maxsize):
        #    range_queue.put((begin, min(begin+self.maxsize-1, length-1)))
        a = end + 1
        b = end
        n = (length - a) // self.maxsize
        for _ in range(n):
            b += self.maxsize
            range_queue.put((a, b))
            a = b + 1
        if length > a:
            range_queue.put((a, length - 1))

        for i in range(self.threads):
            if isRangeFetchBig:
                spawn_later(self.sleeptime * i if i else 0, self.__fetchlet, range_queue, data_queue, i + 1)
            else:
                spawn_later(self.sleeptime if i else 0, self.__fetchlet, range_queue, data_queue, i + 1)
        has_peek = hasattr(data_queue, 'peek')
        peek_timeout = 30
        self.expect_begin = start
        while self.expect_begin < length:
            try:
                if has_peek:
                    begin, data = data_queue.peek(timeout=peek_timeout)
                    if self.expect_begin == begin:
                        data_queue.get()
                    elif self.expect_begin < begin:
                        sleep(0.1)
                        continue
                    else:
                        logging.error('%s RangeFetch 错误：begin(%r) < expect_begin(%r)，退出', self.address_string(), begin, self.expect_begin)
                        break
                else:
                    begin, data = data_queue.get(timeout=peek_timeout)
                    if self.expect_begin == begin:
                        pass
                    elif self.expect_begin < begin:
                        data_queue.put((begin, data))
                        sleep(0.1)
                        continue
                    else:
                        logging.error('%s RangeFetch 错误：begin(%r) < expect_begin(%r)，退出', self.address_string(), begin, self.expect_begin)
                        break
            except Queue.Empty:
                logging.error('%s data_queue peek 超时，break', self.address_string())
                break
            try:
                self.write(data)
                self.expect_begin += len(data)
            except Exception as e:
                logging.info('%s RangeFetch 本地连接断开：%r, %r', self.address_string(), self.url, e)
                break
        else:
            logging.info('%s RangeFetch 成功完成 %r', self.address_string(), self.url)
        self._stopped = True
        self.record()
        if self.expect_begin < length:
            self.handler.close_connection = True

    def address_string(self, response=None):
        return self.handler.address_string(response)

    def record(self):
        with RangeFetch.Lock:
            RangeFetch.obj -= 1
        RangeFetch.lastactive = time()

    def __fetchlet(self, range_queue, data_queue, threadorder):
        headers = dict((k.title(), v) for k, v in self.headers.items())
        headers['Connection'] = 'close'
        while True:
            try:
                with self.tLock:
                    if self.lastupdate != testip.lastupdate:
                        self.lastupdate = testip.lastupdate
                        self.iplist = GC.IPLIST_MAP['google_gws'].copy()
                noerror = True
                response = None
                starttime = None
                appid = None
                if self._stopped: return
                try:
                    if self.response:
                        response = self.response
                        self.response = None
                        start, end = self.firstrange
                    else:
                        appid = get_appid()
                        if self._last_app_status.get(appid, 200) >= 500:
                            sleep(2)
                        start, end = range_queue.get(timeout=1)
                    headers['Range'] = 'bytes=%d-%d' % (start, end)
                    while (start - self.expect_begin) / self.delaysize > 4.0 and data_queue.qsize() * self.bufsize / self.delaysize > 8.0:
                        if self._stopped: return
                        sleep(0.1)
                    if appid:
                        response = gae_urlfetch(self.command, self.url, headers, self.payload, appid, getfast=self.timeout)
                    if response:
                        if appid:
                            self._last_app_status[appid] = response.app_status
                        xip = response.xip[0]
                        if xip in self.iplist:
                            realstart = start
                            starttime = time()
                        else:
                            range_queue.put((start, end))
                            noerror = False
                            continue
                except Queue.Empty:
                    appid = None
                    return
                except Exception as e:
                    logging.warning('%s Response %r in __fetchlet', self.address_string(response), e)
                    range_queue.put((start, end))
                    continue
                if self._stopped: return
                if not response:
                    logging.warning('%s RangeFetch %s 没有响应，重试', self.address_string(response), headers['Range'])
                    range_queue.put((start, end))
                elif response.app_status == 503:
                    if appid:
                        mark_badappid(appid)
                    range_queue.put((start, end))
                    noerror = False
                elif response.app_status != 200:
                    logging.warning('%s Range Fetch "%s %s" %s 返回 %s', self.address_string(response), self.command, self.url, headers['Range'], response.app_status)
                    range_queue.put((start, end))
                    noerror = False
                elif response.getheader('Location'):
                    self.url = urlparse.urljoin(self.url, response.getheader('Location'))
                    logging.info('%s RangeFetch Redirect(%r)', self.address_string(response), self.url)
                    range_queue.put((start, end))
                elif 200 <= response.status < 300:
                    content_range = response.getheader('Content-Range')
                    if not content_range:
                        logging.warning('%s RangeFetch "%s %s" 返回 Content-Range=%r: response headers=%r', self.address_string(response), self.command, self.url, content_range, response.getheaders())
                        range_queue.put((start, end))
                        continue
                    content_length = int(response.getheader('Content-Length', 0))
                    logging.info('%s >>>>>>>>>>>>>>> %s: 线程 %s %s %s', self.address_string(response), self.host, threadorder, content_length, content_range)
                    try:
                        data = response.read(self.bufsize)
                        while data:
                            data_queue.put((start, data))
                            start += len(data)
                            if self._stopped: return
                            if (start-realstart) / (time()-starttime) < self.lowspeed:
                                #移除慢速 ip
                                if self.delable: 
                                    with self.tLock:
                                        if xip in self.iplist and len(self.iplist) > self.minip:
                                            self.iplist.remove(xip)
                                            logging.warning('%s RangeFetch 移除慢速 ip %s', self.address_string(), xip)
                                noerror = False
                                break
                            else:
                                data = response.read(self.bufsize)
                    except Exception as e:
                        noerror = False
                        logging.warning('%s RangeFetch "%s %s" %s 失败：%r', self.address_string(response), self.command, self.url, headers['Range'], e)
                    if self._stopped: return
                    if start < end + 1:
                        logging.warning('%s RangeFetch "%s %s" 重试 %s-%s', self.address_string(response), self.command, self.url, start, end)
                        range_queue.put((start, end))
                        continue
                    logging.info('%s >>>>>>>>>>>>>>> %s: 线程 %s 成功接收到 %d 字节', self.address_string(response), self.host, threadorder, start)
                else:
                    logging.error('%s RangeFetch %r 返回 %s', self.address_string(response), self.url, response.status)
                    range_queue.put((start, end))
                    noerror = False
            except Exception as e:
                logging.exception('%s RangeFetch._fetchlet 错误：%r', self.address_string(), e)
                noerror = False
                raise
            finally:
                if appid:
                    qGAE.put(True)
                if response:
                    response.close()
                    if noerror:
                        #放入套接字缓存
                        ssl_connection_cache['google_fe:443'].append((time(), response.sock))
                    elif self.delable:
                        with self.tLock:
                             if xip in self.iplist and len(self.iplist) > self.minip:
                                self.iplist.remove(xip)
                                logging.warning('%s RangeFetch 移除故障 ip %s', self.address_string(response), xip)
                if noerror:
                    sleep(0.1)

class RangeFetchFast(RangeFetch):
    maxsize = GC.AUTORANGE_FAST_MAXSIZE or 1024 * 1024 * 4
    threads = GC.AUTORANGE_FAST_THREADS or 2
    minip = max(threads-2, 3)
    lowspeed = GC.AUTORANGE_FAST_LOWSPEED or 1024 * 32
    timeout = max(GC.FINDER_MAXTIMEOUT / 1000, 0.8)
    sleeptime = GC.FINDER_MAXTIMEOUT / 500.0
    delaysize = max(min(maxsize, 1024 * 1024), 1024 * 128)

class RangeFetchBig(RangeFetch):
    maxsize = GC.AUTORANGE_BIG_MAXSIZE or 1024 * 1024 * 4
    threads = GC.AUTORANGE_BIG_THREADS or 2
    minip = int(threads * 1.5)
    lowspeed = GC.AUTORANGE_BIG_LOWSPEED or 0
    timeout = max(GC.LINK_FWDTIMEOUT, 5)
    sleeptime = GC.AUTORANGE_BIG_SLEEPTIME
    delaysize = GC.AUTORANGE_BIG_ONSIZE / 4

RangeFetchs = None, RangeFetchFast, RangeFetchBig
