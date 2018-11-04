# coding:utf-8

import ssl
import zlib
import struct
import threading
import logging
from io import BytesIO
from time import time, timezone, localtime, strftime, strptime, mktime
from urllib.request import ProxyHandler, HTTPSHandler, build_opener
from .compat import Queue, httplib
from .GlobalConfig import GC
from .GAEUpdate import testipuseable
from .HTTPUtil import http_gws
from .common import LRUCache
from .common.decompress import GzipSock

timezone_PST = timezone - 3600 * 8 # UTC-8
timezone_PDT = timezone - 3600 * 7 # UTC-7
def get_refreshtime():
    #距离 GAE 流量配额每日刷新的时间
    #刷新时间是否遵循夏令时？
    now = time() + timezone_PST
    refreshtime = strftime('%y %j', localtime(now + 86400))
    refreshtime = mktime(strptime(refreshtime, '%y %j'))
    return refreshtime - now

nappid = 0
nLock = threading.Lock()
badappids = LRUCache(len(GC.GAE_APPIDS))
qGAE = Queue.LifoQueue()
for _ in range(GC.GAE_MAXREQUESTS * len(GC.GAE_APPIDS)):
    qGAE.put(True)

proxy_server = 'http://127.0.0.1:%d' % GC.LISTEN_AUTO_PORT
proxy_handler = ProxyHandler({
    'http': proxy_server,
    'https': proxy_server
})
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
context.verify_mode = ssl.CERT_NONE
https_handler = HTTPSHandler(context=context)
proxy_opener = build_opener(proxy_handler, https_handler)

def check_appid_exists(appid):
    response = proxy_opener.open('https://%s.appspot.com/' % appid)
    return response.status in (200, 503)

def get_appid():
    global nappid
    with nLock:
        while True:
            nappid += 1
            if nappid >= len(GC.GAE_APPIDS):
                nappid = 0
            appid = GC.GAE_APPIDS[nappid]
            contains, expired, _ = badappids.getstate(appid)
            if contains and expired:
                for _ in range(GC.GAE_MAXREQUESTS):
                    qGAE.put(True)
            if not contains or expired:
                break
        return appid

def mark_badappid(appid, time=None):
    if appid not in badappids:
        if time is None:
            time = get_refreshtime()
            if len(GC.GAE_APPIDS) - len(badappids) <= 1:
                logging.error('全部的 AppID 流量都使用完毕')
            else:
                logging.warning('当前 AppID[%s] 流量使用完毕，切换下一个…', appid)
        badappids.set(appid, True, time)
        for _ in range(GC.GAE_MAXREQUESTS):
            qGAE.get()

gae_options = []
if GC.GAE_DEBUG:
    gae_options.append('debug=%d' % GC.GAE_DEBUG)
if GC.GAE_PASSWORD:
    gae_options.append('password=' +  GC.GAE_PASSWORD)
if GC.GAE_SSLVERIFY:
    gae_options.append('sslverify')
if GC.GAE_MAXSIZE and GC.GAE_MAXSIZE != 1024 * 1024 * 4:
    gae_options.append('maxsize=%d' % GC.GAE_MAXSIZE)
gae_options = ','.join(gae_options)
if gae_options:
    gae_options = 'X-UrlFetch-Options: %s\r\n' % gae_options

def make_errinfo(response, htmltxt):
    del response.headers['Content-Type']
    del response.headers['Connection']
    response.headers['Content-Type'] = 'text/plain; charset=UTF-8'
    response.headers['Content-Length'] = len(htmltxt)
    response.fp = BytesIO(htmltxt)
    response.read = response.fp.read
    return response

class gae_params:
    port = 443
    ssl = True
    hostname = 'google_gws'
    path = GC.GAE_PATH
    command = 'POST'
    fetchhost = '%s.appspot.com'
    fetchserver = 'https://%s.appspot.com' + path

    __slots__ = 'host', 'url'

    def __init__(self, appid):
        self.host = self.fetchhost % appid
        self.url = self.fetchserver % appid

gae_params_dict = {}
for appid in GC.GAE_APPIDS:
    gae_params_dict[appid] = gae_params(appid)

def gae_urlfetch(method, url, headers, payload, appid, getfast=None, **kwargs):
    # GAE 代理请求不允许设置 Host 头域
    if 'Host' in headers:
        del headers['Host']
    metadata = '%s %s HTTP/1.1\r\n' % (method, url)
    metadata += ''.join('%s: %s\r\n' % (k, v) for k, v in headers.items())
    metadata += gae_options
    if not isinstance(metadata, bytes):
        metadata = metadata.encode()
    metadata = zlib.compress(metadata)[2:-4]
    if payload:
        if not isinstance(payload, bytes):
            payload = payload.encode()
        payload = struct.pack('!h', len(metadata)) + metadata + payload
    else:
        payload = struct.pack('!h', len(metadata)) + metadata
    request_headers = {
        'User-Agent': 'Mozilla/5.0',
        'Accept-Encoding': 'gzip',
        'Content-Length': str(len(payload))
        }
    request_params = gae_params_dict[appid]
    realurl = 'GAE-' + url
    qGAE.get() # get start from Queue
    while True:
        response = http_gws.request(request_params, payload, request_headers, connection_cache_key='google_fe:443', getfast=getfast, realmethod=method, realurl=realurl)
        if response is None:
            return
        app_server = response.headers.get('Server')
        if app_server == 'Google Frontend':
            break
        if GC.GAE_ENABLEPROXY:
            logging.warning('GAE 前置代理 [%s:%d] 无法正常工作', *response.xip)
            continue
        if testipuseable(response.xip[0]):
            break
        logging.warning('发现并移除非 GAE IP：%s，Server：%s', response.xip[0], app_server)
    response.app_status = response.status
    if response.status != 200:
        return response
    #解压并解析 chunked & gziped 响应
    if 'Transfer-Encoding' in response.headers:
        responseg = httplib.HTTPResponse(GzipSock(response), method=method)
        responseg.begin()
        responseg.app_status = 200
        responseg.xip =  response.xip
        responseg.sock = response.sock
        return responseg
    #读取压缩头部
    data = response.read(2)
    if len(data) < 2:
        response.status = 502
        return make_errinfo(response, b'connection aborted. too short leadtype data=' + data)
    headers_length, = struct.unpack('!h', data)
    data = response.read(headers_length)
    if len(data) < headers_length:
        response.status = 502
        return make_errinfo(response, b'connection aborted. too short headers data=' + data)
    #解压缩并解析头部
    raw_response_line, headers_data = zlib.decompress(data, -zlib.MAX_WBITS).split(b'\r\n', 1)
    raw_response_line = str(raw_response_line, 'iso-8859-1')
    raw_response_list = raw_response_line.split(None, 2)
    raw_response_length = len(raw_response_list)
    if raw_response_length == 3:
        _, status, reason = raw_response_list
        response.reason = reason.strip()
    elif raw_response_length == 2:
        _, status = raw_response_list
        response.reason = ''
    else:
        return
    response.status = int(status)
    #标记服务器端错误信息
    headers_data, app_msg = headers_data.split(b'\r\n\r\n')
    if app_msg:
        response.app_status = response.status
        response.reason = 'debug error'
        response.app_msg = app_msg
    response.headers = response.msg = httplib.parse_headers(BytesIO(headers_data))
    return response
