# coding:utf-8

import zlib
import queue
import struct
import logging
from io import BytesIO
from time import time, sleep, timezone, localtime, strftime, strptime, mktime
from http.client import HTTPResponse, parse_headers
from .FilterUtil import get_action
from .GlobalConfig import GC
from .GIPManager import test_ip_gae
from .HTTPUtil import http_gws, http_nor
from .common.decompress import GzipSock
from .common.decorator import make_lock_decorator
from .common.dns import dns, set_dns
from .common.net import isipv4, isipv6
from .common.util import LRUCache, LimitBase

class LimitGAE(LimitBase):
    'A response limiter wrapper for GAE.'

    maxsize = GC.GAE_MAXREQUESTS * len(GC.GAE_APPIDS)
    timeout = 30
    appids = dict((appid, 0) for appid in GC.GAE_APPIDS)

    def __init__(self, *args):
        super().__init__(*args)
        self.appid = _get_appid()
        self.appids[self.appid] += 1
        self._response = None

    def __getattr__(self, name):
        return getattr(self._response, name)

    def __call__(self, response):
        if response:
            self._response = response
            return self
        self.close()

    def close(self):
        if super().close():
            self.appids[self.appid] -= 1
            if hasattr(self._response, 'close'):
                self._response.close()

LimitGAE.init()

timezone_PST = timezone - 3600 * 8 # UTC-8
#timezone_PDT = timezone - 3600 * 7 # UTC-7
def get_refreshtime():
    #距离 GAE 流量配额每日刷新的时间
    #刷新时间不遵循夏令时
    now = time() + timezone_PST
    refreshtime = strftime('%y %j', localtime(now + 86400))
    refreshtime = mktime(strptime(refreshtime, '%y %j'))
    return refreshtime - now

nappid = 0
_lock_appid = make_lock_decorator()
badappids = LRUCache(len(GC.GAE_APPIDS))

def check_appid_exists(appid):
    request_params, http_util, connection_cache_key = _get_request_params(appid)
    for _ in range(3):
        err = None
        response = None
        try:
            sock = http_util.create_ssl_connection((request_params.host, request_params.port),
                                                   request_params.hostname,
                                                   connection_cache_key)
            if sock is None:
                continue
            sock.sendall(b'HEAD / HTTP/1.1\r\n'
                         b'Host: %s\r\n'
                         b'Connection: Close\r\n\r\n' % host.encode())
            response = HTTPResponse(sock, method='HEAD')
            response.begin()
        except:
            err = True
        finally:
            if response:
                response.close()
                if err is None:
                    exists = response.status in (200, 503)
                    if exists and GC.GAE_KEEPALIVE:
                        http_util.ssl_connection_cache[connection_cache_key].append((time(), sock))
                    return exists

@_lock_appid
def _get_appid():
    global nappid
    while True:
        nappid += 1
        if nappid >= len(GC.GAE_APPIDS):
            nappid = 0
            sleep(0.01)
        appid = GC.GAE_APPIDS[nappid]
        contains, expired, _ = badappids.getstate(appid)
        if contains and expired:
            LimitGAE.maxsize += GC.GAE_MAXREQUESTS
        if (not contains or expired) and LimitGAE.appids[appid] < GC.GAE_MAXREQUESTS:
            break
    return appid

@_lock_appid
def mark_badappid(appid, time=None, remove=None):
    if remove:
        try:
            GC.GAE_APPIDS.remove(appid)
        except ValueError:
            pass
        else:
            LimitGAE.maxsize -= GC.GAE_MAXREQUESTS
            try:
                del badappids[appid]
            except KeyError:
                pass
        return

    if appid not in badappids:
        if time is None:
            time = get_refreshtime()
            if len(GC.GAE_APPIDS) - len(badappids) <= 1:
                logging.error('全部的 AppID 流量都使用完毕')
            else:
                logging.warning('当前 AppID[%s] 流量使用完毕，切换下一个…', appid)
        badappids.set(appid, True, time)
        LimitGAE.maxsize -= GC.GAE_MAXREQUESTS

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
    if not isinstance(htmltxt, bytes):
        htmltxt = htmltxt.encode()
    del response.headers['Content-Type']
    del response.headers['Content-Encoding']
    del response.headers['Connection']
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['Content-Length'] = len(htmltxt)
    response.fp = BytesIO(htmltxt)
    response.length = len(htmltxt)

class gae_params:
    port = 443
    ssl = True
    hostname = 'google_gae|'
    path = GC.GAE_PATH
    command = 'POST'
    fetchhost = '%s.appspot.com'
    fetchserver = 'https://%s.appspot.com' + path

    __slots__ = 'host', 'url'

    def __init__(self, appid):
        self.host = self.fetchhost % appid
        self.url = self.fetchserver % appid

class custom_gae_params:
    port = 443
    ssl = True
    path = GC.GAE_PATH
    command = 'POST'
    fetchserver = 'https://%s' + path

    __slots__ = 'host', 'url', 'hostname'

    def __init__(self, host):
        self.host = host
        self.url = self.fetchserver % host


gae_params_dict = {}
for appid in GC.GAE_APPIDS:
    if '.' in appid:
        gae_params_dict[appid] = custom_gae_params(appid)
    else:
        gae_params_dict[appid] = gae_params(appid)

def _get_request_params(appid):
    request_params = gae_params_dict[appid]
    if isinstance(request_params, gae_params):
        http_util = http_gws
    else:
        action, target = get_action('https', request_params.host, request_params.path, request_params.url)
        if target and action in ('do_DIRECT', 'do_FORWARD'):
            iporname, profile = target
        else:
            iporname, profile = None, None
        request_params.hostname = hostname = set_dns(request_params.host, iporname)
        if hostname is None:
            raise OSError(11001, '无法解析 GAE 自定义域名：' + request_params.host)
        if profile == '@v4':
            dns[hostname] = [ip for ip in dns[hostname] if isipv4(ip)]
        elif profile == '@v6':
            dns[hostname] = [ip for ip in dns[hostname] if isipv6(ip)]
        http_util = http_nor
    connection_cache_key = '%s:%d' % (request_params.hostname, request_params.port)
    return request_params, http_util, connection_cache_key

def gae_urlfetch(method, url, headers, payload, getfast=None):
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
    realurl = 'GAE-' + url
    response = LimitGAE()
    _response = _gae_urlfetch(response.appid, payload, getfast, method, realurl)
    return response(_response)

def _gae_urlfetch(appid, payload, getfast, method, realurl):
    request_params, http_util, connection_cache_key = _get_request_params(appid)
    if http_util is http_gws:
        request_headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept-Encoding': 'gzip',
            'Content-Length': str(len(payload))
            }
    else:
        #禁用 CDN 不兼容的 GAE chunked 机制
        request_headers = {
            'User-Agent': '',
            'Content-Length': str(len(payload))
            }
    while True:
        response = http_util.request(request_params, payload, request_headers,
                                     connection_cache_key=connection_cache_key,
                                     getfast=getfast,
                                     realmethod=method,
                                     realurl=realurl)
        if response is None:
            return
        if response.status not in (200, 404):
            break
        if http_util is http_nor:
            break
        app_server = response.headers.get('Server')
        if app_server == 'Google Frontend':
            break
        if GC.GAE_ENABLEPROXY:
            logging.warning('GAE 前置代理 [%s:%d] 无法正常工作', *response.xip)
            continue
        if test_ip_gae(response.xip[0]):
            break
        logging.warning('发现并移除非 GAE IP：%s，Server：%s', response.xip[0], app_server)
    response.http_util = http_util
    response.connection_cache_key = connection_cache_key
    response.app_status = response.status
    if response.status != 200:
        return response
    #解压并解析 chunked & gziped 响应
    if 'Transfer-Encoding' in response.headers:
        responseg = HTTPResponse(GzipSock(response), method=method)
        responseg.begin()
        responseg.app_status = 200
        responseg.xip =  response.xip
        responseg.sock = response.sock
        responseg.http_util = http_util
        responseg.connection_cache_key = connection_cache_key
        return responseg
    #读取压缩头部
    data = response.read(2)
    if len(data) < 2:
        response.status = 502
        make_errinfo(response, 'connection aborted. too short leadtype data=%r' % data)
        return response
    headers_length, = struct.unpack('!h', data)
    data = response.read(headers_length)
    if len(data) < headers_length:
        response.status = 502
        make_errinfo(response, 'connection aborted. too short headers data=%r' % data)
        return response
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
    response.headers = response.msg = parse_headers(BytesIO(headers_data))
    if response.app_status == 200:
        response._method = method
        if response.status in (204, 205, 304) or 100 <= response.status < 200:
            response.length = 0
        else:
            try:
                response.length = int(response.headers.get('Content-Length'))
            except:
                response.length = None
    return response
