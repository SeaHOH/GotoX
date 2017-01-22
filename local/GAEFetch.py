# coding:utf-8

import zlib
import io
import struct
from .compat import Queue, httplib
from .GlobalConfig import GC
from .HTTPUtil import http_gws

qGAE = Queue.LifoQueue()
for i in range(GC.GAE_MAXREQUESTS * len(GC.GAE_APPIDS)):
    qGAE.put(True)

def make_errinfo(htmltxt):
    if not isinstance(htmltxt, bytes):
        htmltxt = htmltxt.encode()
    response.msg['Content-Type'] = 'text/html'
    response.fp = io.BytesIO(htmltxt)
    response.read = response.fp.read
    return response

class gae_params():
    port = 443
    ssl = True
    path = GC.GAE_PATH
    command = 'POST'
    fetchhost = '%s.appspot.com'
    fetchserver = 'https://%s.appspot.com' + path

    def __init__(self, appid):
        self.host = self.fetchhost % appid
        self.url = self.fetchserver % appid

def gae_urlfetch(method, url, headers, payload, appid, timeout=None, rangefetch=None, **kwargs):
    if GC.GAE_PASSWORD:
        kwargs['Password'] = GC.GAE_PASSWORD
    if GC.GAE_SSLVERIFY:
        kwargs['SSLVerify'] = kwargs['validate'] = 1
    if GC.GAE_MAXSIZE:
        kwargs['MaxSize'] = kwargs['fetchmaxsize'] = GC.GAE_MAXSIZE
    # GAE 代理请求不允许设置 Host 头域
    if 'Host' in headers:
        del headers['Host']
    #if payload:
        #if not isinstance(payload, bytes):
        #    payload = payload.encode()
        #if len(payload) < 10 * 1024 * 1024 and 'Content-Encoding' not in headers:
        #    zpayload = zlib.compress(payload)[2:-4]
        #    if len(zpayload) < len(payload):
        #        payload = zpayload
        #        headers['Content-Encoding'] = 'deflate'
        #headers['Content-Length'] = str(len(payload))
    if GC.GAE_PATH == '/2':
        metadata = 'G-Method:%s\nG-Url:%s\n%s' % (method, url, ''.join('G-%s:%s\n' % (k, v) for k, v in kwargs.items() if v))
        metadata += ''.join('%s:%s\n' % (k.title(), v) for k, v in headers.items())
    else:
        metadata = '%s %s HTTP/1.1\r\n' % (method, url)
        metadata += ''.join('%s: %s\r\n' % (k, v) for k, v in headers.items())
        metadata += ''.join('X-Urlfetch-%s: %s\r\n' % (k, v) for k, v in kwargs.items() if v)
    if not isinstance(metadata, bytes):
        metadata = metadata.encode()
    metadata = zlib.compress(metadata)[2:-4]
    if payload:
        if not isinstance(payload, bytes):
            payload = payload.encode()
        payload = struct.pack('!h', len(metadata)) + metadata + payload
    else:
        payload = struct.pack('!h', len(metadata)) + metadata
    request_headers = {'User-Agent': 'a', 'Content-Length': str(len(payload))}
    # post data
    request_params = gae_params(appid)
    connection_cache_key = 'google_gws:443'
    realurl = 'GAE-' + url
    qGAE.get() # get start from Queue
    response = http_gws.request(request_params, payload, request_headers, connection_cache_key=connection_cache_key, timeout=timeout, rangefetch=rangefetch, realurl=realurl)
    if response is None:
        return None
    response.app_status = response.status
    if response.status != 200:
        return response
    #读取 GAE 头部
    if GC.GAE_PATH == '/2':
        data = response.read(4)
        if len(data) < 4:
            response.status = 502
            return make_errinfo(b'connection aborted. too short leadtype data=' + data)
        response.status, headers_length = struct.unpack('!hh', data)
    else:
        data = response.read(2)
        if len(data) < 2:
            response.status = 502
            return make_errinfo(b'connection aborted. too short leadtype data=' + data)
        headers_length, = struct.unpack('!h', data)
    data = response.read(headers_length)
    if len(data) < headers_length:
        response.status = 502
        return make_errinfo(b'connection aborted. too short headers data=' + data)
    #读取实际的头部
    if GC.GAE_PATH == '/2':
        headers_data= zlib.decompress(data, -zlib.MAX_WBITS)
    else:
        raw_response_line, headers_data = zlib.decompress(data, -zlib.MAX_WBITS).split(b'\r\n', 1)
        raw_response_list = raw_response_line.split(None, 2)
        if len(raw_response_list) < 3:
            _, response.status = raw_response_list
            response.app_status = response.status = int(response.status)
            if response.app_status == 403:
                response.app_reason = 'APP 密码错误！请修改后重试。'
                return make_errinfo('<h1>******   APP 密码错误！请修改后重试。******</h1>')
        else:
            _, response.status, response.reason = raw_response_list
            response.status = int(response.status)
            response.reason = response.reason.strip()
    response.headers = response.msg = httplib.parse_headers(io.BytesIO(headers_data))
    return response
