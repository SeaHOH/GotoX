# coding:utf-8

import zlib
import io
import struct
from compat import PY3, httplib, Queue
from GlobalConfig import GC
from HTTPUtil import http_util

qGAE = Queue.Queue(GC.GAE_MAXREQUESTS)
for i in xrange(GC.GAE_MAXREQUESTS):
    qGAE.put(True)

def gae_urlfetch(method, url, headers, payload, appid, rangefetch=None, **kwargs):
    if GC.GAE_PASSWORD:
        kwargs['password'] = GC.GAE_PASSWORD
    if GC.GAE_VALIDATE:
        kwargs['validate'] = 1
    if GC.FETCHMAX_SERVER:
        kwargs['fetchmax'] = GC.FETCHMAX_SERVER
    if GC.FETCHMAXSIZE:
        kwargs['fetchmaxsize'] = GC.FETCHMAXSIZE
    # deflate = lambda x:zlib.compress(x)[2:-4]
    if payload:
        if len(payload) < 10 * 1024 * 1024 and 'Content-Encoding' not in headers:
            zpayload = zlib.compress(payload)[2:-4]
            if len(zpayload) < len(payload):
                payload = zpayload
                headers['Content-Encoding'] = 'deflate'
        headers['Content-Length'] = str(len(payload))
    # GAE donot allow set `Host` header
    if 'Host' in headers:
        del headers['Host']
    metadata = 'G-Method:%s\nG-Url:%s\n%s' % (method, url, ''.join('G-%s:%s\n' % (k, v) for k, v in kwargs.items() if v))
    skip_headers = http_util.skip_headers
    metadata += ''.join('%s:%s\n' % (k.title(), v) for k, v in headers.items() if k not in skip_headers)
    if PY3:
        metadata = metadata.encode()
    # prepare GAE request
    request_method = 'POST'
    request_headers = {}
    metadata = zlib.compress(metadata)[2:-4]
    payload = '%s%s%s' % (struct.pack('!h', len(metadata)), metadata, payload)
    request_headers['Content-Length'] = str(len(payload))
    # post data
    fetchserver = 'https://%s.appspot.com%s?' % (appid, GC.GAE_PATH)
    connection_cache_key = GC.GAE_LISTNAME + ':443'
    realurl = 'GAE-' + url
    qGAE.get() # get start from Queue
    response = http_util.request(request_method, fetchserver, payload, request_headers, connection_cache_key=connection_cache_key, rangefetch=rangefetch, realurl=realurl)
    qGAE.put(True) # put back
    if response is None:
        return None
    response.app_status = response.status
    response.app_options = response.getheader('X-GOA-Options', '')
    if response.status != 200:
        return response
    data = response.read(4)
    if len(data) < 4:
        response.status = 502
        response.fp = io.BytesIO(b'connection aborted. too short leadtype data=' + data)
        response.read = response.fp.read
        return response
    response.status, headers_length = struct.unpack('!hh', data)
    data = response.read(headers_length)
    if len(data) < headers_length:
        response.status = 502
        response.fp = io.BytesIO(b'connection aborted. too short headers data=' + data)
        response.read = response.fp.read
        return response
    response.msg = httplib.HTTPMessage(io.BytesIO(zlib.decompress(data, -zlib.MAX_WBITS)))
    return response
