# coding:utf-8

import zlib
import struct
import json
import random
import logging
import threading
from time import sleep
from io import BytesIO
from gzip import GzipFile
from .GlobalConfig import GC
from .FilterUtil import get_action
from .HTTPUtil import http_cfw
from .common.dns import dns, dns_resolve
from .common.net import explode_ip

# IP 数相比请求数极为巨大，无需重复连接同一 IP
http_cfw.max_per_ip = 1
lock = threading.Lock()
cfw_iplist = []

class cfw_params:
    port = 443
    ssl = True
    command = 'POST'
    host = GC.CFW_WORKER
    path = '/gh'
    url = 'https://%s%s' % (host, path)
    hostname = 'cloudflare_workers|'
    connection_cache_key = '%s:%d' % (hostname, port)

class cfw_ws_params(cfw_params):
    command = 'GET'
    path = '/ws'

cfw_options = {}
if GC.CFW_PASSWORD:
    cfw_options['password'] = GC.CFW_PASSWORD
if GC.CFW_DECODEEMAIL:
    cfw_options['decodeemail'] = GC.CFW_DECODEEMAIL
cfw_options_str = json.dumps(cfw_options)

def set_dns():
    if dns.gettill(cfw_params.hostname):
        return
    dns.setpadding(cfw_params.hostname)
    if not cfw_iplist:
        if GC.CFW_IPLIST:
            iplist = GC.CFW_IPLIST
        else:
            iplist = dns_resolve('cloudflare.com')
            if not iplist:
                logging.warning('无法解析 cloudflare.com，使用默认 IP 列表')
                # https://www.cloudflare.com/ips/
                # 百度云加速与 CloudFlare 合作节点，保证可用
                iplist = ['162.159.208.0', '162.159.209.0', '162.159.210.0', '162.159.211.0']
        # 每个 IP 会自动扩展为 256 个，即填满最后 8 bit 子网
        cfw_iplist[:] = sum([explode_ip(ip) for ip in iplist], [])
        random.shuffle(cfw_iplist)
    dns.set(cfw_params.hostname, cfw_iplist, expire=False)

def check_response(response, host):
    if response:
        if response.headers.get('Server') == 'cloudflare':
            if response.headers.get('X-Fetch-Status'):  # ok / fail
                return 'ok'
            elif response.status == 429:
                # https://developers.cloudflare.com/workers/about/limits/
                # a burst rate limit of 1000 requests per minute.
                if lock.acquire(timeout=1):
                    try:
                        logging.warning('CFW %r 超限，暂停使用 30 秒', cfw_params.host)
                        sleep(30)
                    finally:
                        lock.release()
            elif response.status == 302 or 400 <= response.status < 500 or \
                     response.status == 530 and dns_resolve(host):
                 # https://support.cloudflare.com/hc/zh-cn/articles/360029779472-Cloudflare-1XXX-错误故障排除
                 # https://support.cloudflare.com/hc/zh-cn/articles/115003011431-Cloudflare-5XX-错误故障排除
                 with lock:
                    try:
                        cfw_iplist.remove(response.xip[0])
                        logging.test('CFW 移除 %s', response.xip[0])
                    except:
                        pass
            elif response.status in (500, 530):
                return 'ok'
            else:
                #打印收集未知异常状态
                logging.warning('CFW %r 工作异常：%d %s',
                                cfw_params.host, response.status, response.reason)
                return 'ok'
        else:
            logging.error('CFW %r 工作异常：%r 可能不是可用的 CloudFlare 节点',
                          cfw_params.host, response.xip[0])
        return 'retry'
    else:
        logging.test('CFW %r 连接失败', cfw_params.host)
        return 'fail'

def cfw_ws_fetch(host, url, headers):
    options = cfw_options.copy()
    options['url'] = 'http' + url[2:]
    headers.update({
        'Host': cfw_params.host,
        'X-Fetch-Options': json.dumps(options),
    })
    realurl = 'CFW-' + url
    while True:
        response = http_cfw.request(cfw_ws_params, headers=headers,
                                    connection_cache_key=cfw_params.connection_cache_key,
                                    realurl=realurl)
        if check_response(response, host) == 'retry':
            continue
        return response

def cfw_fetch(method, host, url, headers, payload=b'', options=None):
    set_dns()
    with lock:
        pass
    if url[:2] == 'ws':
        return cfw_ws_fetch(host, url, headers)
    ae = headers.get('Accept-Encoding', '')
    if 'Range' in headers and 'gzip' not in ae:
        ae += ', gzip'
        headers['Accept-Encoding'] = ae
    if 'gzip' not in ae and 'br' not in ae:
        ae = 'gzip'
    metadata = ['%s %s' % (method, url)]
    metadata += ['%s\t%s' % header for header in headers.items()]
    metadata = '\n'.join(metadata).encode()
    metadata = zlib.compress(metadata)[2:-4]
    if hasattr(payload, 'read'):
        payload = payload.read()
    if payload:
        if not isinstance(payload, bytes):
            payload = payload.encode()
        payload = struct.pack('!h', len(metadata)) + metadata + payload
    else:
        payload = struct.pack('!h', len(metadata)) + metadata
    if options:
        _options = cfw_options.copy()
        _options.update(options)
        options_str = json.dumps(_options)
    else:
        options_str = cfw_options_str
    request_headers = {
        'Host': cfw_params.host,
        'User-Agent': 'GotoX/ls/0.4',
        'Accept-Encoding': ae,
        'Content-Length': str(len(payload)),
        'X-Fetch-Options': options_str,
    }
    realurl = 'CFW-' + url
    while True:
        response = http_cfw.request(cfw_params, payload, request_headers,
                                    connection_cache_key=cfw_params.connection_cache_key,
                                    realmethod=method,
                                    realurl=realurl)
        status = check_response(response, host)
        if status == 'ok':
            response.http_util = http_cfw
            response.connection_cache_key = cfw_params.connection_cache_key
            if response.status == 206 and response.headers.get('Content-Encoding') == 'gzip':
                if response.headers['Content-Range'].startswith('bytes 0-'):
                    response.fp = gzipfp = GzipFile(fileobj=BytesIO(response.read()))
                    response.length = length = len(gzipfp.read())
                    response.headers.replace_header('Content-Range', f'bytes 0-{length - 1}/{length}')
                    del response.headers['Content-Encoding']
                    gzipfp.rewind()
                else:
                    response.status = 501
                    response.reason = 'Not Implemented'
                    content = b'CloudFlare Workers not support gziped response returned by range request which not starts with zero.'
                    response.fp = BytesIO(content)
                    response.length = len(content)
        elif status == 'retry':
            continue
        return response
