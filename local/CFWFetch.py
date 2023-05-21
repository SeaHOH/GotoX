# coding:utf-8

import re
import zlib
import struct
import json
import math
import random
import logging
import threading
from time import sleep, mtime
from io import BytesIO
from gzip import GzipFile, _PaddedFile
from collections import deque
from .GlobalConfig import GC
from .FilterUtil import get_action
from .HTTPUtil import http_cfw
from .common.decompress import decompress_readers
from .common.decorator import make_lock_decorator
from .common.dns import dns, dns_resolve
from .common.net import explode_ip
from .common.util import spawn_later

version = (0, 7)
http_cfw.max_per_ip = 1
lock = threading.Lock()
_lock_worker = make_lock_decorator(lock)
cfw_iplist = []

class cfw_params:
    server = (0, 7)
    port = 443
    ssl = True
    command = 'POST'
    host = GC.CFW_WORKER
    path = '/gh'
    url = f'https://{host}{path}'
    hostname = 'cloudflare_workers|'
    connection_cache_key = f'{hostname}:{port}'
    ignore_530 = f'<title>Origin DNS error | {GC.CFW_WORKER} | Cloudflare</title>'.encode()

    def __init__(self, worker):
        self.host = f'{worker}.{GC.CFW_SUBDOMAIN}.workers.dev'
        self.url = f'https://{self.host}{self.path}'
        self.ignore_530 = f'<title>Origin DNS error | {self.host} | Cloudflare</title>'.encode()

class cfw_ws_params(cfw_params):
    command = 'GET'
    path = '/ws'

class cfw_detect_params:
    command = 'GET'
    path = '/about'

    def __init__(self, cfw_params):
        self._cfw_params = cfw_params
        self.headers = {
            'Host': cfw_params.host,
            'User-Agent': 'GotoX/ls/0.7',
            'Accept-Encoding': 'br' in decompress_readers and 'br' or 'gzip',
        }

    def __getattr__(self, name):
        return getattr(self._cfw_params, name)

cfw_options = {}
if GC.CFW_PASSWORD:
    cfw_options['password'] = GC.CFW_PASSWORD
if GC.CFW_DECODEEMAIL:
    cfw_options['decodeemail'] = GC.CFW_DECODEEMAIL
cfw_options_str = json.dumps(cfw_options)

if GC.CFW_SUBDOMAIN and GC.CFW_WORKERS:
    cfw_paramses = deque(cfw_params(worker) for worker in GC.CFW_WORKERS)
    cfw_ws_paramses = deque(cfw_ws_params(worker) for worker in GC.CFW_WORKERS)
else:
    cfw_paramses = [cfw_params]
    cfw_ws_paramses = [cfw_ws_params]

def fetch_server_version():
    set_dns()
    errors = []
    for worker_params in cfw_paramses:
        noerror = True
        response = None
        try:
            worker_detect_params = cfw_detect_params(worker_params)
            response = http_cfw.request(worker_detect_params, headers=worker_detect_params.headers,
                                        connection_cache_key=worker_params.connection_cache_key)
            if response.status != 200:
                logging.warning('CFW [%s] 版本检测失败：%d', worker_params.host, response.status)
                continue
            content = decompress_readers[response.headers['Content-Encoding']](response).read()
            ver = re.search(b'GotoX remote server ([\d\.]+) in CloudFlare Workers', content)
            if ver:
                ver = ver.groups()[0].decode()
                worker_params.server = server = tuple(map(int, ver.split('.')))
                if server < version:
                    logging.warning('CFW [%s] 版本低于本地服务端：%s，建议更新', worker_params.host, ver)
                elif server > version:
                    logging.warning('CFW [%s] 版本高于本地服务端：%s，可能无法正常工作', worker_params.host, ver)
                else:
                    logging.test('CFW [%s] 版本匹配本地服务端：%s', worker_params.host, ver)
            else:
                logging.error('CFW [%s] 没有检测到任何版本信息，请检查配置信息是否正确', worker_params.host)
        except Exception as e:
            noerror = False
            errors.append(e)
        finally:
            if noerror and response:
                response.close()
                if GC.CFW_KEEPALIVE:
                    http_cfw.ssl_connection_cache[worker_params.connection_cache_key].append((mtime(), response.sock))
                else:
                    response.sock.close()
    if errors:
        raise errors[0]

spawn_later(10, fetch_server_version)

@_lock_worker
def get_worker_params(f=None):
    worker_paramses = f == 'ws' and cfw_ws_paramses or cfw_paramses
    if len(worker_paramses) > 1:
        worker_paramses.append(worker_paramses.popleft())
    return worker_paramses[0]

def set_dns():
    if dns.gettill(cfw_params.hostname):
        http_cfw.max_per_ip = math.ceil(32 / len(cfw_iplist))
        return
    dns.setpadding(cfw_params.hostname)
    explodeip = GC.CFW_EXPLODEIP
    if GC.CFW_IPLIST:
        expire = False
        iplist = GC.CFW_IPLIST
    else:
        expire = 3600
        iplist = dns_resolve('cloudflare.com')
        if iplist:
            expire = 3600 * 6
        elif cfw_iplist:
            explodeip = False
        else:
            logging.warning('无法解析 cloudflare.com，使用默认 IP 列表')
            # https://www.cloudflare.com/ips/
            # 百度云加速与 CloudFlare 合作节点，保证可用
            iplist = ['162.159.208.0', '162.159.209.0', '162.159.210.0', '162.159.211.0']
    if explodeip:
        # 每个 IP 会自动扩展为 256 个，即填满最后 8 bit 子网
        cfw_iplist[:] = sum([explode_ip(ip) for ip in iplist], [])
    elif iplist:
        cfw_iplist[:] = iplist
    random.shuffle(cfw_iplist)
    dns.set(cfw_params.hostname, cfw_iplist, expire=expire)
    # 根据 IP 数限制对同一 IP 请求数
    http_cfw.max_per_ip = math.ceil(32 / len(cfw_iplist))

def remove_badip(ip):
    with lock:
        try:
            cfw_iplist.remove(ip)
            return True
        except:
            pass

def check_response(response, worker_params):
    if response:
        if response.headers.get('Server') == 'cloudflare':
            # https://support.cloudflare.com/hc/zh-cn/articles/115003014512-4xx-客户端错误
            # https://support.cloudflare.com/hc/zh-cn/articles/115003011431-Cloudflare-5XX-错误故障排除
            # https://support.cloudflare.com/hc/zh-cn/articles/360029779472-Cloudflare-1XXX-错误故障排除
            if response.headers.get('X-Fetch-Status'):  # ok / fail
                return 'ok'
            content = None
            if response.status == 530:
                ce = response.headers.get('Content-Encoding')
                if ce and ce in decompress_readers:
                    del response.headers['Content-Encoding']
                    response = decompress_readers[ce](response)
                content = response.read()
                response.fp = BytesIO(content)
                response.chunked = False
                response.length = len(content)
            if content and (worker_params.ignore_530 not in content or not dns_resolve(worker_params.host)):
                return 'ok'
            if response.status == 429:
                # https://developers.cloudflare.com/workers/platform/limits#request
                # a burst rate limit of 1000 requests per minute.
                if lock.acquire(timeout=1):
                    try:
                        logging.warning('CFW %r 超限，暂停使用 30 秒', worker_params.host)
                        sleep(30)
                    finally:
                        lock.release()
            elif response.status in (500, 502, 503, 504):
                sleep(5)
            elif remove_badip(response.xip[0]):
                logging.test('CFW %d 移除 %s', response.status, response.xip[0])
        elif remove_badip(response.xip[0]):
            logging.error('CFW %r 工作异常：%r 可能不是可用的 CloudFlare 节点',
                          worker_params.host, response.xip[0])
        return 'retry'
    else:
        logging.test('CFW %r 连接失败', worker_params.host)
        return 'fail'

def cfw_ws_fetch(host, url, headers):
    options = cfw_options.copy()
    options['url'] = 'http' + url[2:]
    worker_params = get_worker_params('ws')
    headers.update({
        'Host': worker_params.host,
        'X-Fetch-Options': json.dumps(options),
    })
    realurl = 'CFW-' + url
    while True:
        response = http_cfw.request(worker_params, headers=headers,
                                    connection_cache_key=worker_params.connection_cache_key,
                                    realurl=realurl)
        if response and 'X-Fetch-Status' not in response.headers:
            response.headers['X-Fetch-Status'] = 'ok'
        status = check_response(response, worker_params)
        if status == 'retry':
            continue
        return response

def cfw_fetch(method, host, url, headers, payload=b'', options=None):
    set_dns()
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
    worker_params = get_worker_params()
    if worker_params.server >= (0, 7):
        deflated = len(metadata) > 3000
        if deflated:
            metadata = zlib.compress(metadata)[2:-4]
        metadata = struct.pack('!H', deflated and len(metadata) | 0x8000 or len(metadata)) + metadata
    else:
        metadata = zlib.compress(metadata)[2:-4]
        metadata = struct.pack('!H', len(metadata)) + metadata
    length = len(metadata) + int(headers.get('Content-Length', 0))
    if payload:
        if hasattr(payload, 'read'):
            payload = _PaddedFile(payload, metadata)
        else:
            if not isinstance(payload, bytes):
                payload = payload.encode()
            payload = metadata + payload
    else:
        payload = metadata
    if options:
        _options = cfw_options.copy()
        _options.update(options)
        options_str = json.dumps(_options)
    else:
        options_str = cfw_options_str
    request_headers = {
        'Host': worker_params.host,
        'User-Agent': 'GotoX/ls/0.7',
        'Accept-Encoding': ae,
        'Content-Length': str(length),
        'X-Fetch-Options': options_str,
    }
    realurl = 'CFW-' + url
    while True:
        response = http_cfw.request(worker_params, payload, request_headers,
                                    connection_cache_key=worker_params.connection_cache_key,
                                    realmethod=method,
                                    realurl=realurl)
        status = check_response(response, worker_params)
        if status == 'ok':
            response.http_util = http_cfw
            response.connection_cache_key = worker_params.connection_cache_key
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
