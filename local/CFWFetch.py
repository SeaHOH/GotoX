# coding:utf-8

import zlib
import struct
import json
import logging
from .GlobalConfig import GC
from .FilterUtil import get_action
from .HTTPUtil import http_cfw
from .common.dns import dns, set_dns as _set_dns


class cfw_params:
    port = 443
    ssl = True
    command = 'POST'
    host = GC.CFW_WORKER
    path = '/gh'
    url = 'https://%s%s' % (host, path)
    hostname = 'not ready'

class cfw_ws_params(cfw_params):
    command = 'GET'
    path = '/ws'

cfw_options = {}
if GC.CFW_PASSWORD:
    cfw_options['password'] = GC.CFW_PASSWORD
if GC.CFW_DECODEEMAIL:
    cfw_options['decodeemail'] = GC.CFW_DECODEEMAIL

def set_dns():
    if cfw_params.hostname in dns:
        return
    action, target = get_action('https', cfw_params.host, cfw_params.path, cfw_params.url)
    if target and action in ('do_DIRECT', 'do_FORWARD'):
        iporname, profile = target
    else:
        iporname, profile = None, None
    cfw_params.hostname = 'not ready'
    cfw_params.hostname = hostname = _set_dns(cfw_params.host, iporname)
    cfw_params.connection_cache_key = '%s:%d' % (cfw_params.hostname, cfw_params.port)
    if hostname is None:
        raise OSError(11001, '无法解析 CFWorker 域名：' + cfw_params.host)
    if profile == '@v4':
        dns[hostname] = [ip for ip in dns[hostname] if isipv4(ip)]
    elif profile == '@v6':
        dns[hostname] = [ip for ip in dns[hostname] if isipv6(ip)]

def cfw_ws_fetch(url, headers):
    realurl = 'CFW-' + url
    set_dns()
    options = cfw_options.copy()
    options['url'] = 'http' + url[2:]
    headers.update({
        'Host': cfw_params.host,
        'X-Fetch-Options': json.dumps(options),
    })
    response = http_cfw.request(cfw_ws_params, headers=headers,
                                connection_cache_key=cfw_params.connection_cache_key,
                                realurl=realurl)
    if response and response.headers.get('Server') == 'cloudflare':
        return response
    logging.warning('CFW %r 无法正常工作', cfw_params.host)

def cfw_fetch(method, url, headers, payload=b'', options=json.dumps(cfw_options)):
    if url[:2] == 'ws':
        return cfw_ws_fetch(url, headers)
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
    realurl = 'CFW-' + url
    set_dns()
    request_headers = {
        'Host': cfw_params.host,
        'User-Agent': 'GotoX/ls/0.2',
        'Accept-Encoding': 'gzip',
        'Content-Length': str(len(payload)),
        'X-Fetch-Options': options,
    }
    response = http_cfw.request(cfw_params, payload, request_headers,
                                connection_cache_key=cfw_params.connection_cache_key,
                                realmethod=method,
                                realurl=realurl)
    if response and response.headers.get('Server') == 'cloudflare':
        response.http_util = http_cfw
        response.connection_cache_key = cfw_params.connection_cache_key
        return response
    logging.warning('CFW %r 无法正常工作', cfw_params.host)
