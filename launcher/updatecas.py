#!/usr/bin/env python3
#-*- coding: UTF-8 -*-

import sys
sys.dont_write_bytecode = True

import os
import zlib
from urllib.request import Request
from email.utils import mktime_tz, parsedate_tz
from common import root_dir, ca1, getlogger, create_context, download, \
                   parse_set_proxy, select_path

downloading = False

class DataSource:

    def __init__(self, name, path, crc, url, prefix, cadatas):
        self.name = name
        self.path = path
        self.crc = crc
        self.url = url
        self.prefix = prefix
        self.cadatas = cadatas

ds_GOOGLE = DataSource(
    'GOOGLE',
    os.path.join(root_dir, 'cert', 'cacerts', 'google.pem'),
    0,
    'https://pki.goog/roots.pem',
    b'# ',
    [
# CN = GTS Root R4
# O = Google Trust Services LLC
'''
-----BEGIN CERTIFICATE-----
MIICCTCCAY6gAwIBAgINAgPlwGjvYxqccpBQUjAKBggqhkjOPQQDAzBHMQswCQYD
VQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEUMBIG
A1UEAxMLR1RTIFJvb3QgUjQwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAwMDAw
WjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2Vz
IExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjQwdjAQBgcqhkjOPQIBBgUrgQQAIgNi
AATzdHOnaItgrkO4NcWBMHtLSZ37wWHO5t5GvWvVYRg1rkDdc/eJkTBa6zzuhXyi
QHY7qca4R9gq55KRanPpsXI5nymfopjTX15YhmUPoYRlBtHci8nHc8iMai/lxKvR
HYqjQjBAMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW
BBSATNbrdP9JNqPV2Py1PsVq8JQdjDAKBggqhkjOPQQDAwNpADBmAjEA6ED/g94D
9J+uHXqnLrmvT/aDHQ4thQEd0dlq7A/Cr8deVl5c1RxYIigL9zC2L7F8AjEA8GE8
p/SgguMh1YQdc4acLa/KNJvxn7kjNuK8YAOdgLOaVsjh4rsUecrNIdSUtUlD
-----END CERTIFICATE-----
'''
    ]
)

ds_MOZILLA = DataSource(
    'MOZILLA',
    os.path.join(root_dir, 'cert', 'cacerts', 'mozilla.pem'),
    0,
    'https://curl.se/ca/cacert.pem',
    b'##\n## Bundle of CA Root Certificates\n##',
    [
# CN = ISRG Root X1
# O = Internet Security Research Group
'''
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
''']
)

def sumcrc(fd, cb=None):
    crc = zlib.crc32(b'')  # 0
    data = fd.read(8192)
    while data:
        if callable(cb):
            cb(data)
        crc = zlib.crc32(data, crc)
        data = fd.read(8192)
    fd.close()
    return crc

def _update(ds):
    logger.info('开始更新 CA 证书集 [ %s ]', ds.name)
    if not ds.crc and os.path.isfile(ds.path):
        ds.crc = sumcrc(open(ds.path, 'rb'))
    context = create_context(cadatas=ds.cadatas)
    req = Request(ds.url)
    data = []
    read = 0

    def cb(d):
        nonlocal data, read
        data.append(d)
        read += len(d)

    fd, l = download(req, context=context)
    mtime = fd.headers.get('Last-Modified', 0)
    while True:
        try:
            crc = sumcrc(fd, cb)
        except OSError:
            pass
        if read >= l:
            break
        req.headers['Range'] = 'bytes=%d-' % read
        fd, _ = download(req, context=context)
    
    if read:
        if crc == ds.crc:
            logger.info('检测到 CA 证书集 [ %s ] 没有更新', ds.name)
            return
        if read == l and \
                data[0].startswith(ds.prefix) and \
                data[0].find(b'-----BEGIN CERTIFICATE-----') > 400:
            with open(ds.path, 'wb', l) as f:
                for d in data:
                    f.write(d)
            if mtime:
                mtime = mktime_tz(parsedate_tz(mtime))
                os.utime(ds.path, times=(mtime, mtime))
            ds.crc = crc
            return True

def update(*dss):
    global downloading
    if downloading:
        msg = '已经有更新 CA 证书集的任务正在进行中，请稍后再试'
        logger.warning(msg)
        return False, msg
    downloading = True
    updated = []
    for ds in dss:
        try:
            if _update(ds):
                updated.append(ds.name)
        except Exception as e:
            logger.warning('更新 CA 证书集 [ %s ] 时发生错误：%s', ds.name, e)
    downloading = False
    if updated:
        msg = 'CA 证书集 [ %s ] 更新完毕 !' % ', '.join(updated)
        logger.warning(msg)
        return True, msg
    return False, None

is_main = __name__ == '__main__'
logger = getlogger(is_main)

if is_main:
    if len(sys.argv) < 2:
        print('使用 "--help" 可查看命令行参数说明\n')
    if '--help' in sys.argv:
        print('''
用法：
    --help     显示此使用提示
    -u         下载的证书文件不放入脚本目录而是更新到相邻的 cert/cacerts 目录
               交互模式下参数 "-u" 无效

    指定可用数据源，交互模式中无效

    --all      更新所有证书数据源

    指定数据源并配合以下参数时不会进入交互模式，适用于自动／无人职守模式

    -d         跳过代理设置使用直连，使用参数 "-p" 时参数 "-d" 无效
    -p 主机名(IP 或域名):端口
               非交互模式使用 HTTP 代理，无效地址或无法链接代理时会直接结束脚本

''')

    if parse_set_proxy(int('--all' in sys.argv)) is None:
        for ds in (ds_GOOGLE, ds_MOZILLA):
            if '-u' not in sys.argv:
                ds.path = os.path.basename(ds.path)
            _update(ds)
        sys.exit(0)

    import copy
    while True:
        cwd = select_path(0, 1)
        if cwd is None:
            continue
        dss = copy.deepcopy((ds_GOOGLE, ds_MOZILLA))
        for ds in dss:
            if cwd:
                ds.path = os.path.basename(ds.path)
        update(*dss)
