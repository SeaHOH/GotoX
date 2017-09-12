#!/usr/bin/env python2
# coding:utf-8
# Fork from phuslu's GoProxy/server.gae
# Add App password setting
# It's also work with SeaHOH's GotoX client

import sys
import os

sys.dont_write_bytecode = True

if sys.version > '3.':
    sys.exit(sys.stderr.write('Please run uploader.py by python2\n'))

def println(s, file=sys.stderr):
    assert type(s) is type(u'')
    file.write(s.encode(sys.getfilesystemencoding(), 'replace') + os.linesep)

_real_raw_input = raw_input
def raw_input(s='', file=sys.stderr):
    if type(s) is type(u''):
        file.write(s.encode(sys.getfilesystemencoding(), 'replace'))
        return _real_raw_input()
    else:
        return _real_raw_input(s)

MAX_RETRIES = 1
os.chdir(os.path.abspath(os.path.dirname(__file__)))
GAE = {'dirname': 'gae'}
_file_yaml = os.path.join(GAE['dirname'], 'app.yaml')
_file_app = os.path.join(GAE['dirname'], 'gae.go')
try:
    with open(_file_yaml, 'rb') as fp:
        GAE['app.yaml'] = fp.read()
    with open(_file_app, 'rb') as fp:
        GAE['gae.go'] = fp.read()
except:
    println(u'无法加载 App 文件，上传程序终止……')
    raw_input()
    sys.exit(1)
CACHE_DIR = 'cache'
if os.path.exists(CACHE_DIR):
    if not os.path.isdir(CACHE_DIR):
        os.remove(CACHE_DIR)
        os.mkdir(CACHE_DIR)
else:
    os.mkdir(CACHE_DIR)

import re
import socket
import traceback
import shutil
import ssl
import mimetypes
import time

mimetypes._winreg = None

def clear():
    if os.name == 'nt':
        os.system('cls')
    else:
        sys.stderr.write("\x1b[2J\x1b[H")

try:
    socket.create_connection(('127.0.0.1', 8087), timeout=0.5).close()
    os.environ['HTTP_PROXY'] = 'http://127.0.0.1:8087'
    os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:8087'
    println(u'使用 HTTP 代理：127.0.0.1:8087')
except socket.error:
    try:
        socket.create_connection(('127.0.0.1', 1080), timeout=0.5).close()
        sys.path.append('PySocks')
        import socks
        if os.name == 'nt':
            import win_inet_pton
        socks.set_default_proxy(socks.SOCKS5, '127.0.0.1', port=1080)
        socket.socket = socks.socksocket
        println(u'使用 SOCKS5 代理：127.0.0.1:1080')
    except socket.error:
        println(u'''\
警告：检测到本机没有在指定端口监听的 HTTP 代理 (8087) 或 SOCKS5 代理 (1080)，
      建议先启动 GotoX 客户端或者其它代理，并根据代理类型设定监听的端口。

如果你使用的是 VPN 并且已经正常工作的话，请忽略此警告，按回车键继续。''')
        raw_input()


def patch_google_appengine_sdk(root_dir, *patch_list):
    for item in patch_list:
        filename = os.path.normpath(os.path.join(root_dir, item['name']))
        try:
            with open(filename, 'rb') as fp:
                text = fp.read()
            if item['old'] in text:
                println(u'patch_google_appengine_sdk(%s)' % filename)
                with open(filename, 'wb') as fp:
                    fp.write(text.replace(item['old'], item['new'], 1))
        except Exception as e:
            println(u'patch_google_appengine_sdk(%s) error: %s' % (filename, e))

patch_google_appengine_sdk('./google_appengine',
    {
        'name': 'google/appengine/tools/appengine_rpc_httplib2.py',
        'old' : '~/.appcfg_oauth2_tokens',
        'new' : './.appcfg_oauth2_tokens',
    },
    {
        'name': 'httplib2/__init__.py',
        'old' : 'self.proxy_rdns = proxy_rdns',
        'new' : 'self.proxy_rdns = True',
    },
    {
        'name': 'httplib2/__init__.py',
        'old' : 'content = zlib.decompress(content)',
        'new' : 'content = zlib.decompress(content, -zlib.MAX_WBITS)',
    })


sys.path = ['google_appengine'] + sys.path

import httplib2

def _ssl_wrap_socket(sock, key_file, cert_file,
                     disable_validation, ca_certs):
    cert_reqs = ssl.CERT_NONE
    return ssl.wrap_socket(sock, keyfile=key_file, certfile=cert_file,
                           cert_reqs=ssl.CERT_NONE, ca_certs=None,
                           ssl_version=ssl.PROTOCOL_TLSv1)
httplib2._ssl_wrap_socket = _ssl_wrap_socket
httplib2.HTTPSConnectionWithTimeout._ValidateCertificateHostname = lambda a, b, c: True
if hasattr(ssl, '_create_unverified_context'):
    setattr(ssl, '_create_default_https_context', ssl._create_unverified_context)

println(u'Loading Google Appengine SDK...')
from google_appengine.google.appengine.tools.appcfg import main as appcfg
from google_appengine.google.appengine.tools.appengine_rpc import ClientLoginError

def escaped(str):
    str_e = '"'
    if type(str) is not type(u''):
        str = str.decode(sys.getfilesystemencoding())
    for chr in str:
        chr_code = ord(chr)
        if chr_code < 256:
            str_e += chr.replace('\\', r'\\').replace('\"', r'\"')
        else:
            str_e += repr(unichr(chr_code))[2:-1]
    str_e += '"'
    return str_e

def set_app_info(filename, option, value, cache=None):
    old = option + '.*'
    new = option + ' ' + value
    try:
        if cache is None:
            with open(filename, 'rb') as fp:
                text = fp.read()
        else:
            text = cache
        text_new = re.sub(old, new, text, 1)
        if filename is None:
            return text_new
        if cache is not None or text_new != text:
            with open(filename, 'wb') as fp:
                fp.write(text_new)
    except Exception as e:
        println(u'set_app_info(%s) error: %s' % (filename, e))

def upload(dirname, appid):
    assert isinstance(dirname, basestring) and isinstance(appid, basestring)
    dirname = os.path.join(CACHE_DIR, '%s-%s' % (dirname, appid))
    if os.path.exists(dirname):
        shutil.rmtree(dirname)
    os.mkdir(dirname)
    file_yaml = os.path.join(dirname, 'app.yaml')
    file_app = os.path.join(dirname, 'gae.go')
    set_app_info(file_yaml, 'application:', appid, GAE['app.yaml'])
    with open(file_app, 'wb') as fp:
        fp.write(GAE['new.gae.go'])
    if os.name == 'nt':
        appcfg(['appcfg', 'rollback', dirname])
        appcfg(['appcfg', 'update', dirname])
    else:
        appcfg(['appcfg', 'rollback', '--noauth_local_webserver', dirname])
        appcfg(['appcfg', 'update', '--noauth_local_webserver', dirname])

def retry_upload(max_retries, dirname, appid):
    for i in xrange(max_retries + 1):
        try:
            upload(dirname, appid)
            return True, None
        except ClientLoginError as e:
            return False, u'(%s) 登录失败：%r' % (appid, e)
        except (Exception, SystemExit) as e:
            fail = i + 1
            if i < max_retries:
                println(u'上传 (%s) 失败 %d 次，重试……' % (appid, fail))
                time.sleep(fail)
            else:
                println(u'上传 (%s) 失败 %d 次：%r' % (appid, fail, e))
                traceback.print_exc()
    return None, None

def input_password():
    println(os.linesep + u'如果您不想设定使用密码，请直接按回车键。')
    password = escaped(raw_input(u'请输入 App 使用密码：'))
    GAE['new.gae.go'] = set_app_info(None, 'Password =', password, GAE['gae.go'])

def input_appids():
    println(u'''
输入多个 AppID 时需要使用字符“|”隔开。
特别提醒：AppID 请勿包含 ID/Email 等个人信息!''')
    while True:
        appids = raw_input(u'请输入 AppID：').lower()
        if appids:
            appids = [x.strip() for x in appids.split('|')]
        else:
            continue
        ok = True
        for appid in appids:
            if not re.match(r'^[a-z\d\-]+$', appid):
                println(u'''\
AppID (%s) 格式错误，
请登录 https://console.cloud.google.com/appengine 查看您的 AppID!'''
                        % appid)
                ok = False
            if any(x in appid for x in ('ios', 'android', 'mobile')):
                println(u'''\
AppID 不能包含 ios/android/mobile 字样，
请登录 https://console.cloud.google.com/appengine 删除 AppID (%s) 重建!'''
                        % appid)
                ok = False
        if ok:
            return appids
        else:
            println(os.linesep + u'请重新输入 AppID。')

def check_oauth_tokens(tokens='.appcfg_oauth2_tokens'):
    if os.path.exists(tokens):
        delete = raw_input(os.linesep + 
                 u'发现旧的登录凭证，是（Y）否（回车）删除：').lower() == 'y'
        if delete:
            os.remove(tokens)

def main():
    clear()
    println(u'''\
===============================================================
 GoProxy GAE 服务端部署程序，开始上传 gae 应用文件夹。
===============================================================''')
    check_oauth_tokens()
    appids = input_appids()
    input_password()
    fail_appids = []
    retry = False

    println(os.linesep + u'开始上传……')
    for appid in appids:
        result, msg = retry_upload(MAX_RETRIES, GAE['dirname'], appid)
        if result is False:
            break
        if result is None:
            fail_appids.append(appid)

    if result is False:
        println(os.linesep +
                u'认证失败，请确保你已经登录正在上传的 AppID 所属的谷歌帐号。'
                u'如果你拥有多个谷歌帐号的 AppID，请分别登录后再上传。')
        println(msg)
        retry = True
    elif fail_appids:
        println(os.linesep + u'以下 AppID 上传失败：')
        println(u'|'.join(fail_appids))
        retry = True
    else:
        shutil.rmtree(CACHE_DIR)
        println(os.linesep +
                u'上传成功，请不要忘记编辑 Config.user.ini 把你的 AppID '
                u'填进去，谢谢。按回车键退出程序。')

    if retry:
        println(os.linesep + u'按回车键开始重新上传……')
    raw_input()
    return retry


if __name__ == '__main__':
    try:
        while main():
            pass
    except:
        traceback.print_exc()
        raw_input()
