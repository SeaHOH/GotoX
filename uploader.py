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

os.chdir(os.path.abspath(os.path.dirname(__file__)))

import re
import socket
import ssl
import mimetypes

mimetypes._winreg = None

def clear():
    if os.name == 'nt':
        os.system('cls')
    else:
        sys.stderr.write("\x1b[2J\x1b[H")

def println(s, file=sys.stderr):
    assert type(s) is type(u'')
    file.write(s.encode(sys.getfilesystemencoding(), 'replace') + os.linesep)

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
from google_appengine.google.appengine.tools import appcfg

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

def set_app_info(filename, option, value):
    old = option + '.*'
    new = option + ' ' + value
    try:
        with open(filename, 'rb') as fp:
            text = fp.read()
        text_new = re.sub(old, new, text, 1)
        if text_new != text:
            with open(filename, 'wb') as fp:
                fp.write(text_new)
    except Exception as e:
        println(u'set_app_info(%s) error: %s' % (filename, e))

def upload(dirname, appid):
    assert isinstance(dirname, basestring) and isinstance(appid, basestring)
    file_yaml = os.path.join(dirname, 'app.yaml')
    set_app_info(file_yaml, 'application:', appid)
    if os.name == 'nt':
        appcfg.main(['appcfg', 'rollback', dirname])
        appcfg.main(['appcfg', 'update', dirname])
    else:
        appcfg.main(['appcfg', 'rollback', '--noauth_local_webserver', dirname])
        appcfg.main(['appcfg', 'update', '--noauth_local_webserver', dirname])

def input_password():
    println(os.linesep + u'请设定 App 使用密码，如果您不想设定，请直接按回车键。')
    password = escaped(raw_input('App PassWord:'))
    file_app = os.path.join('gae', 'gae.go')
    set_app_info(file_app, 'Password =', password)

def input_appids():
    while True:
        appids = raw_input('AppID:').lower()
        if appids:
            appids = [x.strip() for x in appids.split('|')]
        else:
            continue
        ok = True
        for appid in appids:
            if not re.match(r'^[a-z\d\-]+$', appid):
                println(u'''\
AppID (%s) 格式错误，
请登录 https://console.cloud.google.com/appengine 查看您的 AppID!''' % appid)
                ok = False
            if any(x in appid for x in ('ios', 'android', 'mobile')):
                println(u'''\
AppID 不能包含 ios/android/mobile 字样，
请登录 https://console.cloud.google.com/appengine 删除 AppID (%s) 重建!''' % appid)
                ok = False
        if ok:
            return appids
        else:
            println(os.linesep + u'请重新输入 AppID。')

def main():
    clear()
    println(u'''\
===============================================================
 GoProxy GAE 服务端部署程序，开始上传 gae 应用文件夹。
===============================================================

请输入您的 AppID，多个 AppID 需要使用字符“|”隔开。
特别提醒：AppID 请勿包含 ID/Email 等个人信息!''')
    appids = input_appids()
    input_password()
    for appid in appids:
        upload('gae', appid)
    println(os.linesep + u'上传成功，请不要忘记编辑 Config.user.ini 把你的 '
                         u'AppID 填进去，谢谢。按回车键退出程序。')
    raw_input()


if __name__ == '__main__':
    main()
