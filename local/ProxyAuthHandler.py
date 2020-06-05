# coding:utf-8

import logging
from .GlobalConfig import GC
from .ProxyHandler import AutoProxyHandler, ACTProxyHandler
from .common.util import LRUCache

if GC.LISTEN_AUTH == 2:
    import string
    from urllib.parse import quote, unquote

    login_page = '''\
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html lang="zh-cn">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
<title>GotoX 登录</title>
<style type="text/css"><!--
div, input {font-size: 12pt; font-family: arial,sans-serif}
#header {margin: 7% auto 3%; text-align: center}
#loginform {margin :auto; height: 30%; width: 28em; position: relative}
.forminfo {width: 21em}
.hideforminfo {display: none}
#submit {width: 8em; position: absolute; right: 2em}
#state {margin: 3% auto 3%; text-align: center}
#notice {margin: 3% auto 3%; width: 34em}
#footer {margin: auto; text-align: center}
//--></style>
</head>
<body>
<div id="header">
<h1>欢迎使用 GotoX 代理，请先登录你的帐号！</h1>
</div>
<div id="loginform">
<form action="login" method="POST">
<big>用&thinsp;户&thinsp;名</big>：
<input class="forminfo" type="text" name="username" maxlength="20" autofocus />
<br /><br />
<big>密&emsp;&thinsp;&thinsp;码</big>：
<input class="forminfo" type="password" name="userpassword" maxlength="20" />
<br /><br />
<input class="hideforminfo" type="text" name="redirect" value="$redirect" />
<input id="submit" type="submit" value="登&emsp;&emsp;录" $disabled/>
</form>
</div>
<div id="state">
<h1>&emsp;$msg&emsp;</h1>
</div>
<div id="notice">
<h3>注意及声明事项：</h3>
<p>&emsp;&emsp;1、如果你没有被授权，请关闭当前页面，不要进行登录行为；如果你想要继续使用当前网络应用，请在其设置或系统设置中取消本代理设置。</p>
<p>&emsp;&emsp;2、如果连续错误登录 $maxtry 次，后续任何请求（包括登录）都将会被拒绝。</p>
<p>&emsp;&emsp;3、如果你忘记了密码，请联系本代理提供者而非 GotoX 软件的作者。</p>
<p>&emsp;&emsp;4、无论登录成功与否，本代理都会记录且仅只记录登录请求的 IP。</p>
<p>&emsp;&emsp;5、本代理基于 IP 进行认证，只要发起请求的 IP 与登录成功的 IP 相同，即通过认证；这就使得多台主机可以通过一个处于成功登录状态的 IP 来使用本代理。如果这会造成不良影响，请不要对同一子网的其它用户透露本代理地址。</p>
<p>&emsp;&emsp;6、登录成功后，如果连续 $expired 分钟没有发起任何请求，登录将会失效；要继续使用本代理，请重新登录。</p>
<p>&emsp;&emsp;7、最后，<big><b>请不要利用本代理进行任何形式的非法行为！</b></big></p>
</div>
<div id="footer">
从 GitHub 获取 GotoX 源代码：<a href="https://github.com/SeaHOH/GotoX">SeaHOH/GotoX</a>
</div>
</body>
</html>
'''

    class ProxyIPAuthHandler:
        '''处理基于 IP 的 HTTPS 登录认证'''

        #登录成功后加入白名单，连续半小时不使用即过期，需重新登录
        expired_time = 30
        #最大失败次数，超出后加入黑名单，时效 6 小时
        max_try_times = 5

        auth_white_list = LRUCache(32, 60 * expired_time)
        auth_black_list = LRUCache(32, 3600 * 6)
        logged_users = {}
        users = GC.LISTEN_AUTHUSER
        login_url = 'gotox.go/login'
        login_page = string.Template(login_page).substitute

        #不会过期的白名单项目
        for ip in GC.LISTEN_AUTHWHITELIST:
            auth_white_list.set(ip, True, expire=False)

        def _check_auth(self):
            form_data = self.get_form_data()
            if form_data:
                client_ip = self.client_address[0]
                auth_black_list = self.auth_black_list
                form_dict = dict(kv.split('=', 1) for kv in form_data.split('&'))
                user = form_dict.get('username') + ':' + form_dict.get('userpassword')
                redirect = form_dict.get('redirect')
                if user in self.users:
                    logged_users = self.logged_users
                    auth_white_list = self.auth_white_list
                    try:
                        #删除该用户之前登录的 IP，使其登录失效
                        del auth_white_list[logged_users[user]]
                    except KeyError:
                        pass
                    try:
                        #清除当前登 IP 的失败记录
                        del auth_black_list[client_ip]
                    except KeyError:
                        pass
                    #更新用户最新登录成功的 IP
                    logged_users[user] = client_ip
                    #登录成功加入白名单
                    auth_white_list[client_ip] = True
                    logging.warning('%s 成功登录 GotoX', self.address_string())
                    if redirect is '':
                        #返回登录成功提示
                        self.send_login_page(msg='登录成功！', disabled='disabled="disabled" ')
                    else:
                        #返回先前请求的网址
                        target = unquote(redirect) 
                        self.write('HTTP/1.1 303 See Other\r\n'
                                   'Location: %s\r\n\r\n' % target)
                else:
                    #登录失败计数
                    logging.error('%s 登录 GotoX 失败', self.address_string())
                    try:
                        auth_black_list[client_ip] += 1
                    except KeyError:
                        auth_black_list[client_ip] = 1
                    self.send_login_page(redirect=redirect, msg='登录失败！')
            else:
                #数据读取出错，原始网址信息丢失
                self.send_login_page(msg='数据提交错误，请重试！')

        def check_auth(self):
            client_ip = self.client_address[0]
            auth_white_list = self.auth_white_list
            if client_ip in auth_white_list:
                auth_white_list[client_ip] = True
                return True
            auth_black_list = self.auth_black_list
            if client_ip in auth_black_list and auth_black_list[client_ip] > self.max_try_times:
                auth_black_list[client_ip] = times = auth_black_list[client_ip] + 1
                logging.error('%s 黑名单 IP 第 %s 次请求代理！"%s %s"',
                        self.address_string(), times, self.command, self.url or self.path)
            elif self.command == 'CONNECT':
                self._do_CONNECT()
                self.do_FAKECERT()
            else:
                self._do_METHOD()
                if (self.ssl_request or self.ssl) and self.url[8:].lower().startswith(self.login_url):
                    #只有登录地址为加密链接时才发送登录页面
                    redirect = ''
                    if self.command == 'POST':
                        #开始验证
                        return self._check_auth()
                    elif self.command == 'GET':
                        #获取原始网址
                        _, _, query = self.path.partition('?')
                        if query is not '':
                            query = dict(kv.split('=', 1) for kv in query.split('&'))
                            redirect = query.get('redirect', '')
                    #发送登录页面
                    self.send_login_page(redirect=redirect)
                else:
                    #重定向到登录页面
                    url = self.url
                    login_url = self.login_url
                    if url[7:].lower().startswith(login_url):
                        #纠正登录地址为加密链接
                        target = 'https://' + url[7:]
                    else:
                        target = 'https://%s?redirect=%s' % (login_url, quote(url))
                    self.write('HTTP/1.1 302 Found\r\n'
                               'Cache-Control: no-cache\r\n'
                               'Location: %s\r\n\r\n' %  target)
                    logging.info('%s 重定向 %r 到 GotoX 登录页面', self.address_string(), url)

        def send_login_page(self, redirect='', msg='', disabled=''):
            page = self.login_page(redirect=redirect, msg=msg, disabled=disabled,
                        maxtry=self.max_try_times, expired=self.expired_time).encode()
            l = len(page)
            self.write('HTTP/1.1 200 OK\r\n'
                       'Cache-Control: no-cache\r\n'
                       'Content-Length: %s\r\n'
                       'Content-Type: text/html; charset=utf-8\r\n\r\n' % l)
            self.write(page)

        def get_form_data(self):
            #只支持默认格式
            ctype = self.headers.get('Content-Type', '')
            ctype, _, plist = ctype.partition(';')
            if ctype != 'application/x-www-form-urlencoded':
                return ''
            #继续获取 charset 以兼容不规范请求
            pdict = {}
            if plist is not '':
                plist = plist.split(';')
                for kv in plist:
                    kv = kv.strip()
                    if '=' in plist:
                        k, v = kv.split('=', 1) 
                        pdict[k] = v
                    elif ':' in plist:
                        k, v = kv.split(':', 1) 
                        pdict[k] = v
                    else:
                        pdict[kv] = ''
            charset = pdict.get('charset', 'utf-8')
            length = int(self.headers.get('Content-Length', 0))
            if length > 0:
                form_data = self.rfile.read(length)
            else:
                form_data = self.rfile.read()
            if form_data:
                return unquote(form_data.decode(charset))
            else:
                return ''

    ProxyAuthHandler = ProxyIPAuthHandler

elif GC.LISTEN_AUTH == 1:
    from base64 import b64decode

    class ProxyBasicAuthHandler:
        '''处理 HTTP 基本认证'''

        auth_warning = (
                'HTTP/1.1 407 Proxy Authentication Required\r\n'
                'Proxy-Connection: close\r\n\r\n'
                '<h1>密码错误！使用此代理之前你必须先进行认证。</h1>').encode()
        require_auth_header = (
                b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                b'Access-Control-Allow-Origin: *\r\n'
                b'Proxy-Authenticate: Basic realm=GotoX\r\n'
                b'Content-Length: 0\r\n'
                b'Proxy-Connection: keep-alive\r\n\r\n')
        auth_white_list = set(GC.LISTEN_AUTHWHITELIST)
        auth_black_list = LRUCache(32, 3600 * 6)
        users = GC.LISTEN_AUTHUSER
        every_try_times = 2
        #最大失败次数，超出后加入黑名单，时效 6 小时
        max_try_times = 5

        skip_auth_check = False
        auth_header_send_count = 0

        def setup(self):
            AutoProxyHandler.setup(self)
            if not self.skip_auth_check:
                self.skip_auth_check = self.client_address[0] in self.auth_white_list

        def check_auth(self):
            if self.skip_auth_check:
                return True
            client_ip = self.client_address[0]
            auth_black_list = self.auth_black_list
            if client_ip in auth_black_list and auth_black_list[client_ip] > self.max_try_times:
                auth_black_list[client_ip] = times = auth_black_list[client_ip] + 1
                logging.error('%s 黑名单 IP 第 %s 次请求代理！"%s %s"',
                        self.address_string(), times, self.command, self.url or self.path)
                return
            auth_data = self.headers.get('Proxy-Authorization')
            if auth_data:
                method, _, auth_user = auth_data.partition(' ')
                if method.lower() == 'basic':
                    try:
                        auth_user = b64decode(auth_user).decode()
                    except:
                        pass
                    else:
                        if auth_user in self.users:
                            self.skip_auth_check = True
                            return True
            if self.auth_header_send_count < self.every_try_times:
                self.write(self.require_auth_header)
                self.auth_header_send_count += 1
                self.close_connection = False
            elif self.command == 'CONNECT':
                self._do_CONNECT()
                self.do_FAKECERT()
            else:
                self.write(self.auth_warning)
                try:
                    auth_black_list[client_ip] += self.every_try_times
                except KeyError:
                    auth_black_list[client_ip] = self.every_try_times
                logging.error('%s 请求代理，但密码错误！"%s %s"',
                        self.address_string(), self.command, self.url or self.path)

    ProxyAuthHandler = ProxyBasicAuthHandler

class AutoProxyAuthHandler(ProxyAuthHandler, AutoProxyHandler):

    def do_CONNECT(self):
        if self.check_auth():
            AutoProxyHandler.do_CONNECT(self)

    def do_METHOD(self):
        if self.check_auth():
            AutoProxyHandler.do_METHOD(self)

class ACTProxyAuthHandler(ProxyAuthHandler, ACTProxyHandler):

    def do_CONNECT(self):
        if self.check_auth():
            ACTProxyHandler.do_CONNECT(self)

    def do_METHOD(self):
        if self.check_auth():
            ACTProxyHandler.do_METHOD(self)
