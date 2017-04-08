#!/usr/bin/env python3
# coding:utf-8

import os
import sys
sys.dont_write_bytecode = True

__file__ = os.path.abspath(__file__)
if os.path.islink(__file__):
    __file__ = getattr(os, 'readlink', lambda x: x)(__file__)

app_root = os.path.dirname(os.path.dirname(__file__))
py_path = os.path.join(app_root, 'python')
py_exe = sys.executable
app_start = os.path.join(app_root, 'start.py')
icon_gotox = os.path.join(app_root, 'gotox.ico')
config_dir = os.path.join(app_root, 'config')
ipdb_direct = os.path.join(app_root, 'data', 'directip.db')
refresh_proxy = os.path.join(app_root, 'launcher', 'refresh_proxy_win.py')

#使用安装版 Python
if os.path.dirname(py_exe) != py_path:
    import glob
    helpers = os.path.join(py_path, 'site-packages', 'helpers_win32.egg')
    sys.path.insert(0, helpers)
sys.path.insert(0, app_root)

import re
from configparser import ConfigParser
#默认编码
_read = ConfigParser.read
ConfigParser.read = lambda s, f, encoding='utf8': _read(s, f, encoding)

CONFIG_FILENAME = os.path.join(config_dir, 'Config.ini')
CONFIG_USER_FILENAME = re.sub(r'\.ini$', '.user.ini', CONFIG_FILENAME)
CONFIG_AUTO_FILENAME = os.path.join(config_dir, 'ActionFilter.ini')

def get_listen_addr():
    CONFIG = ConfigParser(inline_comment_prefixes=('#', ';'))
    CONFIG._optcre = re.compile(r'(?P<option>[^=\s]+)\s*(?P<vi>=?)\s*(?P<value>.*)')
    CONFIG.read([CONFIG_FILENAME, CONFIG_USER_FILENAME])
    LISTEN_IP = CONFIG.get('listen', 'ip')
    if LISTEN_IP == '0.0.0.0': LISTEN_IP = '127.0.0.1'
    LISTEN_GAE = '%s:%d' % (LISTEN_IP, CONFIG.getint('listen', 'gae_port'))
    LISTEN_AUTO = '%s:%d' % (LISTEN_IP, CONFIG.getint('listen', 'auto_port'))
    return proxy_server(LISTEN_GAE, True), proxy_server(LISTEN_AUTO, True)

import winreg

SET_PATH = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER, SET_PATH, 0, winreg.KEY_ALL_ACCESS)
ProxyOverride = ('localhost;127.*;192.168.*;10.*;172.16.*;172.17.*;172.18.*;'
                 '172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;'
                 '172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*')

class proxy_server:
    __slots__ = 'type', 'pac', 'http', 'https', 'ftp', 'socks'

    def __init__(self, server_str, http_only=None):
        if not server_str:
            self.type = 0
            return
        if '://' in server_str:
            self.type = 1
            self.pac = server_str
            return
        elif '=' in server_str:
            for k, v in (kv.split('=', 1) for kv in server_str.split(';')):
                self.__setattr__(k, v)
        else:
            self.http = server_str
            self.https = server_str
            if not http_only:
                self.ftp = server_str
                self.socks = server_str
        self.type = 2

    def __getattr__(self, attr):
        try:
            return self.__getattribute__(attr)
        except:
            if attr in self.__slots__:
                return None

    def __contains__(self, obj):
        if isinstance(obj, str):
            return obj in self.str
        if isinstance(obj, self.__class__):
            return ((not obj.http  or obj.http  == self.http ) and
                    (not obj.https or obj.https == self.https) and
                    (not obj.ftp   or obj.ftp   == self.ftp  ) and
                    (not obj.socks or obj.socks == self.socks))

    def get_server_list(self):
        server_list = []
        #按顺序重建
        for k in ('http', 'https', 'ftp', 'socks'):
            v = self.__getattr__(k)
            if v:
                server_list.append('%s=%s' % (k, v))
        return server_list

    @property
    def str(self):
        #作为设置参数使用
        if self.type == 0:
            return ''
        elif self.type & 1:
            return self.pac
        return ';'.join(self.get_server_list())

    def __str__(self):
        #打印用
        if self.type == 0:
            return '无'
        server_list = self.get_server_list()
        if self.type & 1:
            server_list.insert(0, 'pac=' + self.pac)
        return '\n'.join(server_list)

def get_proxy_state():
    AutoConfigURL = ProxyServer = None
    try:
        AutoConfigURL, reg_type = winreg.QueryValueEx(SETTINGS, 'AutoConfigURL')
        AutoConfigURL = proxy_server(AutoConfigURL)
    except:
        pass
    try:
        ProxyEnable, reg_type = winreg.QueryValueEx(SETTINGS, 'ProxyEnable')
        if ProxyEnable:
            ProxyServer, reg_type = winreg.QueryValueEx(SETTINGS, 'ProxyServer')
            ProxyServer = proxy_server(ProxyServer)
    except:
        pass
    if AutoConfigURL and ProxyServer:
        ProxyServer.pac = AutoConfigURL.pac
        ProxyServer.type |= 1
    elif AutoConfigURL:
        ProxyServer = AutoConfigURL
    elif ProxyServer:
        pass
    else:
        ProxyServer = proxy_server(None)
    return ProxyServer

def refresh_proxy_state(enable=None):
    if enable:
        try:
            ProxyOverride, reg_type = winreg.QueryValueEx(SETTINGS, 'ProxyOverride')
        except:
            ProxyOverride =None
        #导入默认代理例外地址
        if not ProxyOverride:
            winreg.SetValueEx(SETTINGS, 'ProxyOverride', 0,  winreg.REG_SZ, ProxyOverride)
    Popen((py_exe, refresh_proxy))

from subprocess import Popen
from local import __version__ as gotoxver, clogging as logging

GotoX_app = None

def start_GotoX():
    global GotoX_app, LISTEN_GAE, LISTEN_AUTO
    LISTEN_GAE, LISTEN_AUTO = get_listen_addr()
    GotoX_app = Popen((py_exe, app_start))
    os.environ['HTTPS_PROXY'] = os.environ['HTTP_PROXY'] = LISTEN_AUTO.http

def stop_GotoX():
    if GotoX_app is None:
        logging.warning('GotoX 进程还未开始。')
    else:
        retcode = GotoX_app.poll()
        if retcode is None:
            GotoX_app.terminate()
        else:
            logging.warning('GotoX 进程已经结束，code：%s。', retcode)

import ctypes
hwnd = ctypes.windll.kernel32.GetConsoleWindow()

def on_show(systray):
    ctypes.windll.user32.ShowWindow(hwnd, 1)

def on_hide(systray):
    ctypes.windll.user32.ShowWindow(hwnd, 0)

def on_refresh(systray):
    if ctypes.windll.user32.MessageBoxW(None,
            '是否重新载入 CotoX？', '请确认', 4 | 48) == 6:
        stop_GotoX()
        start_GotoX()
        ctypes.windll.user32.ShowWindow(hwnd, 8)

def on_about(systray):
    about = 'GotoX v%s\n\nhttps://github.com/SeaHOH/GotoX' % gotoxver
    ctypes.windll.user32.MessageBoxW(None, about, '关于', 0)

def on_quit(systray):
    stop_GotoX()
    winreg.CloseKey(SETTINGS)
    sys.exit(0)

def on_disable_proxy(systray):
    proxy_state = proxy_state_menu
    if proxy_state.type & 1:
        winreg.DeleteValue(SETTINGS, 'AutoConfigURL')
    if proxy_state.type & 2:
        winreg.SetValueEx(SETTINGS, 'ProxyEnable', 0,  winreg.REG_DWORD, 0)
    refresh_proxy_state()

def disable_x_proxy(type):
    proxy_state = proxy_state_menu
    proxy_state.__delattr__(type)
    #忽略 AutoConfigURL 保持原样，如有则优先
    #设置代理类型为 Server
    proxy_state.type = 2
    ProxyServer = proxy_state.str
    if ProxyServer == '':
        winreg.SetValueEx(SETTINGS, 'ProxyEnable', 0,  winreg.REG_DWORD, 0)
    else:
        winreg.SetValueEx(SETTINGS, 'ProxyServer', 0,  winreg.REG_SZ, ProxyServer)
    refresh_proxy_state()

def on_disable_http_proxy(systray):
    disable_x_proxy('http')

def on_disable_https_proxy(systray):
    disable_x_proxy('https')

def on_disable_ftp_proxy(systray):
    disable_x_proxy('ftp')

def on_disable_socks_proxy(systray):
    disable_x_proxy('socks')

def enable_proxy(ProxyServer):
    proxy_state = proxy_state_menu
    #删除 AutoConfigURL 确保使用 ProxyServer
    if proxy_state.pac:
        winreg.DeleteValue(SETTINGS, 'AutoConfigURL')    
    if not proxy_state.type & 2:
        winreg.SetValueEx(SETTINGS, 'ProxyEnable', 0,  winreg.REG_DWORD, 1)
    proxy_state.type = 2
    proxy_state.http = ProxyServer.http
    proxy_state.https = ProxyServer.https
    winreg.SetValueEx(SETTINGS, 'ProxyServer', 0,  winreg.REG_SZ, proxy_state.str)
    refresh_proxy_state(1)

def on_enable_auto_proxy(systray):
    enable_proxy(LISTEN_AUTO)

def on_enable_gae_proxy(systray):
    enable_proxy(LISTEN_GAE)

def on_left_click(systray):
    build_menu(systray)
    systray._show_menu()

def on_right_click(systray):
    visible = ctypes.windll.user32.IsWindowVisible(hwnd)
    ctypes.windll.user32.ShowWindow(hwnd, visible^1)

from winsystray import SysTrayIcon, win32_adapter
import buildipdb

MFS_CHECKED = win32_adapter.MFS_CHECKED
MFS_DISABLED = win32_adapter.MFS_DISABLED
MFS_DEFAULT = win32_adapter.MFS_DEFAULT
MFT_RADIOCHECK = win32_adapter.MFT_RADIOCHECK
fixed_fState = MFS_CHECKED | MFS_DISABLED

last_main_menu = None
sub_menu1 = (('打开默认配置', lambda x: Popen(CONFIG_FILENAME, shell=True)), #双击打开第一个有效命令
             ('打开用户配置', lambda x: Popen(CONFIG_USER_FILENAME, shell=True)),
             ('打开自动规则配置', lambda x: Popen(CONFIG_AUTO_FILENAME, shell=True)))
sub_menu2 = (('建议更新频率：10～30 天一次', 'pass', MFS_DISABLED),
             (None, '-'),
             ('从 APNIC 下载（每日更新）', lambda x: buildipdb.download_apnic_cniplist_as_db(ipdb_direct)),
             ('从 17mon 下载（每月初更新）', lambda x: buildipdb.download_17mon_cniplist_as_db(ipdb_direct)),
             ('从以上两者下载后合并', lambda x: buildipdb.download_both_cniplist_as_db(ipdb_direct)))

def build_menu(systray):
    global proxy_state_menu, last_main_menu
    proxy_state_menu = proxy_state = get_proxy_state()
    disable_state = proxy_state.type == 0 and fixed_fState or 0
    disable_http_state = disable_state or proxy_state.type & 2 and not proxy_state.http and fixed_fState or 0
    disable_https_state = disable_state or proxy_state.type & 2 and not proxy_state.https and fixed_fState or 0
    disable_ftp_state = disable_state or proxy_state.type & 2 and not proxy_state.ftp and fixed_fState or 0
    disable_socks_state = disable_state or proxy_state.type & 2 and not proxy_state.socks and fixed_fState or 0
    auto_state = proxy_state.type == 2 and LISTEN_AUTO in proxy_state and fixed_fState or 0
    gae_state = proxy_state.type == 2 and LISTEN_GAE in proxy_state  and fixed_fState or 0
    sub_menu3 = (
                 ('使用自动代理', on_enable_auto_proxy, auto_state, MFT_RADIOCHECK),
                 ('使用 GAE 代理', on_enable_gae_proxy, gae_state, MFT_RADIOCHECK),
                 ('完全禁用代理', on_disable_proxy, disable_state, MFT_RADIOCHECK),
                 (None, '-'),
                 ('禁用 HTTP 代理', on_disable_http_proxy, disable_http_state, MFT_RADIOCHECK),
                 ('禁用 HTTPS 代理', on_disable_https_proxy, disable_https_state, MFT_RADIOCHECK),
                 ('禁用 FTP 代理', on_disable_ftp_proxy, disable_ftp_state, MFT_RADIOCHECK),
                 ('禁用 SOCKS 代理', on_disable_socks_proxy, disable_socks_state, MFT_RADIOCHECK))
    visible = ctypes.windll.user32.IsWindowVisible(hwnd)
    show_state = visible and fixed_fState or 0
    hide_state = not visible and fixed_fState or 0
    main_menu = (('GotoX 设置', sub_menu1, icon_gotox, MFS_DEFAULT),
                 ('更新直连 IP 库', sub_menu2),
                 (None, '-'),
                 ('显示窗口', on_show, show_state, MFT_RADIOCHECK),
                 ('隐藏窗口', on_hide, hide_state, MFT_RADIOCHECK),
                 ('设置系统（IE）代理', sub_menu3),
                 ('重启 GotoX', on_refresh),
                 (None, '-'),
                 ('关于', on_about))
    if main_menu != last_main_menu:
        systray.update(menu=main_menu)
        last_main_menu = main_menu

quit_item = '退出', on_quit
systray_GotoX = SysTrayIcon(icon_gotox, 'GotoX', None, quit_item,
                            left_click=on_left_click,
                            right_click=on_right_click)
systray_GotoX.start()
start_GotoX()
#LISTEN_GAE, LISTEN_AUTO = get_listen_addr()

from time import sleep

proxy_state = get_proxy_state()
sleep(1)
systray_GotoX.update(
    hover_text='GotoX\n当前系统（IE）代理：\n%s' % proxy_state,
    balloons=('\nGotoX 已经启动。        \n\n'
              '左键单击：打开菜单\n\n'
              '左键双击：打开配置\n\n'
              '右键单击：隐藏窗口\n\n'
              '当前系统代理设置为：\n'
              '%s' % proxy_state,
              'GotoX 通知', 4 | 32, 15)
    )

while True:
    now_proxy_state = get_proxy_state()
    if proxy_state.str != now_proxy_state.str:
        text = '设置由：\n%s\n变更为：\n%s' % (proxy_state, now_proxy_state)
        proxy_state = now_proxy_state
        systray_GotoX.update(
            hover_text='GotoX\n当前系统（IE）代理：\n%s' % proxy_state,
            balloons=(text, '系统代理改变', 2 | 32, 15)
            )
    sleep(5)
