#!/usr/bin/env python3
# coding:utf-8

import os
import sys

sys.dont_write_bytecode = True

import warnings
warnings.filterwarnings('ignore', '"is" with a literal', SyntaxWarning, append=True) # py38+

from common import (
    root_dir as app_root, config_dir, icon_gotox, direct_ipdb, direct_domains,
    config_filename, config_user_filename, config_auto_filename, single_instance,
    get_dirname, getlogger, startfile, load_config as _load_config, cconfig)

single_instance('gotox.win_tray')
logging = getlogger()

app_start = os.path.join(app_root, 'start.py')
create_shortcut_js = os.path.join(app_root, 'create_shortcut.vbs')
refresh_proxy = os.path.join(app_root, 'launcher', 'refresh_proxy_win.py')


import winreg
import ctypes
from time import sleep
from subprocess import Popen
from local import __version__ as gotoxver

SET_PATH = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
ProxyOverride = ';'.join(
    ['localhost', '127.*', '192.168.*', '10.*'] +
    ['100.%d.*' % (64 + n) for n in range(1 << 6)] +
    ['172.%d.*' % (16 + n) for n in range(1 << 4)])

hwnd = ctypes.windll.kernel32.GetConsoleWindow()
CreateEvent = ctypes.windll.kernel32.CreateEventA
SetEvent = ctypes.windll.kernel32.SetEvent
WaitForSingleObject = ctypes.windll.kernel32.WaitForSingleObject
RegNotifyChangeKeyValue = ctypes.windll.advapi32.RegNotifyChangeKeyValue
ShowWindow = ctypes.windll.user32.ShowWindow
MessageBox = ctypes.windll.user32.MessageBoxW
IsWindowVisible = ctypes.windll.user32.IsWindowVisible

def reg_notify():
    assert RegNotifyChangeKeyValue(
        SETTINGS.handle,                   # hKey
        False,                             # bWatchSubtree
        winreg.REG_NOTIFY_CHANGE_LAST_SET, # dwNotifyFilter
        notifyHandle,                      # hEvent
        True                               # fAsynchronous
    ) == 0, 'RegNotifyChangeKeyValue 失败'

try:
    ACCESS = winreg.KEY_QUERY_VALUE | winreg.KEY_NOTIFY | winreg.KEY_SET_VALUE
    SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER, SET_PATH, access=ACCESS)
    INFINITE = -1

    notifyHandle = CreateEvent(
        None,                      # lpEventAttributes
        False,                     # bManualReset
        False,                     # bInitialState
        'pyInternetSettingsNotify' # lpName
    )
    assert notifyHandle != 0, 'CreateEvent 失败'
    reg_notify()
except Exception as e:
    reg_notify = None
    if notifyHandle:
        CloseHandle(notifyHandle)
        notifyHandle = None
    logging.warning('发生错误：%s，采用轮询方式替代注册表监视。', e)
    ACCESS = winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE
    SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER, SET_PATH, access=ACCESS)

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
            for k, v in (kv.split('=', 1) for kv in server_str.split(';') if kv):
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
    Popen((sys.executable, refresh_proxy))

GotoX_app = None

def load_config():
    global LISTEN_AUTO, LISTEN_ACT, LISTEN_ACTTYPE
    _LISTEN_AUTO, _LISTEN_ACT, LISTEN_ACTTYPE = _load_config()
    LISTEN_ACT = proxy_server(_LISTEN_ACT, True)
    LISTEN_AUTO = proxy_server(_LISTEN_AUTO, True)

def start_GotoX():
    global GotoX_app
    load_config()
    GotoX_app = Popen((sys.executable, app_start))
    os.environ['HTTPS_PROXY'] = os.environ['HTTP_PROXY'] = LISTEN_AUTO.http

def stop_GotoX():
    if GotoX_app is None:
        logging.warning('GotoX 进程还未开始。')
    else:
        retcode = GotoX_app.poll()
        if retcode is None:
            urlopen('http://localhost/docmd?cmd=quit')
        else:
            logging.warning('GotoX 进程已经结束，code：%s。', retcode)

def on_show(systray):
    ShowWindow(hwnd, 1)

def on_hide(systray):
    ShowWindow(hwnd, 0)

def on_create_shortcut(systray):
    os.system(create_shortcut_js)

from urllib.request import urlopen
def on_reset_dns(systray):
    urlopen('http://localhost/docmd?cmd=reset_dns')

def on_reset_autorule(systray):
    urlopen('http://localhost/docmd?cmd=reset_autorule')

def on_refresh(systray):
    if MessageBox(None,
            '是否重新载入 GotoX？', '请确认', 4 | 48) == 6:
        stop_GotoX()
        start_GotoX()
        ShowWindow(hwnd, 8)

def on_about(systray):
    about = 'GotoX v%s\n\nhttps://github.com/SeaHOH/GotoX' % gotoxver
    MessageBox(None, about, '关于', 0)

def on_quit(systray):
    global running
    running = False
    stop_GotoX()
    if reg_notify:
        SetEvent(notifyHandle)

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

def on_enable_act_proxy(systray):
    enable_proxy(LISTEN_ACT)

def on_left_click(systray):
    build_menu(systray)
    systray._show_menu()

def on_right_click(systray):
    visible = IsWindowVisible(hwnd)
    ShowWindow(hwnd, visible^1)

from winsystray import SysTrayIcon, win32_adapter
import buildipdb
import builddomains

gloop_conf = os.path.join(config_dir, 'gloop.conf')

buildipdb.ds_APNIC.load()
builddomains.ds_FELIX.load()
gloop = cconfig('gloop', conf=gloop_conf)
gloop.add(['libuv-cffi', 'libev-cext', 'libev-cffi', 'nogevent'])
gloop.load()

MFS_CHECKED = win32_adapter.MFS_CHECKED
MFS_ENABLED = win32_adapter.MFS_ENABLED
MFS_DISABLED = win32_adapter.MFS_DISABLED
MFS_DEFAULT = win32_adapter.MFS_DEFAULT
MFT_RADIOCHECK = win32_adapter.MFT_RADIOCHECK
fixed_fState = MFS_CHECKED | MFS_DISABLED
NIIF_WARNING = win32_adapter.NIIF_WARNING
NIIF_USER = win32_adapter.NIIF_USER
NIIF_LARGE_ICON = win32_adapter.NIIF_LARGE_ICON

def download_cniplist(p):
    msg = buildipdb.download_cniplist_as_db(direct_ipdb, p)
    if msg:
        balloons_warning(msg)

def download_domains(p):
    msg = builddomains.download_domains_as_txt(direct_domains, p)
    if msg:
        balloons_warning(msg)

def build_menu(systray):
    libuv_cffi_state = gloop.check('libuv-cffi') and fixed_fState or MFS_ENABLED
    libev_cext_state = gloop.check('libev-cext') and fixed_fState or MFS_ENABLED
    libev_cffi_state = gloop.check('libev-cffi') and fixed_fState or MFS_ENABLED
    nogevent_state = gloop.check('nogevent') and fixed_fState or MFS_ENABLED
    default_loop_state = not (libuv_cffi_state or libev_cext_state or libev_cffi_state or nogevent_state) and fixed_fState or MFS_ENABLED
    sub_menu1 = (('打开默认配置', lambda x: startfile(config_filename)), #双击打开第一个有效命令
                 ('打开用户配置', lambda x: startfile(config_user_filename)),
                 ('打开自动规则配置', lambda x: startfile(config_auto_filename)),
                 (None, '-'),
                 ('选择 gevent 优先使用的事件循环', 'pass', MFS_DISABLED),
                 ('以下名称同时也是等价命令行参数', 'pass', MFS_DISABLED),
                 ('    ├─ libuv-cffi', lambda x: gloop.checked('libuv-cffi', True), libuv_cffi_state, MFT_RADIOCHECK),
                 ('    ├─ libev-cext', lambda x: gloop.checked('libev-cext', True), libev_cext_state, MFT_RADIOCHECK),
                 ('    ├─ libev-cffi', lambda x: gloop.checked('libev-cffi', True), libev_cffi_state, MFT_RADIOCHECK),
                 ('    ├─ nogevent (禁用)', lambda x: gloop.checked('nogevent', True), nogevent_state, MFT_RADIOCHECK),
                 ('    └─ 默认', lambda x: gloop.clear(True), default_loop_state, MFT_RADIOCHECK))
    mo_state = buildipdb.ds_APNIC.check('mo') and MFS_CHECKED or MFS_ENABLED
    hk_state = buildipdb.ds_APNIC.check('hk') and MFS_CHECKED or MFS_ENABLED
    sub_menu2 = (('建议更新频率：10～30 天一次', 'pass', MFS_DISABLED),
                 (None, '-'),
                 ('Ⅰ 从 APNIC 下载（每日更新）', lambda x: download_cniplist(buildipdb.ds_APNIC)),
                 ('    ├─ 包含澳门', lambda x: buildipdb.ds_APNIC.switch('mo', True), mo_state, MFT_RADIOCHECK),
                 ('    └─ 包含香港', lambda x: buildipdb.ds_APNIC.switch('hk', True), hk_state, MFT_RADIOCHECK),
                 ('Ⅱ 从 17mon 下载（每月初更新）', lambda x: download_cniplist(buildipdb.ds_17MON)),
                 ('Ⅲ 从 gaoyifan 下载（每日更新）', lambda x: download_cniplist(buildipdb.ds_GAOYIFAN)),
                 ('从 Ⅰ、Ⅱ 下载后合并', lambda x: download_cniplist(buildipdb.ds_APNIC | buildipdb.ds_17MON)),
                 ('从 Ⅰ、Ⅲ 下载后合并', lambda x: download_cniplist(buildipdb.ds_APNIC | buildipdb.ds_GAOYIFAN)),
                 ('从 Ⅱ、Ⅲ 下载后合并', lambda x: download_cniplist(buildipdb.ds_17MON | buildipdb.ds_GAOYIFAN)),
                 ('全部下载后合并', lambda x: download_cniplist(buildipdb.data_source_manager.sign_all)))
    fapple_state = builddomains.ds_FELIX.check('apple') and MFS_CHECKED or MFS_ENABLED
    sub_menu3 = (('建议更新频率：1～7 天一次', 'pass', MFS_DISABLED),
                 (None, '-'),
                 ('Ⅰ 从 felixonmars 下载（每日更新）', lambda x: download_domains(builddomains.ds_FELIX)),
                 ('    └─ 包含 apple', lambda x: builddomains.ds_FELIX.switch('apple', True), fapple_state, MFT_RADIOCHECK),
                 ('全部下载后合并', lambda x: download_domains(builddomains.data_source_manager.sign_all)))
    global proxy_state_menu, last_main_menu
    proxy_state_menu = proxy_state = get_proxy_state()
    disable_state = proxy_state.type == 0 and fixed_fState or MFS_ENABLED
    disable_http_state = disable_state or proxy_state.type & 2 and not proxy_state.http and fixed_fState or MFS_ENABLED
    disable_https_state = disable_state or proxy_state.type & 2 and not proxy_state.https and fixed_fState or MFS_ENABLED
    disable_ftp_state = disable_state or proxy_state.type & 2 and not proxy_state.ftp and fixed_fState or MFS_ENABLED
    disable_socks_state = disable_state or proxy_state.type & 2 and not proxy_state.socks and fixed_fState or MFS_ENABLED
    auto_state = proxy_state.type == 2 and LISTEN_AUTO in proxy_state and fixed_fState or MFS_ENABLED
    act_state = proxy_state.type == 2 and LISTEN_ACT in proxy_state  and fixed_fState or MFS_ENABLED
    sub_menu4 = (
                 ('使用自动代理', on_enable_auto_proxy, auto_state, MFT_RADIOCHECK),
                 ('使用 %s 代理' % LISTEN_ACTTYPE, on_enable_act_proxy, act_state, MFT_RADIOCHECK),
                 ('完全禁用代理', on_disable_proxy, disable_state, MFT_RADIOCHECK),
                 (None, '-'),
                 ('禁用 HTTP 代理', on_disable_http_proxy, disable_http_state, MFT_RADIOCHECK),
                 ('禁用 HTTPS 代理', on_disable_https_proxy, disable_https_state, MFT_RADIOCHECK),
                 ('禁用 FTP 代理', on_disable_ftp_proxy, disable_ftp_state, MFT_RADIOCHECK),
                 ('禁用 SOCKS 代理', on_disable_socks_proxy, disable_socks_state, MFT_RADIOCHECK))
    visible = IsWindowVisible(hwnd)
    show_state = visible and fixed_fState or MFS_ENABLED
    hide_state = not visible and fixed_fState or MFS_ENABLED
    main_menu = (('GotoX 设置', sub_menu1, icon_gotox, MFS_DEFAULT),
                 ('更新直连 IP 库', sub_menu2),
                 ('更新直连域名列表', sub_menu3),
                 (None, '-'),
                 ('显示窗口', on_show, show_state, MFT_RADIOCHECK),
                 ('隐藏窗口', on_hide, hide_state, MFT_RADIOCHECK),
                 ('创建桌面快捷方式', on_create_shortcut),
                 ('设置系统（IE）代理', sub_menu4),
                 ('重置 DNS 缓存', on_reset_dns),
                 ('重置自动规则缓存', on_reset_autorule),
                 ('重启 GotoX', on_refresh),
                 (None, '-'),
                 ('关于', on_about))
    if main_menu != last_main_menu:
        systray.update(menu=main_menu)
        last_main_menu = main_menu

def update_tip():
    global last_proxy_state
    new_proxy_state = get_proxy_state()
    if last_proxy_state and last_proxy_state.str == new_proxy_state.str:
        return
    systray_GotoX.update(hover_text='GotoX\n当前系统（IE）代理：\n%s' % new_proxy_state)
    last_proxy_state = new_proxy_state
    return new_proxy_state

def balloons_info(text, title='GotoX 通知'):
    systray_GotoX.show_balloon(text, title, NIIF_USER | NIIF_LARGE_ICON)

def balloons_warning(text, title='注意'):
    systray_GotoX.show_balloon(text, title, NIIF_WARNING | NIIF_LARGE_ICON)

def notify_proxy_changed():
    old_proxy_state = last_proxy_state
    new_proxy_state = update_tip()
    if new_proxy_state:
        text = '设置由：\n%s\n变更为：\n%s' % (old_proxy_state, new_proxy_state)
        balloons_warning(text, '系统代理改变')

last_main_menu = None
last_proxy_state = None
quit_item = '退出', on_quit
systray_GotoX = SysTrayIcon(icon_gotox, 'GotoX', None, quit_item,
                            left_click=on_left_click,
                            right_click=on_right_click)
systray_GotoX.start()
start_GotoX()
#load_config()
#os.environ['HTTPS_PROXY'] = os.environ['HTTP_PROXY'] = LISTEN_AUTO.http
sleep(0.1)
balloons_info('''
GotoX 已经启动。        

左键单击：打开菜单

左键双击：打开配置

右键单击：隐显窗口

当前系统代理设置为：
%s''' % update_tip())

running = True
if reg_notify is None:
    while running:
        for _ in range(50):
            if running:
                sleep(0.1)
            else:
                break
        notify_proxy_changed()
else:
    while running:
        WaitForSingleObject(notifyHandle, INFINITE)
        if not running:
            break
        notify_proxy_changed()
        reg_notify()
