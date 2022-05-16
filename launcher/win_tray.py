#!/usr/bin/env python3
#-*- coding: UTF-8 -*-

import os
import sys

sys.dont_write_bytecode = True

from common import (
    root_dir as app_root, config_dir, icon_gotox, direct_ipdb, direct_domains,
    config_filename, config_user_filename, config_auto_filename, single_instance,
    get_dirname, getlogger, startfile, load_config as _load_config, cconfig)

single_instance('gotox.win_tray')
logger = getlogger()

app_start = os.path.join(app_root, 'start.py')
create_shortcut_js = os.path.join(app_root, 'create_shortcut.vbs')
refresh_proxy = os.path.join(app_root, 'launcher', 'refresh_proxy_win.py')
wintray_conf = os.path.join(config_dir, 'win_tray.conf')


import winreg
import ctypes
from time import sleep
from subprocess import Popen
from local import __version__ as gotoxver

SET_PATH = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
ProxyOverride_local = ';'.join(
    ['localhost', '127.*', '192.168.*', '10.*'] +
    ['100.%d.*' % (64 + n) for n in range(1 << 6)] +
    ['172.%d.*' % (16 + n) for n in range(1 << 4)])
sysproxy_keys = 'AutoConfigURL', 'ProxyEnable', 'ProxyServer', 'ProxyOverride'

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
    logger.warning('发生错误：%s，采用轮询方式替代注册表监视。', e)
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
                server_list.append(f'{k}={v}')
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

    def __bool__(self):
        return bool(self.type)

def reg_query_value(key, path=SETTINGS):
    try:
        return winreg.QueryValueEx(path, key)
    except:
        return None, None

def reg_get_value(key, path=SETTINGS):
    return reg_query_value(key, path)[0]

def reg_set_value(key, rtype, value, path=SETTINGS):
    if rtype is None or value is None:
        reg_del_value(key, path=path)
    else:
        winreg.SetValueEx(path, key, 0, rtype, value)

def reg_del_value(key, path=SETTINGS):
    try:
        winreg.DeleteValue(path, key)
    except:
        pass

def get_proxy_state():
    AutoConfigURL = proxy_server(reg_get_value('AutoConfigURL'))
    if reg_get_value('ProxyEnable'):
        ProxyServer = proxy_server(reg_get_value('ProxyServer'))
    else:
        ProxyServer = proxy_server(None)
    if AutoConfigURL:
        if ProxyServer:
            ProxyServer.pac = AutoConfigURL.pac
            ProxyServer.type |= 1
        else:
            ProxyServer = AutoConfigURL
    return ProxyServer

def refresh_proxy_state(enable=None):
    if enable:
        ProxyOverride = reg_get_value('ProxyOverride')
        #导入默认代理例外地址
        if not ProxyOverride:
            reg_set_value('ProxyOverride', winreg.REG_SZ, ProxyOverride_local)
        if ProxyOverride == '<local>':
            reg_set_value('ProxyOverride', winreg.REG_SZ, f'{ProxyOverride_local};<local>')
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
        logger.warning('GotoX 进程还未开始。')
    else:
        retcode = GotoX_app.poll()
        if retcode is None:
            urlopen('http://localhost/docmd?cmd=quit')
        else:
            logger.warning('GotoX 进程已经结束，code：%s。', retcode)

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

def on_reset_autorule_cache(systray):
    urlopen('http://localhost/docmd?cmd=reset_autorule_cache')

def on_refresh(systray):
    if MessageBox(None,
            '是否重新载入 GotoX？', '请确认', 4 | 48) == 6:
        stop_GotoX()
        start_GotoX()
        ShowWindow(hwnd, 8)

def on_about(systray):
    about = f'GotoX v{gotoxver}\n\nhttps://github.com/SeaHOH/GotoX'
    MessageBox(None, about, '关于', 0)

def on_quit(systray):
    global running
    running = False
    if sysproxy.check('quit-restore'):
        for key, (value, rtype) in sysproxy_start_state.items():
            reg_set_value(key, rtype, value)
        Popen((sys.executable, refresh_proxy))
    stop_GotoX()
    if reg_notify:
        SetEvent(notifyHandle)

def on_disable_proxy(systray):
    proxy_state = proxy_state_menu
    if proxy_state.type & 1:
        reg_del_value('AutoConfigURL')
    if proxy_state.type & 2:
        reg_set_value('ProxyEnable', winreg.REG_DWORD, 0)
    refresh_proxy_state()

def disable_x_proxy(type):
    proxy_state = proxy_state_menu
    proxy_state.__delattr__(type)
    #忽略 AutoConfigURL 保持原样，如有则优先
    #设置代理类型为 Server
    proxy_state.type = 2
    ProxyServer = proxy_state.str
    if ProxyServer == '':
        reg_set_value('ProxyEnable', winreg.REG_DWORD, 0)
    else:
        reg_set_value('ProxyServer', winreg.REG_SZ, ProxyServer)
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
        reg_del_value('AutoConfigURL')
    if not proxy_state.type & 2:
        reg_set_value('ProxyEnable', winreg.REG_DWORD, 1)
    proxy_state.type = 2
    proxy_state.http = ProxyServer.http
    proxy_state.https = ProxyServer.https
    reg_set_value('ProxyServer', winreg.REG_SZ, proxy_state.str)
    refresh_proxy_state(True)

def on_enable_auto_proxy(systray):
    enable_proxy(LISTEN_AUTO)
    sysproxy.set('auto')
    sysproxy.set('act', 0, True)

def on_enable_act_proxy(systray):
    enable_proxy(LISTEN_ACT)
    sysproxy.set('act')
    sysproxy.set('auto', 0, True)

def on_left_click(systray):
    build_menu(systray)
    systray._show_menu()

def on_right_click(systray):
    visible = IsWindowVisible(hwnd)
    ShowWindow(hwnd, visible^1)

from winsystray import SysTrayIcon, win32_adapter
import updatecas
import buildipdb
import builddomains

buildipdb.data_source_manager.load()
builddomains.data_source_manager.load()
if not buildipdb.data_source_manager.data_source:
    buildipdb.data_source_manager.set(buildipdb.ds_17MON.name)
builddomains.data_source_manager.set(builddomains.ds_FELIX.name)
wintray = cconfig('wintray', conf=wintray_conf)
gloop = wintray.add_child('gloop')
gloop.add(['libuv-cffi', 'libev-cext', 'libev-cffi', 'nogevent'])
gloop.load()
sysproxy = wintray.add_child('sysproxy')
sysproxy.add(['start-set', 'quit-restore', 'auto', 'act'])
sysproxy.load()

MFS_CHECKED = win32_adapter.MFS_CHECKED
MFS_ENABLED = win32_adapter.MFS_ENABLED
MFS_DISABLED = win32_adapter.MFS_DISABLED
MFS_DEFAULT = win32_adapter.MFS_DEFAULT
MFT_RADIOCHECK = win32_adapter.MFT_RADIOCHECK
fixed_fState = MFS_CHECKED | MFS_DISABLED
pass_fState = 'pass', MFS_DISABLED
NIIF_WARNING = win32_adapter.NIIF_WARNING
NIIF_USER = win32_adapter.NIIF_USER
NIIF_LARGE_ICON = win32_adapter.NIIF_LARGE_ICON

def make_rc_state(checked, disable=True):
    return checked and (disable and fixed_fState or MFS_CHECKED
            ) or MFS_ENABLED, MFT_RADIOCHECK

def on_update_cas(systray):
    msg = updatecas.update(updatecas.ds_GOOGLE, updatecas.ds_MOZILLA)
    if msg:
        balloons_warning(msg)

def download_cniplist(p):
    msg = buildipdb.download_cniplist_as_db(direct_ipdb, p)
    if msg:
        balloons_warning(msg)

def download_domains(p):
    msg = builddomains.download_domains_as_txt(direct_domains, p)
    if msg:
        balloons_warning(msg)

def compare_menu_eq(a, b):
    if bool(a) != bool(b) or len(a) != len(b):
        return False
    eq = True
    for ma, mb in zip(a, b):
        # 忽略 lambda
        if getattr(ma, '__name__', None) == '<lambda>':
            continue
        if isinstance(ma, tuple):
            eq = compare_menu_eq(ma, mb)
        else:
            eq = ma == mb
        if not eq:
            break
    return eq

def build_menu(systray):
    sub_menu1 = (('打开默认配置', lambda x: startfile(config_filename)), #双击打开第一个有效命令
                 ('打开用户配置', lambda x: startfile(config_user_filename)),
                 ('打开自动规则配置', lambda x: startfile(config_auto_filename)),
                 (None, '-'),
                 ('选择 gevent 优先使用的事件循环', *pass_fState),
                 ('以下名称同时也是等价命令行参数', *pass_fState),
                 ('  ├─ libuv-cffi', lambda x: gloop.checked('libuv-cffi', True), *make_rc_state(gloop.check('libuv-cffi'))),
                 ('  ├─ libev-cext', lambda x: gloop.checked('libev-cext', True), *make_rc_state(gloop.check('libev-cext'))),
                 ('  ├─ libev-cffi', lambda x: gloop.checked('libev-cffi', True), *make_rc_state(gloop.check('libev-cffi'))),
                 ('  ├─ nogevent (禁用)', lambda x: gloop.checked('nogevent', True), *make_rc_state(gloop.check('nogevent'))),
                 ('  └─ 默认', lambda x: gloop.clear(True), *make_rc_state(not gloop)),
                )
    sub_menu2 = (('点击此处开始更新', on_update_cas),
                 ('建议更新频率：60 天一次', *pass_fState),
                 ('固定数据来源', *pass_fState),
                 (None, '-'),
                 ('Google Trust Services', *pass_fState),
                 ('Mozilla NSS, 由 curl.se 提供转换格式', *pass_fState)
                )
    dsm = buildipdb.data_source_manager
    apnic_checked = dsm.check(buildipdb.ds_APNIC.name)
    l7mon_checked = dsm.check(buildipdb.ds_17MON.name)
    gaoyifan_checked = dsm.check(buildipdb.ds_GAOYIFAN.name)
    misakaio_checked = dsm.check(buildipdb.ds_MISAKAIO.name)
    standalone_source = sum(map(int, [apnic_checked, l7mon_checked, gaoyifan_checked, misakaio_checked])) == 1
    sub_menu3 = (('点击此处开始更新', lambda x: download_cniplist(dsm.data_source)),
                 ('建议更新频率：10～30 天一次', *pass_fState),
                 ('请选择数据来源（多选）', *pass_fState),
                 (None, '-'),
                 ('APNIC（每日更新）', lambda x: dsm.switch(buildipdb.ds_APNIC.name, True), *make_rc_state(apnic_checked, standalone_source)),
                 ('  ├─ 包含澳门', lambda x: buildipdb.ds_APNIC.switch('mo', True), *make_rc_state(buildipdb.ds_APNIC.check('mo'), False)),
                 ('  └─ 包含香港', lambda x: buildipdb.ds_APNIC.switch('hk', True), *make_rc_state(buildipdb.ds_APNIC.check('hk'), False)),
                 ('17mon（每季度更新）', lambda x: dsm.switch(buildipdb.ds_17MON.name, True), *make_rc_state(l7mon_checked, standalone_source)),
                 ('gaoyifan（每日更新）', lambda x: dsm.switch(buildipdb.ds_GAOYIFAN.name, True), *make_rc_state(gaoyifan_checked, standalone_source)),
                 ('misakaio（每小时更新）', lambda x: dsm.switch(buildipdb.ds_MISAKAIO.name, True), *make_rc_state(misakaio_checked, standalone_source)),
                )
    sub_menu4 = (('点击此处开始更新', lambda x: download_domains(builddomains.data_source_manager.data_source)),
                 ('建议更新频率：1～7 天一次', *pass_fState),
                 ('请选择数据来源', *pass_fState),
                 (None, '-'),
                 ('felixonmars（随时更新）', 'pass', *make_rc_state(True)),
                 ('  └─ 包含 apple', lambda x: builddomains.ds_FELIX.switch('apple', True), *make_rc_state(builddomains.ds_FELIX.check('apple'), False))
                )
    global proxy_state_menu, last_main_menu
    proxy_state_menu = proxy_state = get_proxy_state()
    auto_state = proxy_state.type == 2 and LISTEN_AUTO in proxy_state
    act_state = proxy_state.type == 2 and LISTEN_ACT in proxy_state
    disable_state = proxy_state.type == 0
    disable_http_state = disable_state or proxy_state.type & 2 and not proxy_state.http
    disable_https_state = disable_state or proxy_state.type & 2 and not proxy_state.https
    disable_ftp_state = disable_state or proxy_state.type & 2 and not proxy_state.ftp
    disable_socks_state = disable_state or proxy_state.type & 2 and not proxy_state.socks
    sub_menu5 = (('启动时设置代理', lambda x: sysproxy.switch('start-set', True), *make_rc_state(sysproxy.check('start-set'), False)),
                 ('退出时恢复代理', lambda x: sysproxy.switch('quit-restore', True), *make_rc_state(sysproxy.check('quit-restore'), False)),
                 (None, '-'),
                 ('使用自动代理', on_enable_auto_proxy, *make_rc_state(auto_state)),
                 (f'使用 {LISTEN_ACTTYPE} 代理', on_enable_act_proxy, *make_rc_state(act_state)),
                 ('完全禁用代理', on_disable_proxy, *make_rc_state(disable_state)),
                 (None, '-'),
                 ('禁用 HTTP 代理', on_disable_http_proxy, *make_rc_state(disable_http_state)),
                 ('禁用 HTTPS 代理', on_disable_https_proxy, *make_rc_state(disable_https_state)),
                 ('禁用 FTP 代理', on_disable_ftp_proxy, *make_rc_state(disable_ftp_state)),
                 ('禁用 SOCKS 代理', on_disable_socks_proxy, *make_rc_state(disable_socks_state)),
                )
    visible = IsWindowVisible(hwnd)
    main_menu = (('GotoX 设置', sub_menu1, icon_gotox, MFS_DEFAULT),
                 ('更新 CA 证书集', sub_menu2),
                 ('更新直连 IP 库', sub_menu3),
                 ('更新直连域名列表', sub_menu4),
                 (None, '-'),
                 visible and ('隐藏窗口', on_hide) or ('显示窗口', on_show),
                 ('创建桌面快捷方式', on_create_shortcut),
                 (f'设置系统（{sys_web_browser}）代理', sub_menu5),
                 ('重置 DNS 缓存', on_reset_dns),
                 ('重置自动规则缓存', on_reset_autorule_cache),
                 ('重置自动规则', on_reset_autorule),
                 ('重启 GotoX', on_refresh),
                 (None, '-'),
                 ('关于', on_about)
                )
    if not compare_menu_eq(main_menu, last_main_menu):
        systray.update(menu=main_menu)
        last_main_menu = main_menu

def update_tip():
    global last_proxy_state
    new_proxy_state = get_proxy_state()
    if last_proxy_state and last_proxy_state.str == new_proxy_state.str:
        return
    systray_GotoX.update(hover_text=f'GotoX\n当前系统（{sys_web_browser}）代理：\n{new_proxy_state}')
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
        text = f'设置由：\n{old_proxy_state}\n变更为：\n{new_proxy_state}'
        balloons_warning(text, '系统代理改变')

sys_web_browser = sys.getwindowsversion().major < 10 and 'IE' or 'Edge'
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
balloons_info(f'''
GotoX 已经启动。

左键单击：打开菜单

左键双击：打开配置

右键单击：隐显窗口

当前系统代理设置为：

{update_tip()}''')

sysproxy_start_state = {key: reg_query_value(key) for key in sysproxy_keys}
if sysproxy.check('start-set'):

    def _enable_proxy(proxy):
        global proxy_state_menu
        proxy_state_menu = get_proxy_state()
        enable_proxy(proxy)
        sleep(5)
        notify_proxy_changed()

    if sysproxy.check('auto'):
        _enable_proxy(LISTEN_AUTO)
    elif sysproxy.check('act'):
        _enable_proxy(LISTEN_ACT)

    del _enable_proxy

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
