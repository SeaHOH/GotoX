#!/usr/bin/env python3
# coding:utf-8

import os
import sys
sys.dont_write_bytecode = True

__file__ = os.path.abspath(__file__)
if os.path.islink(__file__):
    __file__ = getattr(os, 'readlink', lambda x: x)(__file__)

app_root = os.path.dirname(os.path.dirname(__file__))
py_exe = os.path.join(app_root, 'python', 'python.exe')
app_start = os.path.join(app_root, 'start.py')
icon_gotox = os.path.join(app_root, 'gotox.ico')
config_dir = os.path.join(app_root, 'config')

sys.path.insert(0, app_root)

from local import __version__ as gotoxver, clogging as logging
from subprocess import Popen
import ctypes
from winsystray import SysTrayIcon, win32_adapter
import winreg
from time import sleep
from win32_proxy_manager import disable_proxy, set_proxy
import re
from configparser import ConfigParser
#默认编码
_read = ConfigParser.read
ConfigParser.read = lambda s, f, encoding='utf8': _read(s, f, encoding)

def get_listen_addr():
    CONFIG = ConfigParser()
    CONFIG._optcre = re.compile(r'(?P<option>[^=\s]+)\s*(?P<vi>=?)\s*(?P<value>.*)')
    CONFIG.read([CONFIG_FILENAME, CONFIG_USER_FILENAME])
    LISTEN_IP = CONFIG.get('listen', 'ip')
    if LISTEN_IP == '0.0.0.0': LISTEN_IP = '127.0.0.1'
    LISTEN_GAE = '%s:%d' % (LISTEN_IP, CONFIG.getint('listen', 'gae_port'))
    LISTEN_AUTO = '%s:%d' % (LISTEN_IP, CONFIG.getint('listen', 'auto_port'))
    return LISTEN_GAE, LISTEN_AUTO

def get_proxy_state():
    try:
        AutoConfigURL, reg_type = winreg.QueryValueEx(SETTINGS, 'AutoConfigURL')
        return AutoConfigURL
    except:
        pass
    try:
        ProxyEnable, reg_type = winreg.QueryValueEx(SETTINGS, 'ProxyEnable')
        if ProxyEnable:
            ProxyServer, reg_type = winreg.QueryValueEx(SETTINGS, 'ProxyServer')
            return ProxyServer
    except:
        pass
    return '无'

CONFIG_FILENAME = os.path.join(config_dir, 'Config.ini')
CONFIG_USER_FILENAME = re.sub(r'\.ini$', '.user.ini', CONFIG_FILENAME)
CONFIG_AUTO_FILENAME = os.path.join(config_dir, 'ActionFilter.ini')
SET_PATH = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
SETTINGS = winreg.OpenKey(winreg.HKEY_CURRENT_USER, SET_PATH, 0, winreg.KEY_ALL_ACCESS)
proxy_state = get_proxy_state()
GotoX_app = None
hwnd = ctypes.windll.kernel32.GetConsoleWindow()

def start_GotoX():
    global GotoX_app, LISTEN_GAE, LISTEN_AUTO
    LISTEN_GAE, LISTEN_AUTO = get_listen_addr()
    GotoX_app = Popen((py_exe, app_start))

def stop_GotoX():
    if GotoX_app is None:
        logging.warning('GotoX 进程还未开始。')
    else:
        retcode = GotoX_app.poll()
        if retcode is None:
            GotoX_app.terminate()
        else:
            logging.warning('GotoX 进程已经结束，code：%s。', retcode)

def on_main_setting(systray):
    Popen(CONFIG_FILENAME, shell=True)

def on_user_setting(systray):
    Popen(CONFIG_USER_FILENAME, shell=True)

def on_auto_setting(systray):
    Popen(CONFIG_AUTO_FILENAME, shell=True)

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
    global running
    running = False

def on_disable_proxy(systray):
    disable_proxy()

def on_enable_auto_proxy(systray):
    set_proxy(LISTEN_AUTO)

def on_enable_gae_proxy(systray):
    set_proxy(LISTEN_GAE)

def on_left_click(systray):
    build_menu(systray)
    systray._show_menu()

def on_right_click(systray):
    visible = ctypes.windll.user32.IsWindowVisible(hwnd)
    ctypes.windll.user32.ShowWindow(hwnd, visible^1)

sub_menu1 = (('打开默认配置', on_main_setting), #双击打开第一个有效命令
             ('打开用户配置', on_user_setting),
             ('打开自动规则配置', on_auto_setting))

def build_menu(systray):
    proxy_state = get_proxy_state()
    disable_item_state = proxy_state == '无' and fixed_fState or 0
    auto_item_state = proxy_state == LISTEN_AUTO and fixed_fState or 0
    gae_item_state = proxy_state == LISTEN_GAE and fixed_fState or 0
    sub_menu2 = (('当前代理：', 'pass', MFS_DISABLED),
                 (proxy_state, 'pass', MFS_DISABLED),
                 (None, '-'),
                 ('禁用代理', on_disable_proxy, disable_item_state, MFT_RADIOCHECK),
                 ('自动代理', on_enable_auto_proxy, auto_item_state, MFT_RADIOCHECK),
                 ('GAE 代理', on_enable_gae_proxy, gae_item_state, MFT_RADIOCHECK))
    visible = ctypes.windll.user32.IsWindowVisible(hwnd)
    show_item_state = visible and fixed_fState or 0
    hide_item_state = not visible and fixed_fState or 0
    main_menu = (('GotoX 设置', sub_menu1, icon_gotox, MFS_DEFAULT),
                 (None, '-'),
                 ('显示窗口', on_show, show_item_state, MFT_RADIOCHECK),
                 ('隐藏窗口', on_hide, hide_item_state, MFT_RADIOCHECK),
                 ('设置系统（IE）代理', sub_menu2),
                 ('重启 GotoX', on_refresh),
                 (None, '-'),
                 ('关于', on_about))
    systray.update(menu=main_menu)

MFS_CHECKED = win32_adapter.MFS_CHECKED
MFS_DISABLED = win32_adapter.MFS_DISABLED
MFS_DEFAULT = win32_adapter.MFS_DEFAULT
MFT_RADIOCHECK = win32_adapter.MFT_RADIOCHECK
fixed_fState = MFS_CHECKED | MFS_DISABLED

quit_item = '退出', on_quit
systray_GotoX = SysTrayIcon(icon_gotox, 'GotoX', None, quit_item,
                            left_click=on_left_click,
                            right_click=on_right_click)
systray_GotoX.start()
start_GotoX()
#LISTEN_GAE, LISTEN_AUTO = get_listen_addr()
sleep(1)
systray_GotoX.show_balloon('\nGotoX 已经启动。        \n\n'
                           '左键单击：打开菜单\n\n'
                           '左键双击：打开配置\n\n'
                           '右键单击：隐藏窗口\n\n'
                           '当前系统代理设置为：\n'
                           '    %s' % proxy_state,
                           'GotoX 通知', 4 | 32, 15)

running = True
while running:
    now_proxy_state = get_proxy_state()
    if proxy_state != now_proxy_state:
        text = '设置由：\n      %s\n变更为：\n      %s' % (proxy_state, now_proxy_state)
        proxy_state = now_proxy_state
        systray_GotoX.show_balloon(text, '系统代理改变', 2 | 32, 15)
    sleep(5)
