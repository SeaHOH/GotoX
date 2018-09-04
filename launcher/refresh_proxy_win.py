# coding:utf-8
# 改变注册表设置后
# HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
# 调用此脚本刷新代理状态
# 同一进程多次刷新可能会失败，保险起见使用进程方式调用

from ctypes import windll

# INTERNET_OPTION_REFRESH = 37
# INTERNET_OPTION_SETTINGS_CHANGED = 39
# INTERNET_OPTION_PROXY_SETTINGS_CHANGED = 95
windll.wininet.InternetSetOptionW(0, 95, 0, 0)
