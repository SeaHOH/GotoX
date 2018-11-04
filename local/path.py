# coding:utf-8

import os

__file__ = os.path.abspath(__file__)
if os.path.islink(__file__):
    __file__ = getattr(os, 'readlink', lambda x: x)(__file__)

app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cert_dir = os.path.join(app_root, 'cert')
config_dir = os.path.join(app_root, 'config')
data_dir = os.path.join(app_root, 'data')
launcher_dir = os.path.join(app_root, 'launcher')
py_dir = os.path.join(app_root, 'python')
web_dir = os.path.join(app_root, 'web')
icon_gotox = os.path.join(app_root, 'gotox.ico')
packages = os.path.join(py_dir, 'site-packages')
