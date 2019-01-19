# coding:utf-8

import os


def get_dirname(path):
    path = os.path.abspath(path)
    if os.path.islink(path):
        path = getattr(os, 'readlink', lambda x: x)(path)
    return os.path.dirname(path)

app_root = os.path.dirname(os.path.dirname(get_dirname(__file__)))
cert_dir = os.path.join(app_root, 'cert')
config_dir = os.path.join(app_root, 'config')
data_dir = os.path.join(app_root, 'data')
launcher_dir = os.path.join(app_root, 'launcher')
py_dir = os.path.join(app_root, 'python')
web_dir = os.path.join(app_root, 'web')
icon_gotox = os.path.join(app_root, 'gotox.ico')
packages = os.path.join(py_dir, 'site-packages')
