# coding:utf-8

import os


def get_dirname(path):
    return os.path.dirname(os.path.realpath(path))

def get_realpath(path, dir='.'):
    if path[:1] == '~':
        path = os.path.expanduser(path)
    if not os.path.isabs(path):
        path = os.path.join(dir, path)
    return os.path.realpath(path)

app_root = os.path.dirname(os.path.dirname(get_dirname(__file__)))
cert_dir = os.path.join(app_root, 'cert')
config_dir = os.path.join(app_root, 'config')
data_dir = os.path.join(app_root, 'data')
launcher_dir = os.path.join(app_root, 'launcher')
log_dir = os.path.join(app_root, 'log')
py_dir = os.path.join(app_root, 'python')
web_dir = os.path.join(app_root, 'web')
icon_gotox = os.path.join(app_root, 'gotox.ico')
packages = os.path.join(py_dir, 'site-packages')
