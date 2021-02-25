#!/usr/bin/env python
# This script is used to package python's portable version.
# It's only targeted at Windows platform.

import os
import re
import sys
import json
import zlib
import shutil
import hashlib
import pycurl
import base64
from io import BytesIO
from configparser import ConfigParser
from distutils.version import StrictVersion
from distutils.versionpredicate import VersionPredicate


sitecustomize = b'''\
import os
import sys
import glob
import _imp
import builtins

py_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

def pkgdll_get_path(loader, path, name):
    for dll_ext in _imp.extension_suffixes():
        dll_name = name.split('.')[-1] + dll_ext
        if hasattr(loader, 'archive'):
            dll_path = loader.prefix + dll_name
            if dll_path not in loader._files:
                continue
            path = os.path.join(eggs_cache,
                                os.path.basename(loader.archive) + '-tmp',
                                dll_path)
            if not os.path.exists(path):
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, 'wb') as f:
                    f.write(loader.get_data(dll_path))
        else:
            dll_path = os.path.join(os.path.dirname(path), dll_name)
            if not os.path.exists(dll_path):
                continue
            path = dll_path
        return os.path.abspath(path)

def set_prefix():
    for name in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONUSERBASE'):
        os.environ.pop(name, None)
    sys.prefix = py_dir
    sys.base_prefix = py_dir
    sys.exec_prefix = py_dir
    sys.base_exec_prefix = py_dir
    import site
    site.PREFIXES[:] = [py_dir]
    site.USER_SITE = None
    site.USER_BASE = None

def set_path():
    global eggs_cache
    sys.executable = sys._base_executable = os.path.join(py_dir, 'python.exe')
    if 'VIRTUAL_ENV' in os.environ:
        home = os.environ['PYTHONHOME']
        prompt = os.environ.get('VIRTUAL_PROMPT')
        dlls = os.path.join(home, 'DLLs')
        for i, path in enumerate(sys.path):
            if path == dlls:
                sys.path[i] = os.path.join(py_dir, 'DLLs')
            elif path.endswith('site-packages'):
                if os.path.exists(path):
                    sys.path[i + 1:i + 1] = glob.glob(os.path.join(path, '*.egg'))
                    break
        eggs_cache = os.path.join(home, 'Eggs-Cache')
        if prompt:
            sys.ps1 = prompt + ' >>> '
            sys.ps2 = ' ' * len(prompt) + ' ... '
    else:
        if not (py_dir == sys.prefix == sys.base_prefix == sys.exec_prefix == sys.base_exec_prefix):
            set_prefix()
        sp_dir = os.path.join(py_dir, 'site-packages')
        sys.path[:] = [os.path.join(py_dir, 'python%d%d.zip' % sys.version_info[:2])]
        sys.path.append(os.path.join(py_dir, 'DLLs'))
        sys.path.append(py_dir)
        if os.path.exists(sp_dir):
            sys.path.append(sp_dir)
            sys.path.extend(glob.glob(os.path.join(sp_dir, '*.egg')))
        eggs_cache = os.path.join(py_dir, 'Eggs-Cache')

def main():
    builtins.pkgdll_get_path = pkgdll_get_path
    set_path()

main()
'''

dllpy = b'''\
def __bootstrap__():
    global __bootstrap__, __loader__, __file__
    import imp
    __file__ = pkgdll_get_path(__loader__, __file__, __name__)
    __loader__ = None; del __bootstrap__, __loader__
    imp.load_dynamic(__name__, __file__)

__bootstrap__()
'''



simplewinvenv = b'''\
"""
A simple virtual environment script for Python.
Additional files must be copied manually, if need.
It's only targeted at Windows platform.
"""

import os
import sys

help = """\
Creates a simple virtual environment for Python

Use:  python -m svenv venvdir [prompt]

  venvdir       A directory to create the environment in.
  prompt        Provides an alternative prompt prefix for this environment.
                If not set, will use the directory name.

"""

activate_bat = """\
@echo off
set VIRTUAL_ENV=%~dp0
set VIRTUAL_PROMPT={prompt}
set PYTHONNOUSERSITE=
set PYTHONHOME=%VIRTUAL_ENV%
set _PYTHON_PROJECT_BASE=%VIRTUAL_ENV%
set PATH=%VIRTUAL_ENV%Scripts;{exe_dir};%VIRTUAL_ENV%;%PATH%
if not defined PROMPT set PROMPT=$P$G
set PROMPT=({prompt}) %PROMPT%
echo on
"""

launcher_bat = """\
@if not defined VIRTUAL_ENV call "%~dp0activate.bat"
@"{exe}" %*
"""

console_bat = """\
@if not defined VIRTUAL_ENV (
    call "%~dp0activate.bat"
    cmd
)
"""

def create(env_dir, prompt):
    lib_dir = os.path.join(env_dir, 'Lib')
    sp_dir = os.path.join(env_dir, lib_dir, 'site-packages')
    exe_dir = os.path.dirname(sys.executable)
    os.makedirs(sp_dir, exist_ok=True)
    with open(os.path.join(env_dir, 'activate.bat'), 'w') as f:
        f.write(activate_bat.format(prompt=prompt, exe_dir=exe_dir))
    with open(os.path.join(env_dir, 'python.bat'), 'w') as f:
        f.write(launcher_bat.format(exe=sys.executable))
    with open(os.path.join(env_dir, 'console.bat'), 'w') as f:
        f.write(console_bat)
    print('New virtual environment created at %r, prompt is %r.' % (env_dir, prompt))

def main():
    try:
        env_dir = sys.argv[1]
    except IndexError:
        print(help)
        return
    if not os.path.isabs(env_dir) or os.path.isfile(env_dir):
        raise ValueError("The environment path must be absolute, and can't be a exists file.")
    try:
        prompt = sys.argv[2]
    except IndexError:
        prompt = os.path.basename(env_dir.rstrip(os.path.sep))
    create(env_dir, prompt)

if __name__ == '__main__':
    rc = 1
    try:
        main()
        rc = 0
    except Exception as e:
        print('Error: %s' % e, file=sys.stderr)
    sys.exit(rc)
'''

dllsb64z = {
    'win32': (
        ('api-ms-win-core-path-l1-1-0.dll.w7', b'''
7VZLb9xUFD7zKDRNEyZNg1ggcKRWahYe5SVINpBkJqEjJp3ROKQIJFqPx8nc1mMb20kmrIJ4KVKFBiGk
sqISCIkNYtFFhVSptFWLaPIH2MCiq7KgrJEI3722M56H0i7YgLij7z7OPee73z22753FNxqUIKIksLdH
dI38MkOPLjeA/ue/76erPbvD12L53eGlKnMl27FWHbUmaappWp5U1iVnzZSYKWULilSzKnq6r+/IiYDj
I2X41q3xQiPEc7sfNG6K9t3GD6L9MBi/J9oS06rcL9RQnCfKx+L0S2OoFNp+pfhwb6zX31QyIjgFSEGP
9+NET2D3IUQZ9WOu9BEsM4fEIBUEp5o0V1D9FI9wg/dh4oBkwf9Z+udK2tPrHtoLiUBQ+159SefTjuto
FGiTAp/DrX4zj/e4/y//0RJ+O/x1nuLA+zSVPDimpGSVe3883BxZv3t66/b0F1++/tlADPbZYk5eVOSz
zJQzlqPLRdWryvkxeUweTduVcleuiRs3U7w6yqvjvEry6jDt7Ozw+c+XfH1fDRDxNZ4O8CN0SrDVgW30
3wcuB+12qmkLW46Pg/GnEd/LAbYj/RC3wf0z8BuwBwwdIxoBXgReAd4E3ga2gE+Ar4GrwD3gPvAnMDBI
dAqYAl4F3hrku4kh3wl8jodw9jyJT7KHjlAvHaU+6qen8EkP0DEapOM0RKrN5JorbyCnGs+pzXNq+Dmt
GAbxHM8ahqVlVNMymaYa7B09YrVqZWb6hoxWna1U5lTtomuobrWbbb4esc7XPd10mWXu22xbNyuto2ZE
h4A2W8SzVVQwbM4vMLNz8ZxbsiwvHJX0mrWud+ylzdyk9Cc6SH3zAjN0xda1ptVUa53OykVmRzUonsPs
oqOvsHqLacna98q5r53JQMW/ocTEVfIMXud2e8y/GjvsPTgnTqN3HnfLpS7336XEJOplUugc6nkqoZej
Ap3BOId6AX1erid//4vz8ZuYZrZOhu3LAU8Sv3gb94M4j1DII4cYmbQKNkYG6WA2aYUs+NwRPqM0CUyL
dk5c8XmcIDHKwKdGNqnw34QaFSNdcC+CSQOvRS6wgjUk4e3Am9cqLAw9k/j+U+AK184Crohl8G164WzE
mEGvLti47jUqo5eFmjzmHRqJ8CwDDpia8S9QmiaAafRG8UvTGHoTOLMnwXKKNkQWyoheQ+w5RHvYD/ea
gPcUjaMni5hxWEYCzl6syfPlifVM7MyIZEIVml2h2Q0U87IF3hhU68g6j+C5sZFDvutVqhL/b/INVD1+
HtOYmQWTgbbJ4oqRLhQ4tI66Ak+il4TuQuDJAt1h7sxH6r9AJxFfFMoqsGqYO/j5fwslZ8VKFVg2YOeW
Avj1/X3wd5A/2U2xlg42XuZwnrev1f50D3q2vGTF17aMdZwubznRCfHHbkkoMcFrtLyhhO/0u643+t8=
'''),
    ),
    'win_amd64': (
        ('api-ms-win-core-path-l1-1-0.dll.w7', b'''
7VZNb9xEGH73o0AaErYNRUVC1EEttAev8iVIhQTZ7CZixWZ3tQ6p1EvjtSfZab22ZTtNyikVUC49rBBC
QuqRCwcQh0pEIKTSSByq5gYnfgBqOZRrL5Rnxnb2U2kPcAAxq2c+Xr/vM8+89szs0vkWpYgoDTx6RLRD
YZmjx5dbwOiJ70bp5tDe+E6itDe+3OC+4nrOuqc3FUO3bSdQ6kzxNmyF20qhoilNx2TZkZHDJyOOj7Xx
3d2pSivGy3sftW7L9mrrR9lei8YfyLbGjYbwizVUF4jMa0m69/BYLbb9Qa8ow8nhcFHpDsEZWW8n4n6S
6CmsPoYsE2HMiRsEy2pinyDTTdIeh90WqjvJjrkU6EgdkDz4v0R/X8kGbCtAez4VCepdeyhpNev5nkGR
NiXyeabbb+7JXv//5T9S4r0jPt9ZAXw/s+mDY2paQbu7PLZ9sfxq6atfyp/8duPznNhXuWpRXdLUc9xW
847H1KoeNNTSpDqpTmRdsz6Qa/rW7t24iPHDb0M9nx4hEpwvRNiBrgxsDeDDzD+Dm+C+A/wKPAAOHSV6
EXgNeAN4F9ABF7gKfAZ8AXwP/Az8DiTGiI4Dp4E3gfKYWE0C+U1hux3CWfM0ttwQHaZhepZGaJSew5Y9
QkdpjJ6nY6S7XG366iZyaIgcuiKHVphD07JI5DRnWY6R123H5oZu8fdZh9Vp1rkdGvJGI2ea87pxybd0
vzHItrDVYV3YCpjtc8fet7kus83uUTuiT0CPrcOzW1Q0bD9f5Hb/5EW/5jhBPKqxpnOZ9a2lx9ymDB/0
kYbmRW4xzWVG22rrzX5n7RJ3OzVogcfdqsfW+FaXadnZ9yr675XzUPFvLAl5dRzHHdlrT4RXY599COfE
O+it4i65PuC+u56aQb1CGl1AvUA19IpUoTLGRdSL6IvyQ/rBn4JP3MQ0t30qbt+OeNL4JXu47ydFhEYB
ecTJpnWwcbKIgdmmNXLg85P0maAZ4Kxs5+UVX8KJkqA8fJrkkg7/K1CjY8Qk9xKYDPA65ANrmEOR3h68
Ra3DwtGzSaw/A6547gLgy1gO37YXzkaMOfQyySZ0b1AdvQLUlPDcozMdPCuAB6Z2/OuUpWngLHoT+GVp
Er1pnNkzYDlNmzILdURvIPYCogOsR3hNw3uWptBTZcwULGcizmHMKfIVyPlsrMzqyIQuNftSsx8pln+i
wJuAaoasiwiRGxc5FKtepwaJ/yJfQtWT5zGLJzkwWWjbLL4cManAo8uoTXgSvSV1VyJPHumOc2c/Vv9F
OoX4qlRmwmrg2cHv/2soOSdnMmHZhF1YKuBn++sQ36B4s1fkXAxsoszjfO+dq/ftHvRuRSnI3baCebwB
XznRSflHblkqscFrdX2hhH36zcAb/S8='''),
    )
}

useless_exes = '''\
pythonw.exe
vcruntime140.dll
vcruntime140_1.dll
_msi.pyd
_distutils_findvs.pyd
winsound.pyd
'''.split()

_7z = '7za'
to_null = '1>/dev/null'
ca1 = 'cert/CA.crt'
ca2 = 'cert/cacerts/mozilla.pem'
if os.path.exists(ca1):
    ca = os.path.realpath('ca.pem')
    if not os.path.exists(ca):
        with open(ca, 'wb') as f:
            with open(ca1, 'rb') as f1:
                f.write(f1.read())
            with open(ca2, 'rb') as f2:
                f.write(f2.read())
else:
    ca = os.path.realpath(ca2)

STRING = b'STRING'
BYTES = b'BYTES'
JSON = b'JSON'
ARB = re.compile(b'Accept-Ranges:\s?bytes', re.I).search

def _download(url, f):
    f.reset_headers()
    start = f.tell()
    c = pycurl.Curl()
    c.setopt(c.CAINFO, ca)
    c.setopt(c.SSL_VERIFYHOST, 2)
    c.setopt(c.BUFFERSIZE, 32768)
    c.setopt(c.TIMEOUT, 60)
    c.setopt(c.FOLLOWLOCATION, 1)
    c.setopt(c.MAXREDIRS, 3)
    c.setopt(c.URL, url)
    c.setopt(c.WRITEFUNCTION, f.write)
    c.setopt(c.HEADERFUNCTION, f.header_cb)
    if start:
        c.setopt(c.RANGE, f'{start:d}-')
    try:
        c.perform()
        ok = c.getinfo(c.RESPONSE_CODE) in (200, 206)
    finally:
        c.close()
    return ok

class file:
    def __init__(self, filepath, sum):
        self.f = None
        self.filepath = filepath
        if sum:
            self.algorithm, self.sum = sum.split('|')
        self.new_file()
        self.headers = []

    def new_file(self):
        self.close()
        if self.filepath in (STRING, BYTES, JSON):
            self.f = BytesIO()
        else:
            self.f = open(self.filepath, 'wb')
        if hasattr(self, 'algorithm'):
            self.m = getattr(hashlib, self.algorithm)()
        else:
            self.m = None

    def __getattr__(self, name):
        return getattr(self.f, name)

    def write(self, data):
        if self.accept_ranges is None:
            self.accept_ranges = bool(ARB(b''.join(self.headers)))
            if self.f.tell() and not self.accept_ranges:
                self.new_file()
        self.f.write(data)
        if self.m:
            self.m.update(data)

    def header_cb(self, data):
        self.headers.append(data)

    def reset_headers(self):
        self.headers.clear()
        self.accept_ranges = None

    def close(self):
        if hasattr(self.f, 'close'):
            self.f.close()

    def check_sum(self):
        if self.m:
            return self.m.hexdigest() == self.sum
        else:
            return True

def download(url, filepath=None, sum=None):
    if not filepath:
        name_parts = url.split('/')[2:]
        filepath = name_parts.pop()
        while not filepath and name_parts:
            filepath = name_parts.pop()
    print(f'start download {url!r} to {filepath!r}.')

    f = file(filepath, sum)
    ok = False
    retry = 0
    max_retry = 10
    while not ok and retry <= max_retry:
        try:
            ok = _download(url, f)
        except Exception as e:
            print(f'download {url!r} error: {e}.', file=sys.stderr)
            err = e
        else:
            if not ok and retry == max_retry:
                f.new_file()
        retry += 1

    if ok:
        ok = f.check_sum()
        if ok:
            if filepath is STRING:
                res = f.getvalue().decode()
            elif filepath is BYTES:
                res = f.getvalue()
            elif filepath is JSON:
                res = json.loads(f.getvalue().decode())
            else:
                res = filepath
        else:
            err = 'hash check failed'
    else:
        err = 'response status is wrong'
    f.close()
    if ok:
        print(f'download {url!r} to {filepath!r} over.')
        return res
    else:
        print(f'download {url!r} fail: {err}.', file=sys.stderr)
        sys.exit(-1)


# python embed
ConfigParser.optionxform = lambda s, opt: opt
config = ConfigParser()
config.read('pack_portable.ini')
if len(sys.argv) < 2:
    print('missing version parameter!', file=sys.stderr)
    sys.exit(-1)
py_ver = sys.argv[1]
if py_ver not in config.sections():
    print('version parameter mismatch!', file=sys.stderr)
    sys.exit(-1)
extras = sys.argv[2:]

py_url = config.get(py_ver, 'url')
py_sum = config.get(py_ver, 'sum')
py_ver, py_arch = py_ver.split('-')
py_ver = py_ver.replace('.', '')[:2]
dll_tag = f'cp{py_ver}-{py_arch}'

if not os.path.exists('python/python.exe'):
    filepath = download(py_url, sum=py_sum)
    os.system(f'{_7z} e {filepath} -opython {to_null}')
    os.remove(filepath)

if not os.path.exists('python'):
    os.mkdir('python')
os.chdir('python')
for filename in useless_exes:
    try:
        os.remove(filename)
    except:
        pass
is_dll = re.compile('^(?!python\d).+\.(dll|pyd)$').match
if not os.path.exists('DLLs'):
    os.mkdir('DLLs')
for filename in os.listdir():
    if filename.endswith(('txt', 'cat', 'cfg', '_pth')):
        os.remove(filename)
    elif is_dll(filename):
        os.rename(filename, os.path.join('DLLs', filename))
    elif filename.endswith('zip'):
        os.system(f'{_7z} x {filename} -opythonzip {to_null}')
        os.remove(filename)
        with open('pythonzip/sitecustomize.py', 'wb') as f:
            f.write(sitecustomize)
        with open('pythonzip/svenv.py', 'wb') as f:
            f.write(simplewinvenv)
        os.system(f'{_7z} a -mx=9 -mfb=258 -mtc=off {to_null} {filename} ./pythonzip/*')
        shutil.rmtree('pythonzip', True)
if py_ver >= '39':
    install_dlls = ['''\
for /f "tokens=2 delims=[" %%v in ('ver') do set version=%%v
for /f "tokens=2" %%v in ('echo %version%') do set version=%%v
for /f "delims=]" %%v in ('echo %version%') do set version=%%v
if %version% lss 6.2 ( goto :install )''']
    for filename, _ in dllsb64z[py_arch]:
        install_dlls.append(f'del {filename}')
    install_dlls.append('''
:del_self
  del %0
  goto :EOF

:install''')
    for filename, b64z in dllsb64z[py_arch]:
        with open(filename, 'wb') as f:
            f.write(zlib.decompress(base64.decodebytes(b64z), -15))
        install_dlls.append(f'  rename {filename} {os.path.splitext(filename)[0]}')
    install_dlls.append('  goto :del_self')
    with open('install_dll.bat', 'w', newline='\r\n') as f:
        f.write('\n'.join(install_dlls))


# python packages
pypi_api = 'https://pypi.org/pypi/{}/json'.format
pypi_ver_api = 'https://pypi.org/pypi/{}/{}/json'.format
if not os.path.exists('site-packages'):
    os.mkdir('site-packages')
os.chdir('site-packages')

stable_sp = True
StrictVersion.version_re = re.compile(r'^(\d+)\.(\d+)(\.(\d+))?(?:\.?([a-z]+)(\d+))?$')
is_supported_tags_1 = re.compile(f'(?:cp|py)3(?:[0-{py_ver[1]}])?-(?:cp{py_ver}m?|none)-(?:{py_arch}|any)').search
is_supported_tags_2 = re.compile(f'cp3(?:[2-{py_ver[1]}])-abi3-{py_arch}').search

def extract(project, version):
    data = download(pypi_api(project), JSON)
    if version and version[0] not in '<>!=':
        project_sub, version = f'{version} '.split(' ', 1)
    else:
        project_sub = None
    if version.strip():
        version = f'({version})'
    version = VersionPredicate(f'{project}{version}')
    if version.pred:
        releases = sorted(((StrictVersion(key), key) for key in data['releases']),
                          key=lambda r: r[0], reverse=True)
        for release, key in releases:
            if stable_sp and release.prerelease:
                continue
            if version.satisfied_by(release):
                dists = sorted(data['releases'][key],
                               key=lambda d: d['python_version'], reverse=True)
                break
    else:
        dists = data['urls']
    dist_type = None
    for dist in dists:
        if dist['packagetype'] in ('bdist_wheel', 'bdist_egg') and (
                is_supported_tags_1(dist['filename']) or
                is_supported_tags_2(dist['filename'])):
            dist_type = dist['packagetype']
            break
    if not dist_type:
        for dist in dists:
            if dist['python_version'] == 'source':
                dist_type = dist['packagetype']
                break
    url = dist['url']
    filename = dist['filename']
    if project_sub:
        filename = filename.replace(project, project_sub)
    while True:
        filename = filename.rpartition('.')[0]
        if not filename.endswith('.tar'):
            filename += '.egg'
            if os.path.exists(filename):
                return
            else:
                break
    sum = '|'.join(('sha256', dist['digests']['sha256']))
    filepath = download(url, dist['filename'], sum)
    if filepath.endswith(('tar.gz', 'tar.xz', 'tar.bz2')):
        os.system(f'{_7z} e {filepath} {to_null}')
        os.remove(filepath)
        filepath = filepath.rpartition('.')[0]
    if filepath.endswith(('whl', 'egg', 'tar', 'zip')):
        os.system(f'{_7z} x -y {filepath} {to_null}')
        try:
            os.remove('@PaxHeader')
        except FileNotFoundError:
            pass
        os.remove(filepath)
    if filepath.endswith(('tar', 'zip')):
        # This is source code, may require a complicated installation process.
        # But in most cases, just pack it is okay.
        name = filepath[:-4]
        updir = '..'
        if os.path.exists(os.path.join(name, 'src')):
            name = os.path.join(name, 'src')
            updir = os.path.join('..', '..')
        for dirpath, dirnames, filenames in os.walk(name):
            for dirname in dirnames:
                old = os.path.join(dirpath, dirname)
                new = os.path.join(dirpath, updir, dirname)
                os.rename(old, new)
            for filename in filenames:
                if filename.startswith(('setup.', 'fuzz.')) or \
                        not filename.endswith('.py'):
                    continue
                old = os.path.join(dirpath, filename)
                new = os.path.join(dirpath, updir, filename)
                os.rename(old, new)
        shutil.rmtree(filepath[:-4])
    name = filepath.rpartition('.')[0]
    if project_sub:
        name = name.replace(project, project_sub)
        for dirpath, dirnames, filenames in os.walk('.'):
            for dirname in dirnames:
                if dirname != project_sub:
                    filepath = os.path.join(dirpath, dirname)
                    shutil.rmtree(filepath, True)
            for filename in filenames:
                if not filename.endswith('.egg'):
                    filepath = os.path.join(dirpath, filename)
                    os.remove(filepath)
            break
    return name

def package(name):
    if not name:
        return
    abi3 = 'abi3' in name
    for dirpath, dirnames, filenames in os.walk('.'):
        for dirname in dirnames:
            if dirname in ('test', 'tests', 'testing'):
                filepath = os.path.join(dirpath, dirname)
                shutil.rmtree(filepath, True)
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if filename.endswith(('pyx', 'pxd', 'html', '.c', '.h', 'ffi_build.py')) or \
                    (filename != '__init__.py' and os.path.getsize(filepath) == 0):
                os.remove(filepath)
            elif filename.endswith('pyd'):
                if abi3:
                    filename = filename[:-3]
                else:
                    if dll_tag not in filename:
                        newname = f'{filename[:-3]}{dll_tag}.pyd'
                        os.rename(os.path.join(dirpath, filename),
                                  os.path.join(dirpath, newname))
                        print(f'Warning: filename {filename!r} does not match the dll_tag {dll_tag!r}, '
                              f'rename it as {newname!r}.')
                        filename =  newname
                    filename = filename.split(dll_tag)[0]
                filename += 'py'
                filepath = os.path.join(dirpath, filename)
                with open(filepath, 'wb') as f:
                    f.write(dllpy)
    os.system(f'{_7z} a -tzip -x!*.egg -mx=9 -mfb=258 -mtc=off {to_null} {name}.egg *')
    for dirpath, dirnames, filenames in os.walk('.'):
        for dirname in dirnames:
            filepath = os.path.join(dirpath, dirname)
            shutil.rmtree(filepath, True)
        for filename in filenames:
            if not filename.endswith('egg'):
                filepath = os.path.join(dirpath, filename)
                os.remove(filepath)
        break

for project, version in config.items('site-packages'):
    package(extract(project, version))

for project in extras:
    version = config.get('site-packages', project, fallback='')
    package(extract(project, version))

