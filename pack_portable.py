#!/usr/bin/env python
# This script is used to package python's portable version.
# It's only targeted at Windows platform.

import os
import re
import sys
import json
import shutil
import hashlib
import pycurl
from io import BytesIO
from configparser import ConfigParser
from distutils.version import StrictVersion
from distutils.versionpredicate import VersionPredicate


usercustomize = b'''\
import os
import sys
import _imp
import builtins

def pkgdll_get_path(loader, path, name):
    dll_name = name.split('.')[-1] + dll_tag_ext
    dll_path = os.path.join(os.path.dirname(path), dll_name)
    if 'zipimporter object' in str(loader):
        path = os.path.join(eggs_cache,
                            os.path.split(loader.archive)[1] + '-tmp',
                            loader.prefix,
                            dll_name)
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'wb') as f:
                f.write(loader.get_data(dll_path))
    else:
        path = dll_path
    return path

def set_path():
    global eggs_cache
    os.environ.pop('PYTHONPATH', None)
    os.environ.pop('PYTHONHOME', None)
    py_dir = os.path.dirname(sys.executable)
    sp_dir = os.path.join(py_dir, 'site-packages')
    del sys.path[1:]
    sys.path.append(os.path.join(py_dir, 'DLLs'))
    if os.path.exists(sp_dir):
        import glob
        sys.path.extend(glob.glob(os.path.join(sp_dir, '*.egg')))
        sys.path.append(sp_dir)
    sys.path.append(os.getcwd())
    eggs_cache = os.path.join(py_dir, 'Eggs-Cache')

def main():
    global dll_tag_ext
    for dll_ext in _imp.extension_suffixes():
        if dll_ext[:3] == '.cp':
            dll_tag_ext = dll_ext
            break
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

useless_exes = '''\
pythonw.exe
vcruntime140.dll
_msi.pyd
_distutils_findvs.pyd
winsound.pyd
'''.split()

params_7z = {
    '7z': '7za',
    'to_null': '1>/dev/null'
}
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
ARB = re.compile(b'Accept-Ranges:\s?bytes').search

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
        c.setopt(c.RANGE, '%d-' % start)
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
    print('start download %r to %r.' % (url, filepath))

    f = file(filepath, sum)
    ok = False
    retry = 0
    max_retry = 10
    while not ok and retry <= max_retry:
        try:
            ok = _download(url, f)
        except Exception as e:
            print('download %r error: %s.' % (url, e), file=sys.stderr)
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
        print('download %r to %r over.' % (url, filepath))
        return res
    else:
        print('download %r fail: %s.' % (url, err), file=sys.stderr)
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
dll_tag = 'cp%s-%s' % (py_ver, py_arch)

if not os.path.exists('python/python.exe'):
    filepath = download(py_url, sum=py_sum)
    cmd = '{7z} e {file} -opython {to_null}'.format(file=filepath, **params_7z)
    os.system(cmd)
    os.remove(filepath)

if not os.path.exists('python'):
    os.mkdir('python')
os.chdir('python')
for filename in useless_exes:
    try:
        os.remove(filename)
    except:
        pass
is_dll = re.compile('^(?!python\d\d).+\.(dll|pyd|cat)$').match
if not os.path.exists('DLLs'):
    os.mkdir('DLLs')
for filename in os.listdir():
    if filename.endswith(('txt', 'cfg', '_pth')):
        os.remove(filename)
    elif is_dll(filename):
        os.rename(filename, os.path.join('DLLs', filename))
    elif filename.endswith('zip'):
        cmd = '{7z} x {file} -opythonzip {to_null}'.format(file=filename, **params_7z)
        os.system(cmd)
        os.remove(filename)
        with open('pythonzip/usercustomize.py', 'wb') as f:
            f.write(usercustomize)
        cmd = '{7z} a -tzip {file} ./pythonzip/* -mx=9 -mfb=258 -mtc=off {to_null}'.format(file=filename, **params_7z)
        os.system(cmd)
        shutil.rmtree('pythonzip', True)


# python packages
pypi_api = 'https://pypi.org/pypi/{}/json'.format
pypi_ver_api = 'https://pypi.org/pypi/{}/{}/json'.format
if not os.path.exists('site-packages'):
    os.mkdir('site-packages')
os.chdir('site-packages')

stable_sp = True
NOTSTABLE = re.compile('[a-z]').search
StrictVersion.version_re = re.compile(r'^(\d+) \. (\d+) (\. (\d+))? (\.?[a-z]+(\d+))?$',
                            re.VERBOSE | re.ASCII)

def extract(project, version):
    data = download(pypi_api(project), JSON)
    if version:
        version = VersionPredicate('%s(%s)' % (project, version))
        if version.pred:
            releases = sorted(data['releases'].keys(),
                              key=lambda r: StrictVersion(r), reverse=True)
            for release in releases:
                if stable_sp and NOTSTABLE(release):
                    continue
                if version.satisfied_by(release):
                    dists = data['releases'][release]
                    break
    else:
        dists = data['urls']
    dist_type = None
    for dist in dists:
        if ((py_ver in dist['python_version'].replace('.', '') and
                py_arch in dist['filename']) or 
                'py3-none-any' in dist['filename']) and \
                dist['packagetype'] in ('bdist_wheel', 'bdist_egg'):
            dist_type = dist['packagetype']
            break
    if not dist_type:
        for dist in dists:
            if dist['python_version'] == 'source':
                dist_type = dist['packagetype']
                break
    url =dist['url']
    filename = fn = dist['filename']
    while True:
        fn = fn.rpartition('.')[0]
        if not fn.endswith('.tar'):
            fn += '.egg'
            if os.path.exists(fn):
                return
            else:
                break
    sum = '|'.join(('sha256', dist['digests']['sha256']))
    filepath = download(url, filename, sum)
    if filepath.endswith('tar.gz'):
        cmd = '{7z} e {file} {to_null}'.format(file=filepath, **params_7z)
        os.system(cmd)
        os.remove(filepath)
        filepath = filepath[:-3]
    if filepath.endswith(('whl', 'egg', 'tar', 'zip')):
        cmd = '{7z} x {file} {to_null}'.format(file=filepath, **params_7z)
        os.system(cmd)
        os.remove(filepath)
    if filepath.endswith('tar'):
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
                if filename.startswith('setup.') or \
                        filename.endswith('.sh'):
                    continue
                old = os.path.join(dirpath, filename)
                new = os.path.join(dirpath, updir, filename)
                os.rename(old, new)
        shutil.rmtree(filepath[:-4])
    return filepath.rpartition('.')[0]

def package(name):
    if not name:
        return
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
                if dll_tag not in filename:
                    newname = '%s%s.pyd' % (filename[:-3], dll_tag)
                    os.rename(os.path.join(dirpath, filename),
                              os.path.join(dirpath, newname))
                    print('Warning: filename %r does not match the dll_tag %r, '
                          'rename it as %r.' % (filename, dll_tag, newname))
                    filename =  newname
                filename = filename.split(dll_tag)[0] + 'py'
                filepath = os.path.join(dirpath, filename)
                with open(filepath, 'wb') as f:
                    f.write(dllpy)
    cmd = '{7z} a -tzip {file}.egg * -x!*.egg -mx=9 -mfb=258 -mtc=off {to_null}'.format(file=name, **params_7z)
    os.system(cmd)
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

