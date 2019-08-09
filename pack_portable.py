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


usercustomize = b'''\
import os
import sys
import builtins

def pkgdll_get_path(loader, path, name):
    dll_name = '%s.%s.pyd' % (name.split('.')[-1], dll_tag)
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
    global dll_tag
    impl_version = 'cp%d%d' % sys.version_info[:2]
    arch = 'win_amd64' if 'amd64' in sys.version.lower() else 'win32'
    dll_tag = '%s-%s' % (impl_version, arch)
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

def _download(url, filepath=None, sum=None):
    if not filepath:
        name_parts = url.split('/')[2:]
        filepath = name_parts.pop()
        while not filepath and name_parts:
            filepath = name_parts.pop()
    print('start download %r to %r.' % (url, filepath))
    c = pycurl.Curl()
    if filepath in (STRING, BYTES, JSON):
        f = BytesIO()
        sum = None
    else:
        f = open(filepath, 'wb')
    c.setopt(c.CAINFO, ca)
    c.setopt(pycurl.SSL_VERIFYHOST, 2)
    c.setopt(pycurl.BUFFERSIZE, 32768)
    c.setopt(pycurl.TIMEOUT, 60)
    c.setopt(c.URL, url)
    c.setopt(c.WRITEDATA, f)
    c.perform()
    ok = c.getinfo(c.RESPONSE_CODE) == 200
    c.close()
    if filepath not in (STRING, BYTES, JSON):
        f.close()
    print('download %r to %r over.' % (url, filepath))
    if sum:
        algorithm, sum = sum.split('|')
        m = getattr(hashlib, algorithm)()
        with open(filepath, 'rb') as f:
            data = f.read(1024)
            while data:
                m.update(data)
                data = f.read(1024)
        ok = m.hexdigest() == sum
    if filepath is STRING:
        res = f.getvalue().decode()
    elif filepath is BYTES:
        res = f.getvalue()
    elif filepath is JSON:
        res = json.loads(f.getvalue().decode())
    else:
        res = filepath
    return ok, res

def download(url, filepath=None, sum=None):
    ok = False
    retry = -1
    while not ok and retry <= 3:
        ok, res = _download(url, filepath, sum)
        retry += 1
    if ok:
        return res
    else:
        print('download %r fail!' % url, file=sys.stderr)
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

py_url = config.get(py_ver, 'url')
py_sum = config.get(py_ver, 'sum')
py_ver, py_arch = py_ver.split('-')
py_ver = py_ver.replace('.', '')[:2]
dll_tag = 'cp%s-%s' % (py_ver, py_arch)


filepath = download(py_url, sum=py_sum)
cmd = '{7z} e {file} -opython {to_null}'.format(file=filepath, **params_7z)
os.system(cmd)
os.remove(filepath)

if not os.path.exists('python'):
    os.mkdir('python')
os.chdir('python')
for filename in ('pythonw.exe', 'vcruntime140.dll'):
    os.remove(filename)
dll = re.compile('.+?\D\d?\.(dll|pyd)').match
os.mkdir('DLLs')
for filename in os.listdir():
    if filename.endswith(('txt', '_pth')):
        os.remove(filename)
    elif dll(filename):
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

def extract(project, version=None):
    if version is None:
        data = download(pypi_api(project), JSON)
    else:
        data = download(pypi_ver_api(project, version), JSON)
    dists = data['urls']
    dist_type = None
    for dist in dists:
        if ((py_ver in dist['python_version'].replace('.', '') and py_arch in dist['filename']) or 
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
    filename = dist['filename']
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
                    raise RuntimeError('filename %r does not match the dll_tag %r'
                                       % (dll_tag, filename))
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

for project in config.options('site-packages'):
    version = config.get('site-packages', project)
    if version.startswith('>'):
        version = None
    package(extract(project, version))

