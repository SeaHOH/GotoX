# coding:utf-8
'''CertUtil module, based on mitmproxy'''

import os
import sys
import threading
import glob
import random
import logging
import OpenSSL
from OpenSSL import crypto
from time import time
from datetime import datetime, timedelta
from local.GlobalConfig import GC
from .path import cert_dir
from .util import LRUCache

ca_vendor = 'GotoX'
ca_certfile = os.path.join(cert_dir, 'CA.crt')
ca_keyfile = os.path.join(cert_dir, 'CAkey.pem')
ca_thumbprint = ''
ca_privatekey = None
ca_subject = None
ca_digest = 'sha256'
ca_years = 20
ca_time_b = -3600 * 24
ca_time_a = 3600 * 24 * (365 * ca_years + ca_years // 4) + ca_time_b
sub_keyfile = os.path.join(cert_dir, 'subkey.pem')
sub_certdir = os.path.join(cert_dir, 'certs')
sub_publickey = None
sub_lock = threading.Lock()
sub_serial = 3600 * 24 * 365 * 46
sub_years = 1
sub_time_b = -3600
sub_time_a = 3600 * 24 * (365 * sub_years + sub_years // 4) + sub_time_b
sub_certs = LRUCache(128)

def create_ca():
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 2048)
    ca = crypto.X509()
    ca.set_version(2)
    ca.set_serial_number(0)
    subject = ca.get_subject()
    subject.countryName = 'CN'
    subject.stateOrProvinceName = 'Internet'
    subject.localityName = 'Cernet'
    subject.organizationName = ca_vendor
    subject.organizationalUnitName = '%s Root' % ca_vendor
    subject.commonName = '%s CA' % ca_vendor
    #某些认证机制会检查签署时间与当前时间之差
    ca.gmtime_adj_notBefore(ca_time_b)
    ca.gmtime_adj_notAfter(ca_time_a)
    ca.set_issuer(subject)
    ca.set_pubkey(pkey)
    ca.add_extensions([
        crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE, pathlen:0'),
        crypto.X509Extension(b'extendedKeyUsage', True, b'serverAuth,emailProtection,timeStamping'),
        crypto.X509Extension(b'keyUsage', False, b'keyCertSign, cRLSign'),
        crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=ca)
    ])
    ca.sign(pkey, ca_digest)
    return pkey, ca

def dump_ca():
    pkey, ca = create_ca()
    with open(ca_certfile, 'wb') as fp:
        fp.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))
    with open(ca_keyfile, 'wb') as fp:
        fp.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))
        fp.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))

def dump_subkey():
    global sub_publickey
    sub_key = crypto.PKey()
    sub_key.generate_key(crypto.TYPE_RSA, 2048)
    with open(sub_keyfile, 'wb') as fp:
        fp.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, sub_key))
        fp.write(crypto.dump_publickey(crypto.FILETYPE_PEM, sub_key))
    sub_publickey = sub_key

def create_subcert(certfile, commonname, ip=False):
    cert = crypto.X509()
    cert.set_version(2)
    cert.set_serial_number(int((int(time() - sub_serial) + random.random()) * 100)) #setting the only number
    subject = cert.get_subject()
    subject.countryName = 'CN'
    subject.stateOrProvinceName = 'Internet'
    subject.localityName = 'Cernet'
    subject.organizationalUnitName = '%s Branch' % ca_vendor
    subject.commonName = commonname
    subject.organizationName = commonname
    #某些认证机制会检查签署时间与当前时间之差
    cert.gmtime_adj_notBefore(sub_time_b)
    cert.gmtime_adj_notAfter(sub_time_a)
    cert.set_issuer(ca_subject)
    cert.set_pubkey(sub_publickey)
    if ip:
        sans = 'IP: ' + commonname
    else:
        sans = 'DNS: %s, DNS: *.%s' % (commonname, commonname)
    cert.add_extensions([crypto.X509Extension(b'subjectAltName', True, sans.encode())])
    cert.sign(ca_privatekey, ca_digest)

    with open(certfile, 'wb') as fp:
        fp.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

def get_cert(commonname, ip=False):
    if ip:
        certfilename = commonname.replace(':', '.')
    else:
        certfilename = '.'.join(reversed(commonname.split('.')))
    certfile = os.path.join(sub_certdir, certfilename + '.crt')

    with sub_lock:
        if os.path.exists(certfile):
            try:
                cert = sub_certs[certfile]
            except KeyError:
                with open(certfile, 'rb') as fp:
                    cert = crypto.load_certificate(crypto.FILETYPE_PEM, fp.read())
                sub_certs[certfile] = cert
            # 最早在过期 30 天前更新证书
            if datetime.strptime(cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ') < datetime.utcnow() + timedelta(days=30):
                try:
                    os.remove(certfile)
                except OSError as e:
                    logging.warning('CertUtil.get_cert：旧证书删除失败：%r', e)
                else:
                    del sub_certs[certfile]
                    cert = None
            if cert:
                return certfile

        sub_certs.pop(certfile, None)
        create_subcert(certfile, commonname, ip)
        return certfile

def import_ca(certfile=None):
    if certfile is None:
        certfile = ca_certfile
    try:
        with open(certfile, 'rb') as fp:
            certdata = fp.read().strip()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, certdata)
        commonname = cert.get_subject().CN
        certdata = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
    except Exception as e:
        logging.error('load_certificate(certfile=%r) 失败：%s', certfile, e)
        return -1

    if sys.platform.startswith('win'):
        import ctypes
        import ctypes.wintypes
        class CERT_CONTEXT(ctypes.Structure):
            _fields_ = [
                ('dwCertEncodingType', ctypes.wintypes.DWORD),
                ('pbCertEncoded', ctypes.POINTER(ctypes.wintypes.BYTE)),
                ('cbCertEncoded', ctypes.wintypes.DWORD),
                ('pCertInfo', ctypes.c_void_p),
                ('hCertStore', ctypes.c_void_p),]
        X509_ASN_ENCODING = 0x1
        CERT_STORE_ADD_ALWAYS = 4
        CERT_STORE_PROV_SYSTEM = 10
        CERT_STORE_OPEN_EXISTING_FLAG = 0x4000
        CERT_SYSTEM_STORE_CURRENT_USER = 1 << 16
        CERT_SYSTEM_STORE_LOCAL_MACHINE = 2 << 16
        CERT_FIND_SUBJECT_STR = 8 << 16 | 7
        crypt32 = ctypes.windll.crypt32
        ca_exists = False
        store_handle = None
        pCertCtx = None
        for store in (CERT_SYSTEM_STORE_LOCAL_MACHINE, CERT_SYSTEM_STORE_CURRENT_USER):
            try:
                store_handle = crypt32.CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, None, CERT_STORE_OPEN_EXISTING_FLAG | store, 'root')
                if not store_handle:
                    if store == CERT_SYSTEM_STORE_CURRENT_USER and not ca_exists:
                        logging.warning('导入证书时发生错误：无法打开 Windows 系统证书仓库')
                        return -1
                    else:
                        continue

                pCertCtx = crypt32.CertFindCertificateInStore(store_handle, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, commonname, None)
                while pCertCtx:
                    certCtx = CERT_CONTEXT.from_address(pCertCtx)
                    _certdata = ctypes.string_at(certCtx.pbCertEncoded, certCtx.cbCertEncoded)
                    if _certdata == certdata:
                        ca_exists = True
                        logging.test("证书 %r 已经存在于 Windows 系统证书仓库", commonname)
                    else:
                        _cert =  crypto.load_certificate(crypto.FILETYPE_ASN1, _certdata)
                        if _cert.get_subject().CN == commonname:
                            ret = crypt32.CertDeleteCertificateFromStore(crypt32.CertDuplicateCertificateContext(pCertCtx))
                            if ret == 1:
                                logging.test("已经移除无效的 Windows 证书 %r", commonname)
                            elif ret == 0 and store == CERT_SYSTEM_STORE_LOCAL_MACHINE:
                                logging.warning('无法从 Windows 计算机账户删除无效证书 %r，请用管理员权限重新运行 GotoX，或者手动删除', commonname)
                    pCertCtx = crypt32.CertFindCertificateInStore(store_handle, X509_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, commonname, pCertCtx)

                #只导入到当前用户账户，无需管理员权限
                if store == CERT_SYSTEM_STORE_CURRENT_USER and \
                        not ca_exists and \
                        crypt32.CertAddEncodedCertificateToStore(store_handle, X509_ASN_ENCODING, certdata, len(certdata), CERT_STORE_ADD_ALWAYS, None) == 1:
                    ca_exists = True
                    msg = ('已经将 GotoX CA 证书导入到系统证书仓库，请重启浏览器。\n\n'
                           '如果你使用的是 Firefox，且导入过老旧证书，请在高级设置中手动删除，'
                           '再重启浏览器，设置好代理后访问以下网址即可导入新证书：\n\n'
                           '\thttp://gotox.go')
                    title = 'GotoX 提示'
                    ctypes.windll.user32.MessageBoxW(None, msg, title, 48)
            except Exception as e:
                logging.warning('检查和导入证书时发生错误：%r\n'
                                '如果没有导入过证书，请手动操作，否则请忽视这条警告。', e)
                if isinstance(e, OSError):
                    store_handle = None
            finally:
                if pCertCtx:
                    crypt32.CertFreeCertificateContext(pCertCtx)
                    pCertCtx = None
                if store_handle:
                    crypt32.CertCloseStore(store_handle, 0)
                    store_handle = None
        return 0 if ca_exists else -1

    #放弃其它系统
    return 0

    if sys.platform == 'darwin':
        return os.system(('security find-certificate -a -c "%s" | grep "%s" >/dev/null || security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" "%s"' % (commonname, commonname, certfile.decode('utf-8'))).encode('utf-8'))

    if sys.platform.startswith('linux'):
        import platform
        platform_distname = platform.dist()[0]
        if platform_distname == 'Ubuntu':
            pemfile = "/etc/ssl/certs/%s.pem" % commonname
            new_certfile = "/usr/local/share/ca-certificates/%s.crt" % commonname
            if not os.path.exists(pemfile):
                return os.system('cp "%s" "%s" && update-ca-certificates' % (certfile, new_certfile))
        elif any(os.path.isfile('%s/certutil' % x) for x in os.environ['PATH'].split(os.pathsep)):
            return os.system('certutil -L -d sql:$HOME/.pki/nssdb | grep "%s" || certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "%s" -i "%s"' % (commonname, commonname, certfile))
        else:
            logging.warning('please install *libnss3-tools* package to import GotoX root ca')
    return 0

def verify_certificate(ca, cert):
    store = crypto.X509Store()
    store.add_cert(ca)
    try:
        crypto.X509StoreContext(store, cert).verify_certificate()
    except:
        return False
    return True

def check_ca():
    #检查文件夹
    for dir in (cert_dir, sub_certdir):
        if os.path.exists(dir):
            if not os.path.isdir(dir):
                os.remove(dir)
                os.mkdir(dir)
        else:
            os.mkdir(dir)
    #检查 CA 证书
    if not os.path.exists(ca_keyfile):
        logging.error('CAkey.pem 不存在，清空 certs 文件夹。')
        any(os.remove(x) for x in glob.glob(os.path.join(sub_certdir, '*.crt')))
        if GC.MISC_CHECKSYSCA and sys.platform.startswith('win'):
            logging.warning('CAkey.pem 不存在，将从系统证书中删除无效的 CA 证书')
        else:
            logging.warning('删除功能未启用或未支持，请自行删除 [%s CA] 证书' % ca_vendor)
        dump_ca()
    global ca_privatekey, ca_subject, sub_publickey, ca_thumbprint
    with open(ca_keyfile, 'rb') as fp:
        content = fp.read()
    ca = crypto.load_certificate(crypto.FILETYPE_PEM, content)
    ca_privatekey = crypto.load_privatekey(crypto.FILETYPE_PEM, content)
    ca_subject = ca.get_subject()
    ca_thumbprint = ca.digest('sha1')
    ca_certerror = True
    if os.path.exists(ca_certfile):
        with open(ca_certfile, 'rb') as fp:
            if fp.read() in content:
                ca_certerror = False
    if ca_certerror:
        with open(ca_certfile, 'wb') as fp:
            fp.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))
    #检查系统 CA 证书
    if GC.MISC_CHECKSYSCA and import_ca() != 0:
        logging.warning('install root certificate failed, Please run as administrator/root/sudo')
    #检查伪造网站密钥
    if os.path.exists(sub_keyfile):
        with open(sub_keyfile, 'rb') as fp:
            content = fp.read()
        sub_publickey = crypto.load_publickey(crypto.FILETYPE_PEM, content)
    else:
        dump_subkey()
    sub_publickey_str = crypto.dump_publickey(crypto.FILETYPE_PEM, sub_publickey)
    #检查伪造网站证书
    certfiles = glob.glob(os.path.join(sub_certdir, '*.crt'))
    if certfiles:
        filename = random.choice(certfiles)
        with open(filename, 'rb') as fp:
            content = fp.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, content)
        if not verify_certificate(ca, cert) or (sub_publickey_str !=
                crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey())):
            logging.error('Certs mismatch, delete Certs.')
            any(os.remove(x) for x in certfiles)
