# coding:utf-8
"""CertUtil module, based on mitmproxy"""

import os
import sys
import threading
import glob
import base64
import hashlib
import random
import OpenSSL
import clogging as logging
from time import time
from common import cert_dir
crypto = OpenSSL.crypto


ca_vendor = 'GotoX'
ca_certfile = os.path.join(cert_dir, 'CA.crt')
ca_keyfile = os.path.join(cert_dir, 'CAkey.pem')
ca_certdir = os.path.join(cert_dir, 'certs')
ca_thumbprint = ''
ca_key = None
ca_subject = None
ca_digest = 'sha256'
sub_keyfile = os.path.join(cert_dir, 'subkey.pem')
sub_key = None
sub_lock = threading.Lock()
sub_serial = 3600*24*365*46
sub_time = 3600*24*(365*10+10//4)

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
    ca.gmtime_adj_notBefore(0)
    ca.gmtime_adj_notAfter(3600*24*(365*30+30//4))
    ca.set_issuer(subject)
    ca.set_pubkey(pkey)
    ca.add_extensions([
        crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE, pathlen:0'),
        crypto.X509Extension(b'extendedKeyUsage', True, b'serverAuth,emailProtection,timeStamping'),
        crypto.X509Extension(b'keyUsage', False, b'keyCertSign, cRLSign'),
        crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=ca), ])
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
    global sub_key
    sub_key = crypto.PKey()
    sub_key.generate_key(crypto.TYPE_RSA, 2048)
    with open(sub_keyfile, 'wb') as fp:
        fp.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, sub_key))
        sub_keystr = crypto.dump_publickey(crypto.FILETYPE_PEM, sub_key)
        fp.write(sub_keystr)
    return sub_keystr

def create_subcert(certfile, commonname, ip=False, sans=[]):
    cert = crypto.X509()
    cert.set_version(2)
    cert.set_serial_number(int((int(time()-sub_serial)+random.random())*100)) #setting the only number
    subject = cert.get_subject()
    subject.countryName = 'CN'
    subject.stateOrProvinceName = 'Internet'
    subject.localityName = 'Cernet'
    subject.organizationalUnitName = '%s Branch' % ca_vendor
    subject.commonName = commonname
    subject.organizationName = commonname
    if ip:
        sans = set([commonname,] + sans)
    else:
        sans = set([commonname, '*.'+commonname] + sans)
    sans = ', '.join('DNS: %s' % x for x in sans)
    if not isinstance(sans, bytes):
        sans = sans.encode()
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(sub_time)
    cert.set_issuer(ca_subject)
    cert.set_pubkey(sub_key)
    cert.add_extensions([crypto.X509Extension(b'subjectAltName', True, sans)])
    cert.sign(ca_key, ca_digest)

    with open(certfile, 'wb') as fp:
        fp.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

def get_cert(commonname, ip=False, sans=[]):
    #if commonname.count('.') >= 2 and [len(x) for x in reversed(commonname.split('.'))] > [2, 4]:
    #    commonname = '.'+commonname.partition('.')[-1]
    if ip:
        certfile = os.path.join(ca_certdir, commonname + '.crt')
    else:
        rcommonname = '.'.join(reversed(commonname.split('.')))
        certfile = os.path.join(ca_certdir, rcommonname + '.crt')
    with sub_lock:
        if os.path.exists(certfile):
            return certfile, sub_keyfile
    create_subcert(certfile, commonname, ip, sans)
    return certfile, sub_keyfile

def import_cert(certfile):
    commonname = os.path.splitext(os.path.basename(certfile))[0]
    isCA = False
    if certfile == ca_keyfile or certfile == ca_certfile:
        commonname = ca_subject.commonName
        isCA = True
    else:
        try:
            with open(certfile, 'rb') as fp:
                commonname = crypto.load_certificate(crypto.FILETYPE_PEM, fp.read()).get_subject().commonName.decode()
        except Exception as e:
            logging.error('load_certificate(certfile=%r) failed:%s', certfile, e)
    if sys.platform.startswith('win'):
        import ctypes
        with open(certfile, 'rb') as fp:
            certdata = fp.read()
            if certdata.startswith(b'-----'):
                begin = b'-----BEGIN CERTIFICATE-----'
                end = b'-----END CERTIFICATE-----'
                certdata = base64.b64decode(b''.join(certdata[certdata.find(begin)+len(begin):certdata.find(end)].strip().splitlines()))
            crypt32 = ctypes.WinDLL(b'crypt32.dll'.decode())
            store_handle = crypt32.CertOpenStore(10, 0, 0, 0x4000 | 0x20000, b'ROOT'.decode())
            if not store_handle:
                return -1
            X509_ASN_ENCODING = 0x00000001
            CERT_FIND_HASH = 0x10000
            CERT_FIND_SUBJECT_STR = 0x00080007
            if isCA:
                class CRYPT_HASH_BLOB(ctypes.Structure):
                    _fields_ = [('cbData', ctypes.c_ulong), ('pbData', ctypes.c_char_p)]
                import binascii
                assert ca_thumbprint
                crypt_hash = CRYPT_HASH_BLOB(20, binascii.a2b_hex(ca_thumbprint.replace(':', '')))
                find_mode = CERT_FIND_HASH
                find_data = ctypes.byref(crypt_hash)
            else:
                find_mode = CERT_FIND_SUBJECT_STR
                find_data = ca_vendor.decode()
            crypt_handle = crypt32.CertFindCertificateInStore(store_handle, X509_ASN_ENCODING, 0, find_mode, find_data, None)
            if crypt_handle:
                crypt32.CertFreeCertificateContext(crypt_handle)
                return 0
            ret = crypt32.CertAddEncodedCertificateToStore(store_handle, 0x1, certdata, len(certdata), 4, None)
            crypt32.CertCloseStore(store_handle, 0)
            del crypt32
        return 0 if ret else -1
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

def remove_cert(name):
    if os.name == 'nt':
        import ctypes, ctypes.wintypes
        class CERT_CONTEXT(ctypes.Structure):
            _fields_ = [
                ('dwCertEncodingType', ctypes.wintypes.DWORD),
                ('pbCertEncoded', ctypes.POINTER(ctypes.wintypes.BYTE)),
                ('cbCertEncoded', ctypes.wintypes.DWORD),
                ('pCertInfo', ctypes.c_void_p),
                ('hCertStore', ctypes.c_void_p),]
        crypt32 = ctypes.WinDLL(b'crypt32.dll'.decode())
        store_handle = crypt32.CertOpenStore(10, 0, 0, 0x4000 | 0x20000, b'ROOT'.decode())
        pCertCtx = crypt32.CertEnumCertificatesInStore(store_handle, None)
        while pCertCtx:
            certCtx = CERT_CONTEXT.from_address(pCertCtx)
            certdata = ctypes.string_at(certCtx.pbCertEncoded, certCtx.cbCertEncoded)
            cert =  crypto.load_certificate(crypto.FILETYPE_ASN1, certdata)
            if hasattr(cert, 'get_subject'):
                cert = cert.get_subject()
            cert_name = next((v for k, v in cert.get_components() if k == 'CN'), '')
            if cert_name and name == cert_name:
                crypt32.CertDeleteCertificateFromStore(crypt32.CertDuplicateCertificateContext(pCertCtx))
            pCertCtx = crypt32.CertEnumCertificatesInStore(store_handle, pCertCtx)
        return 0
    return -1

def verify_ca(ca, cert):
    store = crypto.X509Store()
    store.add_cert(ca)
    try:
        crypto.X509StoreContext(store, cert).verify_certificate()
    except:
        return False
    return True

def check_ca():
    #Check cert Dir
    #if os.path.exists(cert_dir):
    #    if not os.path.isdir(cert_dir):
    #        os.remove(cert_dir)
    #        os.mkdir(cert_dir)
    #else:
    #    os.mkdir(cert_dir)
    #Check CA exists
    if not os.path.exists(ca_keyfile):
        if not OpenSSL:
            logging.critical('CAkey.pem is not exist and OpenSSL is disabled, ABORT!')
            sys.exit(-1)
        if os.path.exists(ca_certdir):
            if os.path.isdir(ca_certdir):
                logging.error('CAkey.pem is not exist, delete Certs.')
                any(os.remove(x) for x in glob.glob('%s/*.crt' % ca_certdir))
            else:
                os.remove(ca_certdir)
                os.mkdir(ca_certdir)
        try:
            if remove_cert('%s CA' % ca_vendor) == 0:
                logging.error('CAkey.pem is not exist, delete from system.')
            else:
                raise UserWarning('cannot work for %s! please delete manually.' % sys.platform)
        except Exception as e:
            logging.warning('CertUtil.remove_cert failed: %r', e)
        dump_ca()
    global ca_key, ca_subject, sub_key, ca_thumbprint
    with open(ca_keyfile, 'rb') as fp:
        content = fp.read()
    ca = crypto.load_certificate(crypto.FILETYPE_PEM, content)
    ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, content)
    ca_subject = ca.get_subject()
    ca_thumbprint = ca.digest(ca_digest)
    ca_certerror = False
    if os.path.exists(ca_certfile):
        with open(ca_certfile, 'rb') as fp:
            if fp.read() not in content:
                ca_certerror = True
    if ca_certerror:
        with open(ca_certfile, 'wb') as fp:
            fp.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))
    #Check sub Key exists
    if os.path.exists(sub_keyfile):
        with open(sub_keyfile, 'rb') as fp:
            content = fp.read()
        sub_key = crypto.load_publickey(crypto.FILETYPE_PEM, content)
        sub_keystr = crypto.dump_publickey(crypto.FILETYPE_PEM, sub_key)
    else:
        sub_keystr = dump_subkey()
    #Check Certs
    certfiles = glob.glob('%s/*.crt' % ca_certdir)
    if certfiles:
        filename = random.choice(certfiles)
        with open(filename, 'rb') as fp:
            content = fp.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, content)
        if not verify_ca(ca, cert) or (sub_keystr !=
                crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey())):
            logging.error('Certs mismatch, delete Certs.')
            any(os.remove(x) for x in certfiles)
        del cert
    #Del none-use object
    del content, certfiles, sub_keystr
    #Check CA imported
    #if import_cert(ca_keyfile) != 0:
    #    logging.warning('install root certificate failed, Please run as administrator/root/sudo')
    #Check Certs Dir
    if os.path.exists(ca_certdir):
        if not os.path.isdir(ca_certdir):
            os.remove(ca_certdir)
            os.mkdir(ca_certdir)
    else:
        os.mkdir(ca_certdir)

if __name__ == '__main__':
    check_ca()
