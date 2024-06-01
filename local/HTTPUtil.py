# coding:utf-8
'''HTTP Request Util'''

import sys
import os
import errno
import socket
import random
import socks
import collections
import OpenSSL
import logging
import threading
from time import mtime, sleep
from queue import Queue
from threading import _start_new_thread as start_new_thread
from http.client import HTTPResponse
from .GlobalConfig import GC
from .compat.openssl import (
    zero_errno, zero_EOF_error, res_ciphers, SSL, SSLConnection,
    CertificateError, CertificateErrorTab, match_hostname )
from .common.dns import dns, dns_resolve
from .common.internet_active import internet_v4, internet_v6
from .common.net import (
    NetWorkIOError, random_hostname, reset_errno, bypass_errno,
    isip, check_connection_dead )
from .common.decorator import make_lock_decorator
from .common.path import cert_dir
from .common.proxy import parse_proxy, proxy_no_rdns
from .common.util import LRUCache, LimiterFull, LimitDictBase, wait_exit
from .FilterUtil import reset_method_list, get_fakesni, unset_temp_fakesni

GoogleONames = {'Google LLC', 'Google Trust Services LLC'}
GoogleICAPkeys = {
# https://pki.goog/repository/

# AE1 / 20290220140000Z
# https://pki.goog/ae1.pem
b'''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfQpc2xnA2QzSeb/iaPxF4hf6vk1Z
G4kdysA5b4ztwEehL4gr9cw0hvWbUY0MMFfx2AFk25RgueBWo4vmSYBqqg==
-----END PUBLIC KEY-----
''',
# GTS CA 1C3 / 20270930000042Z
# https://pki.goog/1c3.pem
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9Yjf52KMHjf4N0KQf2yH
0PtlgiX96MtrpP9t6Voj4pn2HOmSA5kTfAkKivpC1l5WJKp6M4Qf0elpu7l07FdM
ZmiTdzdVU/45EE23NLtfJXc3OxeU6jzlndW8w7RD6y6nR++wRBFj2LRBhd1BMEiT
G7+39uBFAiHglkIXz9krZVY0ByYEDaj9fcou7+pIfDdNPwCfg9/vdYQueVdc/Fdu
Gpb//Iyappm+Jdl/liwG9xEqAoCA62MYPFBJh+WKyl8ZK1mWgQCg+1HbyncLC8mW
T+9wScdcbSD9mbS04soud/0t3Au2axMMjBkrF5aYufCL9qAnu7bjjVGPva7Hm7GJ
nQIDAQAB
-----END PUBLIC KEY-----
''',
# GTS CA 1D4 / 20270930000042Z
# https://pki.goog/1d4.pem
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq8Cqo8ITbuXTD3MLx1M8
gTz1sD7FOYNobvLtV9Dhz6Y5aGVR5tRCkrTK/avrvxEkTErQdYON6r6csgc3USbm
PqsBFmLGbJFKOEhHQo5A8YExSV2xrO0ggns7SD/zaqP+8YOX//e3i1OrGJGEtCdM
tcl14H7YOGR1TogiDHrA3sTk1xQfdFyx6NyqPynlKPX28GbqLUWGosbKaEwWuhZV
QY7fG0gf3V2yDLh4Upx8pUtYrejbX3RDQub9KIqYttEnkC7jLV64UmbYkz14HzgW
SpreK+tdZR5W3J7QJB0q+xjYWRrO/G3G+6wsnMtZgeTnnNxEBpwMDZJ4S0FtB8PW
qwIDAQAB
-----END PUBLIC KEY-----
''',
# GTS CA 1D9 / 20270930000042Z
# https://pki.goog/1d9.pem
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwqgMGYUuoKK4posxN4lL
2fQLQjb4M6EWpVyhUNCZnM0xv+DxQTAmPqm7x6OyEceZp+44M2DeIvzFUKAbVoLk
brwi4rv79tpKfhZN0eU8DPlMfeGfXL3F34vYOIorIFEqMfNGrPFv+1dSSiSND16W
IrNGMrPN9GcZjt2I+Iwf98hqtfU6O6k38TDSxBfZ8GgTAA+awh4S89FaTm15RLc2
94Ezvv/lcSwLGGo+40Xy9m5dOxZZ4/D9+jKV7gvFDa/kYt0pCHiLSg9+0UgQ2Cl9
EmRuQYxDhVoLcjzm+bj5wZd98Nq8KNwsbkVjqqIrdxQfZ0AWtLQtCRfAa9qU0dUN
2wIDAQAB
-----END PUBLIC KEY-----
''',
# GTS CA 1P5 / 20270930000042Z
# https://pki.goog/1p5.pem
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs4LwJIy/LYevstmnrvrK
ukTWWz7+sveyZRbc3hDoTy0QWFoohoeh7mqzoNl1T3+hUgGLVahKWwZIyDYSJauJ
+fIjX51gZflc2r466FxtfZzQhBiFMM1Om+w82LPhltTzxQtl24+wdMv2HvN48ayV
xd1zwzGIga90qm/9DOMFlfDFEE9lY/qgr8YYPcWh35d51wWJszCwdK49khBrjBV3
3QsEV/uBA93qIjTV5Vay8MSNQbHDAtti7IDQ/3bUhuQEGra2DCticX3Zr9nxXvrA
HsqgGVxV8IDRKgwHhpCfNeMoK1vvI8ijHaSjOu7+g9yCTCWwTcVRrZ6b01uEwhpa
6QIDAQAB
-----END PUBLIC KEY-----
''',
# GTS CA 2A1 / 20250930000042Z
# https://pki.goog/2a1.pem
b'''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAN+bsxmjxoOPZBA3MIh/CdD/J31/
5vRh3MdletXO0zD+TrcD4wZPMrVdMsX4tiPtyzI/rYEiaaJFIBfAXqKIiA==
-----END PUBLIC KEY-----
''',
# GTS CA 2D5 / 20270930000042Z
# https://pki.goog/2d5.pem
b'''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGnyqBX4G667p4/WDEYRn+nZv5Rvk
F8SALPXUXCnckvOjTzQwt1BKrjE5wlRRFfQo6Ph0gnLq2XrYAtubC8rGzw==
-----END PUBLIC KEY-----
''',
# GTS CA 2D6 / 20270930000042Z
# https://pki.goog/2d6.pem
b'''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEj3yYpzPSoxq1wGDRu4zdoziVD80c
kaTnyRFIAAx5xy7nuFMEy0V/rfw9336Vkeba/3cOpWwwLaNp5GFN7H/hVQ==
-----END PUBLIC KEY-----
''',
# GTS CA 2P2 / 20270930000042Z
# https://pki.goog/2p2.pem
b'''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp1CTOMAeo5Sxv9OQftzPmVG0Pfvi
01nytisJRvWbHKkT5WYJvUmDOr73e1F0TvwZHM8jj6rqtqFrVMTJaCieIw==
-----END PUBLIC KEY-----
''',
# GTS Root R1 / 20280128000042Z
# https://pki.goog/r1x.pem
b'''\
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAthECix7joXebO9y/lD63
ladAPKH9gvl9MgaCcfb2jH/76Nu8ai6Xl6OMS/kr9rH5zoQdsfnFl97vufKj6bwS
iV6nqlKr+CMny6SxnGPb15l+8Ape62im9MZaRw1NEDPjTrETo8gYbEvs/AmQ351k
KSUjB6G00j0uYODP0gmHu81I8E3CwnqIiru6z1kZ1q+PsAewnjHxgsHA3y6mbWwZ
DrXYfiYaRQM9sHmklCitD38m5agI/pboPGiUU+6DOogrFZYJsuB6jC511pzrp1Zk
j5ZPaK49l8KEj8C8QMALXL32h7M1bKwYUH+E4EzNktMg6TO8UpmvMrUpsyUqtEj5
cuHKZPfmghCN6J3Cioj6OGaK/GP5Afl4/Xtcd/p2h/rs37EOeZVXtL0m79YB0esW
CruOC7XFxYpVq9Os6pFLKcwZpDIlTirxZUTQAs6qzkm06p98g7BAe+dDq6dso499
iYH6TKX/1Y7DzkvgtdizjkXPdsDtQCv9Uw+wp9U7DbGKogPeMa3Md+pvez7W35Ei
Eua++tgy/BBjFFFy3l3WFpO9KWgz7zpm7AeKJt8T11dleCfeXkkUAKIAf5qoIbap
sZWwpbkNFhHax2xIPEDgfg1azVY80ZcFuctL7TlLnMQ/0lUTbiSw1nH69MG6zO0b
9f6BQdgAmD06yK56mDcYBZUCAwEAAQ==
-----END PUBLIC KEY-----
''',
# GTS Root R4 / 20280128000042Z
# https://pki.goog/r4x.pem
b'''\
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE83Rzp2iLYK5DuDXFgTB7S0md+8Fhzube
Rr1r1WEYNa5A3XP3iZEwWus87oV8okB2O6nGuEfYKueSkWpz6bFyOZ8pn6KY019e
WIZlD6GEZQbR3IvJx3PIjGov5cSr0R2K
-----END PUBLIC KEY-----
''',
# MR1 / 20290220140000Z
# https://pki.goog/mr1.pem
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh4BCBh2xRCrRgaWFd0eU
CufFLERH05CBNTLcGE2fMewqVgWPcKci/M+V5T9P13BpmaOkmVb+iSQ+yLu9d8s9
MTKuxKxBW3XeCfD9CJ8E2UfOOZPqDa3rvCLJDBp7wYnJOPrPdSIfdusoluxcgFZh
TCYPpZJvWgvSDRabCd1Jc6Qlgw/coP4+RQL423I7pSNoXM4FgZZ4p8yz5zfc6A7/
FdvxHR1SGKMFbsm0VglrGou+ABhUejmYWuUwf8kxIJzxkJ7RoVeC5gSvTCgY80zj
C7VWMYxVhwSj5nng3NpiO4kCrAFwIOdsNeOb/mCH9zWGsoC7ZqYpviDu7PlnCY0N
awIDAQAB
-----END PUBLIC KEY-----
''',
# WE1 / 20290220140000Z
# https://pki.goog/we1x.pem
b'''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb806/mdXR0whA4VAwkddu1hHD0DB
XBeFxhk359V87YZLm4HZ1xoTpQoD+JjExuie/xBZjywmmPXmJiW7DwL6Vg==
-----END PUBLIC KEY-----
''',
# WE1 / 20290220140000Z
# https://pki.goog/we1.pem
b'''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb806/mdXR0whA4VAwkddu1hHD0DB
XBeFxhk359V87YZLm4HZ1xoTpQoD+JjExuie/xBZjywmmPXmJiW7DwL6Vg==
-----END PUBLIC KEY-----
''',
# WE2 / 20290220140000Z
# https://pki.goog/we2x.pem
b'''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENX4f8hTtkH3hnio0Q4bB1ZboJ3Df
ngTLqcqGeQsITUaKwnSku9m/7v0j1zjzS+9UF+G+58pVJagMMKwtXU6hUQ==
-----END PUBLIC KEY-----
''',
# WE2 / 20290220140000Z
# https://pki.goog/we2.pem
b'''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENX4f8hTtkH3hnio0Q4bB1ZboJ3Df
ngTLqcqGeQsITUaKwnSku9m/7v0j1zjzS+9UF+G+58pVJagMMKwtXU6hUQ==
-----END PUBLIC KEY-----
''',
# WE3 / 20290220140000Z
# https://pki.goog/we3x.pem
b'''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjHJxXGblBFSWeRvBwoFlkDM2czzA
L7S5VAYqWjQnlZE1Cap6v5LJjRjoVpLiT6ptZ1ptQVGsCsN1xieyArfFQg==
-----END PUBLIC KEY-----
''',
# WE3 / 20290220140000Z
# https://pki.goog/we3.pem
b'''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjHJxXGblBFSWeRvBwoFlkDM2czzA
L7S5VAYqWjQnlZE1Cap6v5LJjRjoVpLiT6ptZ1ptQVGsCsN1xieyArfFQg==
-----END PUBLIC KEY-----
''',
# WE4 / 20290220140000Z
# https://pki.goog/we4x.pem
b'''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwaoJ/TzcGDY+2+tprX91ckehyGws
/Si79WBRd8GrvOzSIfY10l5wJFnd/FsTOT3RXzvQ+8yQHWqX/6j0hVMQbA==
-----END PUBLIC KEY-----
''',
# WE4 / 20290220140000Z
# https://pki.goog/we4.pem
b'''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwaoJ/TzcGDY+2+tprX91ckehyGws
/Si79WBRd8GrvOzSIfY10l5wJFnd/FsTOT3RXzvQ+8yQHWqX/6j0hVMQbA==
-----END PUBLIC KEY-----
''',
# WE5 / 20290220140000Z
# https://pki.goog/we5.pem
b'''\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiAyN4TrkJAaThXfWHMDsH1DfFgik
kKUOPMru3Ogk7Qvzg4g7rnXrt+ZvHjtPIBIrt+y4Hqs31/u1q37HWxn+og==
-----END PUBLIC KEY-----
''',
# WR1 / 20290220140000Z
# https://pki.goog/wr1.pem
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz242Foq3K+5GmAMdU3AP
d+6jS6Byvo8jLcJHxo9cjfk95hqO7jMiDckRSLiwYs70aQ1yAn3e1SYPw26bz34O
1yDPxpA7o4IG2jqd/2xWv9zpYZRF5Gm8Tw/JE8CtYURyIIHQDyueaGpiao+KIld5
aSviJDN+dmMsXbxRaX4jB7H/doHx7rhYtWs1Fe+h5kgoOZcx2Qcflaeers+YvJ6N
igPhsJdNUG+TTEof+Nt98ZCZFX/jlu3uMYHqcj1SHd8lZKULcKqe6Ki5R8inWhAl
YG9C4dc/548M8MKDRjMg5kt3BHahaKddFRjv2Ch3Na0OrUbkYm7iqvjM7zd+Dyaz
BwIDAQAB
-----END PUBLIC KEY-----
''',
# WR2 / 20290220140000Z
# https://pki.goog/wr2.pem
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqf+cf0UecKhTn8rZ5Q3e
RldXfbyPmlqsRvGEmruR28n7LwH7kgkAFl6gHPjBq/l4L0rM2IWi2Fk8DtMY+7H1
JA0m7rZbZHZ8FMcves6oTLf02Qj834cjNSCo4mnijE4/sVn6YKIes8kgUxmCyjZT
bWBN6QCR/HaNXAgPCsLc8XNrxRNuCk96wvICHC60Y4PaMfYtdTCy+6vCbtupwA65
+WfUwyVXdOsFtOmOtd4ozcx6FORxA8tNYS5hV8UZqQuYhBroeSnZso0v/1dqZuDO
q5WoKZZjcBJnHjrh27Ahcdd8nv2qF27+K/s4FxTRZqevmrVwzMhjgTqMwCqpdjfO
4wIDAQAB
-----END PUBLIC KEY-----
''',
# WR3 / 20290220140000Z
# https://pki.goog/wr3.pem
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjzR1h6+EchSNBxCRbwOs
8dQINZoZ8psYiTRsmI961N3qBejeG3yMVBK6eYr7GA0NfJzzvTjkqF7GM8tGiW9G
oOk3Y43czNWXTjKtex0jBbn1e0lDmNC8V8dTeBix7adUsnyGvvBURbyHuplZHfS4
2wD7gU9GK2JesTqlKhcjrKK+xY7lXv1xHn2ktCN9BFKyNNLfmayHxkxZX/jmT451
ksKyMEaS0LYNx+SJZ/8/VJQnZeMByEoshC9lX82tXP2mrUFb3Ew/F5aRfanYPFMq
HNDm1HfmQ0rCt/hIos2tY7Ula5ZyHYFFb4ZpxOTmeEwx5qF/pwFzCofvh4lyzNPF
jQIDAQAB
-----END PUBLIC KEY-----
''',
# WR4 / 20290220140000Z
# https://pki.goog/wr4.pem
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr05Rv85QpOuOPZGlvwwq
IqqKdKSMMmjfCkBm7FdtLK9G+NvSa0TECyU/+7CES7F3a1XAOe++VfV0PxZVT1LM
hUGlhxMYGkGn9j2cTVZGH0/Uk+e2vVG1fjU5XXJ5sb6KC5qYcP0xb5Z6atqzNecp
R4qvJRqoEKUff+gC7qJZlg1TjxRIAJU3fUKBFvYCzLht5Tt9ZbbHp2Vk9ZQkEtkU
VUsV4+3Ed9pV4EhLJNWc+e3kZYAn8nwL1CVLTLffNrKDUdnczlTio/c5Ynha23Xw
WYcWR0J+yCbhnHHYiZyk03mwY8TIVHFB5OtspTu4Hi7W9yTFG2570mA9lAHJYM68
JQIDAQAB
-----END PUBLIC KEY-----
''',
# WR5 / 20290220140000Z
# https://pki.goog/wr5.pem
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm9VcmIXBVu1LaU6jcyIs
urTiZNJibqXNHSctT3e+lsHoMpvj2W0JHvA/YJ2BvdqGL8Bitwyk7chcvKldiMVg
FiphDV8ZV4FME+susBn25duGWRibIRQ96P1jFhO26HAl1U+Vb0bwjEa+tyOANZBS
7E5FCyQWKGubLlwocwACx3QqMHaPie61wvnSTRoR07rycn8/antCPGu8pQ22tBYg
8cMwEqddHQK0mX9bMTpsttU+IaK8aJPem59nNothdz8XlrJFi07J8SYYwetzsKpL
tNZAv0PxwcrJdExVO8xUgPgwM+EUx8u7BWSq0S68fCiJeIMG6bcCSOOLoYa5VahA
3QIDAQAB
-----END PUBLIC KEY-----
''',
# 3rd
# Google CA1 / 20250825120000Z
# https://pki.goog/dc_google_ca1.pem
b'''\
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAupYx7NU9sbeWxSISCARB
GUNj/YKmUpoFxnM+cFwU98Qm3TWk+QkkbgWN7ScBqBHKHqwHt6OZvkhCEbV3D7C2
iDknM8riJdR45f9mDzHUiO12AHyxqao54PrSGvIukBCxU0BO8UV8zg/ZDFUoRPL6
4Pk9xWld9Thzlwts6Bi6CkjZ6HM5EiFiiIcOSvx8tGIHc0/ncBBjsop/ceRK6415
ReXKpyFHEEqH42P64XrGdDYSVli0jZhUDQoHCCjZxIpAagLYM5pryVvdWBGTvH4n
0j0uzPIM8riC+XYyHKnpW/JgargXADBQvIRwRNwEuvfvTVa4JIlPhCYwMo4qLzhx
vQIDAQAB
-----END PUBLIC KEY-----
'''}

gws_servername = GC.GAE_SERVERNAME
gae_testgwsiplist = GC.GAE_TESTGWSIPLIST
autorange_threads = GC.AUTORANGE_FAST_THREADS
_lock_context = make_lock_decorator()

class LimitConnection(LimitDictBase):
    'A connection limiter wrapper for remote IP.'

    maxsize = GC.LINK_MAXPERIP
    timeout = 3

    @classmethod
    def _limiterFactory(cls):
        limiter = super()._limiterFactory()
        limiter.iplock = threading.Lock()
        return limiter

    def __init__(self, sock, ip, maxsize=None, timeout=None):
        super().__init__(ip, maxsize, timeout)
        self._sock = sock
        self.iplock = self._limiter.iplock

    def __getattr__(self, name):
        return getattr(self._sock, name)

    def close(self):
        if super().close():
            try:
                self._sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._sock.close()

class LimitConnect(LimitDictBase):
    'A connect limiter for host cache key.'

    maxsize = 3
    timeout = 8

LimitConnection.init()
LimitConnect.init()

def limit_connect(func):

    def newfunc(*args, **kwargs):
        key = args[2]
        limiter = LimitConnect.push(key)
        try:
            return func(*args, **kwargs)
        finally:
            LimitConnect.pop(key)

    return newfunc

class BaseHTTPUtil:
    '''Basic HTTP Request Class'''

    ssl_ciphers = res_ciphers
    new_sock4_cache = collections.deque()
    new_sock6_cache = collections.deque()

    def __init__(self, cacert=None, ssl_ciphers=None):
        if GC.LINK_VERIFYGPK:
            self.google_verify = self.google_verify_pkey
        #建立公用 CA 证书库
        def init_cert_store():
            self.context_cache.clear()
            self.tcp_connection_cache.clear()
            self.ssl_connection_cache.clear()
            self._cert_store = OpenSSL.crypto.X509Store()
            self.load_cacert(cacert)
        if ssl_ciphers:
            self.ssl_ciphers = ssl_ciphers
        self.gws = gws = self.ssl_ciphers is gws_ciphers
        if gws:
            self.keeptime = GC.GAE_KEEPTIME
            self.max_per_ip = GC.GAE_MAXPERIP
        else:
            self.keeptime = GC.LINK_KEEPTIME
            self.max_per_ip = GC.LINK_MAXPERIP
        self.context_cache = LRUCache(min(GC.DNS_CACHE_ENTRIES, 256))
        self.tcp_connection_cache = collections.defaultdict(collections.deque)
        self.ssl_connection_cache = collections.defaultdict(collections.deque)
        self.init_cert_store = init_cert_store() or init_cert_store
        start_new_thread(self.check_connection_cache, ('tcp',))
        start_new_thread(self.check_connection_cache, ('ssl',))

    def load_cacert(self, cacert):
        if os.path.isdir(cacert):
            import glob
            cacerts = glob.glob(os.path.join(cacert, '*.pem'))
            if cacerts:
                for cacert in cacerts:
                    self._cert_store.load_locations(cacert)
        elif os.path.isfile(cacert):
            self._cert_store.load_locations(cacert)
        else:
            wait_exit('未找到可信任 CA 证书集，GotoX 即将退出！请检查：%r', cacert)

    @_lock_context
    def get_context(self, cache_key):
        try:
            return self.context_cache[cache_key]
        except KeyError:
            pass
        if self.gws or cache_key.startswith('cloudflare_workers'):
            #强制使用 TLSv1.3
            ssl_method = SSL.TLSv1_3_METHOD
        else:
            ssl_method = GC.LINK_REMOTESSL
        ssl_options = 0
        #使用兼容模式来指定 TLSv1.3
        if ssl_method == SSL.TLSv1_3_METHOD:
            ssl_options |= SSL.OP_NO_TLSv1
            ssl_options |= SSL.OP_NO_TLSv1_1
            ssl_options |= SSL.OP_NO_TLSv1_2
        #兼容模式 TLS 禁用 TLSv1.1 及以下版本
        elif ssl_method == SSL.SSLv23_METHOD:
            ssl_options |= SSL.OP_NO_SSLv2
            ssl_options |= SSL.OP_NO_SSLv3
            ssl_options |= SSL.OP_NO_TLSv1
            ssl_options |= SSL.OP_NO_TLSv1_1
        context = SSL.Context(ssl_method)
        #不使用压缩
        ssl_options |= SSL.OP_NO_COMPRESSION
        #通用问题修复
        ssl_options |= SSL.OP_ALL
        #会话重用
        ssl_options |= SSL.OP_NO_TICKET
        context.set_session_cache_mode(SSL.SESS_CACHE_OFF)
        #证书验证
        context.set_cert_store(self._cert_store)
        context.set_verify(SSL.VERIFY_PEER, self._verify_callback)
        #加密选择
        context.set_cipher_list(self.ssl_ciphers)
        #应用设置
        context.set_options(ssl_options)
        self.context_cache[cache_key] = context
        return context

    def _verify_callback(self, sock, cert, error_number, depth, ok):
        cert_params = sock.cert_params
        if cert_params and 'allow insecure' in cert_params:
            if error_number:
                logging.warning('%s 已配置为无安全验证, 当前错误代码: %d', sock.orig_hostname, error_number)
            return 1
        reason, gen_error_str = CertificateErrorTab.get(error_number, (None, None))
        if cert_params and reason and f'allow {reason.lower()}' in cert_params:
            ok = 1
            error_number = 0
            logging.debug('%s 已配置为忽略当前错误: %s', sock.orig_hostname, gen_error_str(cert))
        if ok and depth == 0 and not self.gws:
            self.match_hostname(sock, cert)
        elif error_number:
            if reason:
                raise CertificateError(-1, (gen_error_str(cert), depth, len(sock.get_peer_cert_chain())))
            else:
                logging.test('%s：%d-%d，%s', sock.get_servername(), depth, error_number, cert.get_subject())
        elif depth and ok:
            #添加可信的中间证书，一定程度上有助于验证配置缺失的服务器
            #下一步计划使用直接下载
            self._cert_store.add_cert(cert)
        return ok

    @staticmethod
    def match_hostname(sock, cert=None, hostname=None):
        cert = cert or sock.get_peer_certificate()
        if cert is None:
            raise CertificateError(-1, 'No cert has found.')
        hostname = hostname or sock.proof_hostname
        if hostname is None:
            return
        match_hostname(cert, hostname)

    def get_server_hostname(self, host, cache_key):
        servername = get_fakesni(host)
        if servername:
            return servername
        if self.gws:
            if cache_key == 'google_gae|:443' or host and host.endswith('.appspot.com'):
                if gws_servername is None:
                    fakehost = random_hostname('*com')
                    return fakehost
                else:
                    return random.choice(gws_servername)
            else:
                return GC.PICKER_SERVERNAME
        else:
            return host

    @staticmethod
    def set_tcp_socket(sock, timeout=None, set_buffer=True):
        # set reuseaddr option to avoid 10048 socket error
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # set struct linger{l_onoff=1,l_linger=0} to avoid 10048 socket error
        # struct.pack('ii', 1, 0) == b'\x01\x00\x00\x00\x00\x00\x00\x00'
        #sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b'\x01\x00\x00\x00\x00\x00\x00\x00')
        # resize socket recv buffer 8K->*K to improve browser releated application performance
        if set_buffer:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, GC.LINK_RECVBUFFER)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, GC.LINK_SENDBUFFER)
        # disable negal algorithm to send http request quickly.
        sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
        # set a short timeout to trigger timeout retry more quickly.
        sock.settimeout(timeout if timeout else 1)

    def _get_tcp_socket(self, _socket, ip, timeout=None):
        if not ':' in ip:
            if not internet_v4.last_stat:
                sleep(1)
                raise socket.error('无法连接 IPv4 互联网')
            new_sock_cache = self.new_sock4_cache
            AF_INETX = socket.AF_INET
        else:
            if not internet_v6.last_stat:
                sleep(1)
                raise socket.error('无法连接 IPv6 互联网')
            new_sock_cache = self.new_sock6_cache
            AF_INETX = socket.AF_INET6
        if new_sock_cache:
            sock = new_sock_cache.popleft()
        else:
            # create a ipv4/ipv6 socket object
            sock = _socket(AF_INETX)
        try:
            # wrap for connect limit
            sock = LimitConnection(sock, ip, self.max_per_ip)
        except LimiterFull as e:
            new_sock_cache.append(sock)
            raise e
        else:
            self.set_tcp_socket(sock, timeout)
            return sock

    def get_tcp_socket(self, ip, timeout=None):
        return self._get_tcp_socket(socket.socket, ip, timeout)

    def get_proxy_socket(self, proxyip, timeout=None):
        return self._get_tcp_socket(socks.socksocket, proxyip, timeout)

    def get_ssl_socket(self, sock, cache_key, server_hostname=None):
        if isinstance(server_hostname, tuple):
            server_hostname, sock.orig_hostname, sock.proof_hostname, sock.cert_params = server_hostname
        else:
            sock.orig_hostname = sock.proof_hostname = server_hostname
            sock.cert_params = None
        context = self.get_context(cache_key)
        ssl_sock = SSLConnection(context, sock)
        if server_hostname and not isip(server_hostname):
            ssl_sock.set_tlsext_host_name(server_hostname.encode())
        return ssl_sock

    @staticmethod
    def google_verify(sock):
        cert = sock.get_peer_certificate()
        if not cert:
            raise CertificateError(-1, '没有获取到证书')
        subject = cert.get_subject()
        if subject.O not in GoogleONames:
            raise CertificateError(-1, '%s 证书的组织名称（%s）不属于 %s 之一。' % (sock.getpeername(), subject.O, GoogleONames))
        return cert

    @staticmethod
    def google_verify_pkey(sock):
        certs = sock.get_peer_cert_chain()
        if len(certs) < 2:
            raise CertificateError(-1, '谷歌域名没有获取到正确的证书链：缺少 CA。')
        if OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, certs[1].get_pubkey()) not in GoogleICAPkeys:
            raise CertificateError(-1, '谷歌域名没有获取到正确的证书链：CA 公钥不匹配。')
        return certs[0]

    @staticmethod
    def check_connection_alive(sock, keeptime, ctime):
        if mtime() - ctime > keeptime:
            sock.close()
            return
        return not check_connection_dead(sock)

    def check_connection_cache(self, type='tcp'):
        check_connection_alive = self.check_connection_alive
        if type == 'tcp':
            connection_cache = self.tcp_connection_cache
        elif type == 'ssl':
            connection_cache = self.ssl_connection_cache
        else:
            raise ValueError('unknown connection cache type: %r' % type)
        keeptime = self.keeptime
        while True:
            sleep(1)
            #将键名放入元组
            keys = tuple(connection_cache.keys())
            for cache_key in keys:
                if cache_key not in connection_cache:
                    continue
                cache = connection_cache[cache_key]
                try:
                    while cache:
                        ctime, connection = cached_connection = cache.popleft()
                        if check_connection_alive(connection, keeptime, ctime):
                            cache.appendleft(cached_connection)
                            break
                except Exception as e:
                    logging.error('check_connection_cache(type=%r, key=%r) 错误：%s', type, cache_key, e)
                if not cache:
                    del connection_cache[cache_key]

    def clear_all_connection_cache(self):
        self.tcp_connection_cache.clear()
        self.ssl_connection_cache.clear()

class HTTPUtil(BaseHTTPUtil):
    '''HTTP Request Class'''

    protocol_version = 'HTTP/1.1'

    def __init__(self, cacert, ssl_ciphers=None, max_window=4, timeout=8, proxy='', max_retry=2):
        # http://docs.python.org/dev/library/ssl.html
        # http://blog.ivanristic.com/2009/07/examples-of-the-information-collected-from-ssl-handshakes.html
        # http://src.chromium.org/svn/trunk/src/net/third_party/nss/ssl/sslenum.c
        # http://www.openssl.org/docs/apps/ciphers.html
        # openssl s_server -accept 443 -key CA.crt -cert CA.crt
        # set_ciphers as Modern Browsers
        BaseHTTPUtil.__init__(self, cacert, ssl_ciphers)
        self.max_window = max_window
        self.max_retry = max_retry
        self.timeout = timeout
        self.proxy = proxy
        self.tcp_connection_time = LRUCache(512 if self.gws else 4096)
        self.ssl_connection_time = LRUCache(512 if self.gws else 4096)

        if self.gws and GC.GAE_ENABLEPROXY:
            self.gws_front_connection_time = LRUCache(128)
            self.gws_front_connection_time.set('ip', LRUCache(128), expire=False)
            self.create_ssl_connection = self.create_gws_connection_withproxy

        #if self.proxy:
        #    dns_resolve = self.__dns_resolve_withproxy
        #    self.create_connection = self.__create_connection_withproxy
        #    self.create_ssl_connection = self.__create_ssl_connection_withproxy

        self.create_connection = limit_connect(self.create_connection)
        self.create_ssl_connection = limit_connect(self.create_ssl_connection)

    def get_tcp_ssl_connection_time(self, addr):
        t = self.tcp_connection_time.get(addr) or self.ssl_connection_time.get(addr, self.timeout)
        if LimitConnection.full(addr[0]):
            t += self.timeout
        return t

    def get_tcp_connection_time(self, addr):
        t = self.tcp_connection_time.get(addr, self.timeout)
        if LimitConnection.full(addr[0]):
            t += self.timeout
        return t

    def get_ssl_connection_time(self, addr):
        t = self.ssl_connection_time.get(addr, self.timeout)
        if LimitConnection.full(addr[0]):
            t += self.timeout
        return t

    def _cache_connection(self, cache, count, queobj):
        for _ in range(count):
            sock = queobj.get()
            if hasattr(sock, '_sock'):
                cache.append((mtime(), sock))

    def _create_connection(self, ipaddr, queobj, timeout=None, get_cache_sock=None):
        if get_cache_sock:
            sock = get_cache_sock()
            if sock:
                queobj.put(sock)
                return

        sock = None
        try:
            sock = self.get_tcp_socket(ipaddr[0], timeout)
            # start connection time record
            start_time = mtime()
            # TCP connect
            sock.connect(ipaddr)
            # record TCP connection time
            self.tcp_connection_time[ipaddr] = sock.tcp_time = mtime() - start_time
            # put socket object to output queobj
            sock.xip = ipaddr
            queobj.put(sock)
        except NetWorkIOError as e:
            if sock:
                sock.close()
            # any socket.error, put Excpetions to output queobj.
            e.xip = ipaddr
            queobj.put(e)
            # reset a large and random timeout to the ipaddr
            self.tcp_connection_time[ipaddr] = self.timeout + 1

    def create_connection(self, address, hostname, cache_key, ssl=None, forward=None, **kwargs):
        def get_cache_sock(cache=None):
            if cache is None:
                cache = self.tcp_connection_cache.get(cache_key)
            used_sock = []
            try:
                while cache:
                    ctime, sock = cachedsock = cache.pop()
                    if newconn and hasattr(sock, 'used'):
                        used_sock.append(cachedsock)
                        continue
                    if self.check_connection_alive(sock, self.keeptime, ctime):
                        return sock
            except IndexError:
                pass
            finally:
                if newconn and used_sock:
                    used_sock.reverse()
                    cache.extend(used_sock)

        def get_cache_sock_ex():
            if cache_key is None or '|' in hostname:
                return
            names = hostname.split('.')
            if len(names[-1]) == 2 and len(names[-2]) <= 3:
                if len(names) > 3:
                    del names[0]
            elif len(names) > 2:
                del names[0]
            chost = '.'.join(names)
            ckey = '%s:%s' % (chost, cache_key.partition(':')[-1])
            keys = tuple(self.tcp_connection_cache.keys())
            for key in keys:
                if key not in self.tcp_connection_cache or\
                         '|' in key or not key.endswith(ckey):
                    continue
                cache = self.tcp_connection_cache[key]
                sock = get_cache_sock(cache)
                if sock:
                    if key != cache_key:
                        logging.warning(
                            '%s create_connection %r 尝试复用 %r 连接，'
                            '站点 %r 可能配置了多个子域名和较少的 IP。\n'
                            '可以尝试在 iplist 配置列表：\tcdn_%s = %s\n'
                            '然后在自动规则中使用此列表：\t%s$ = cdn_%s',
                            sock.xip[0], hostname, key, chost, chost, chost, chost, chost)
                    return sock

        newconn = forward and ssl
        sock = get_cache_sock()
        if sock:
            return sock

        result = None
        host, port = address
        addresses = [(x, port) for x in dns[hostname]]
        if ssl:
            get_connection_time = self.get_tcp_ssl_connection_time
        else:
            get_connection_time = self.get_tcp_connection_time
        for i in range(self.max_retry):
            addresseslen = len(addresses)
            if addresseslen > self.max_window:
                addresses.sort(key=get_connection_time)
                window = min((self.max_window+1)//2 + min(i, 1), addresseslen)
                addrs = addresses[:window] + random.sample(addresses[window:], self.max_window-window)
            else:
                addrs = addresses
            queobj = Queue()
            for addr in addrs:
                start_new_thread(self._create_connection, (addr, queobj, forward, get_cache_sock))
            addrslen = len(addrs)
            for n in range(addrslen):
                result = queobj.get()
                if isinstance(result, Exception):
                    addr = result.xip
                    if addresseslen > 1:
                        #临时移除 badip
                        try:
                            addresses.remove(addr)
                            addresseslen -= 1
                        except ValueError:
                            pass
                    if i == n == 0:
                        if isinstance(result, LimiterFull):
                            sock = get_cache_sock_ex()
                            if sock:
                                return sock
                        else:
                            #only output first error
                            logging.warning('%s _create_connection %r 返回 %r，重试', addr[0], host, result)
                else:
                    if addrslen - n > 1:
                        cache = self.tcp_connection_cache[cache_key]
                        start_new_thread(self._cache_connection, (cache, addrslen-n-1, queobj))
                    return result
        if result:
            raise result

    def _create_ssl_connection(self, ipaddr, cache_key, host, queobj, timeout=None, get_cache_sock=None, callback=None):
        retry = None
        while True:
            if get_cache_sock:
                sock = get_cache_sock()
                if sock:
                    queobj.put(sock)
                    return

            ip = ipaddr[0]
            sock = None
            try:
                sock = self.get_tcp_socket(ip, timeout)
                server_name = self.get_server_hostname(host, cache_key)
                ssl_sock = self.get_ssl_socket(sock, cache_key, server_name)
                # start connection time record
                start_time = mtime()
                # TCP connect
                ssl_sock.connect(ipaddr)
                #connected_time = mtime()
                # set a short timeout to trigger timeout retry more quickly.
                if timeout is not None:
                    ssl_sock.settimeout(3 if self.gws else 1.5)
                # SSL handshake
                ssl_sock.do_handshake()
                handshaked_time = mtime()
                # record SSL connection time
                ssl_sock.ssl_time = handshaked_time - start_time
                # verify Google SSL certificate.
                if self.gws:
                    self.google_verify(ssl_sock)
                ssl_sock.xip = ipaddr
                if callback:
                    cache_key = callback(ssl_sock) or cache_key
                    self.ssl_connection_time[ipaddr] = ssl_sock.ssl_time
                    self.ssl_connection_cache[cache_key].append((mtime(), ssl_sock))
                    return True
                self.ssl_connection_time[ipaddr] = ssl_sock.ssl_time
                # put ssl socket object to output queobj
                queobj.put(ssl_sock)
            except NetWorkIOError as e:
                if sock:
                    sock.close()
                # any socket.error, put Excpetions to output queobj.
                e.xip = ipaddr
                if callback:
                    if not retry and (e.args == zero_EOF_error or e.args[0] in zero_errno):
                        retry = True
                        continue
                    else:
                        callback(e)
                        return isinstance(e, LimiterFull)
                # reset a large and random timeout to the ipaddr
                try:
                    self.ssl_connection_time[ipaddr] += 1
                except KeyError:
                    self.ssl_connection_time[ipaddr] = self.timeout + 1
                queobj.put(e)
            break

    def create_ssl_connection(self, address, hostname, cache_key, getfast=None, forward=None, **kwargs):
        def get_cache_sock(cache=None):
            if cache is None:
                cache = self.ssl_connection_cache.get(cache_key)
            try:
                while cache:
                    ctime, ssl_sock = cache.pop()
                    if self.check_connection_alive(ssl_sock, self.keeptime, ctime):
                        return ssl_sock
            except IndexError:
                pass

        def get_cache_sock_ex():
            if cache_key is None or '|' in hostname:
                return
            names = hostname.split('.')
            if len(names[-1]) == 2 and len(names[-2]) <= 3:
                if len(names) > 3:
                    del names[0]
            elif len(names) > 2:
                del names[0]
            chost = '.'.join(names)
            ckey = '%s:%s' % (chost, cache_key.partition(':')[-1])
            keys = tuple(self.ssl_connection_cache.keys())
            for key in keys:
                if key not in self.ssl_connection_cache or\
                         '|' in key or not key.endswith(ckey):
                    continue
                cache = self.ssl_connection_cache[key]
                sock = get_cache_sock(cache)
                if sock:
                    if key != cache_key:
                        logging.warning(
                            '%s create_ssl_connection %r 尝试复用 %r 连接，'
                            '站点 %r 可能配置了多个子域名和较少的 IP。\n'
                            '可以尝试在 iplist 配置列表：\tcdn_%s = %s\n'
                            '然后在自动规则中使用此列表：\t%s$ = cdn_%s',
                            sock.xip[0], hostname, key, chost, chost, chost, chost, chost)
                    return sock

        sock = get_cache_sock()
        if sock:
            return sock

        result = None
        host, port = address
        addresses = [(x, port) for x in dns[hostname]]
        for i in range(self.max_retry):
            addresseslen = len(addresses)
            if getfast and gae_testgwsiplist:
                #按线程数量获取排序靠前的 IP
                addresses.sort(key=self.get_ssl_connection_time)
                addrs = addresses[:autorange_threads + 1]
            else:
                if addresseslen > self.max_window:
                    addresses.sort(key=self.get_ssl_connection_time)
                    window = min((self.max_window + 1)//2 + min(i, 1), addresseslen)
                    addrs = addresses[:window] + random.sample(addresses[window:], self.max_window-window)
                else:
                    addrs = addresses
            queobj = Queue()
            for addr in addrs:
                start_new_thread(self._create_ssl_connection, (addr, cache_key, host, queobj, forward, get_cache_sock))
            addrslen = len(addrs)
            for n in range(addrslen):
                result = queobj.get()
                if isinstance(result, Exception):
                    addr = result.xip
                    if addresseslen > 1:
                        #临时移除 badip
                        try:
                            addresses.remove(addr)
                            addresseslen -= 1
                        except ValueError:
                            pass
                    if i == n == 0:
                        if isinstance(result, LimiterFull):
                            sock = get_cache_sock_ex()
                            if sock:
                                return sock
                        else:
                            #only output first error
                            logging.warning('%s _create_ssl_connection %r 返回 %r，重试', addr[0], host, result)
                else:
                    if addrslen - n > 1:
                        cache = self.ssl_connection_cache[cache_key]
                        start_new_thread(self._cache_connection, (cache, addrslen-n-1, queobj))
                    return result
        if result:
            raise result

#    def __create_connection_withproxy(self, address, timeout=None, source_address=None, **kwargs):
#        host, port = address
#        logging.debug('__create_connection_withproxy connect (%r, %r)', host, port)
#        _, proxyuser, proxypass, proxyaddress = parse_proxy(self.proxy)
#        try:
#            try:
#                dns_resolve(host)
#            except (socket.error, OSError):
#                pass
#            proxyhost, _, proxyport = proxyaddress.rpartition(':')
#            sock = socket.create_connection((proxyhost, int(proxyport)))
#            if host in dns:
#                hostname = random.choice(dns[host])
#            elif host.endswith('.appspot.com'):
#                hostname = 'www.google.com'
#            else:
#                hostname = host
#            request_data = 'CONNECT %s:%s HTTP/1.1\r\n' % (hostname, port)
#            if proxyuser and proxypass:
#                request_data += 'Proxy-authorization: Basic %s\r\n' % base64.b64encode(('%s:%s' % (proxyuser, proxypass)).encode()).decode().strip()
#            request_data += '\r\n'
#            sock.sendall(request_data)
#            response = HTTPResponse(sock)
#            response.begin()
#            if response.status >= 400:
#                logging.error('__create_connection_withproxy return http error code %s', response.status)
#                sock = None
#            return sock
#        except Exception as e:
#            logging.error('__create_connection_withproxy error %s', e)
#            raise

#    def __create_ssl_connection_withproxy(self, address, timeout=None, source_address=None, **kwargs):
#        host, port = address
#        logging.debug('__create_ssl_connection_withproxy connect (%r, %r)', host, port)
#        try:
#            sock = self.__create_connection_withproxy(address, timeout, source_address)
#            ssl_sock = self.get_ssl_socket(sock)
#            ssl_sock._sock = sock
#            return ssl_sock
#        except Exception as e:
#            logging.error('__create_ssl_connection_withproxy error %s', e)
#            raise

    if GC.GAE_ENABLEPROXY:
        def get_gws_front(self, getfast=None):
            if len(GC.GAE_PROXYLIST) == 1:
                return GC.GAE_PROXYLIST[0]
            proxy_list = GC.GAE_PROXYLIST.copy()
            proxy_list.sort(key=self.get_gws_front_connection_time)
            if getfast:
                return proxy_list[0]
            else:
                return random.choice((proxy_list[0], random.choice(proxy_list[1:])))

        def get_gws_front_connection_time(self, addr):
            return self.gws_front_connection_time.get(addr, self.timeout)

        def get_gws_front_connection_time_ip(self, addr):
            return self.gws_front_connection_time['ip'].get(addr, 0)

        def create_gws_connection_withproxy(self, address, hostname, cache_key, getfast=None, **kwargs):
            proxy = self.get_gws_front(getfast)
            proxytype, proxyuser, proxypass, proxyaddress = parse_proxy(proxy)
            proxyhost, _, proxyport = proxyaddress.rpartition(':')
            ips = dns_resolve(proxyhost).copy()
            if ips:
                ipcnt = len(ips) 
            else:
                logging.error('create_gws_connection_withproxy 代理地址无法解析：%r', proxy)
                return
            if ipcnt > 1:
                #优先使用未使用 IP，之后按连接速度排序
                ips.sort(key=self.get_gws_front_connection_time_ip)
            proxyport = int(proxyport)
            ohost, port = address
            while ips:
                proxyip = ips.pop(0)
                ip = random.choice(dns[hostname])
                if proxytype:
                    proxytype = proxytype.upper()
                if proxytype not in socks.PROXY_TYPES:
                    proxytype = 'HTTP'
                proxy_sock = self.get_proxy_socket(proxyip, 8)
                proxy_sock.set_proxy(socks.PROXY_TYPES[proxytype], proxyip, proxyport, True, proxyuser, proxypass)
                start_time = mtime()
                try:
                    proxy_ssl_sock = self.get_ssl_socket(proxy_sock, ohost, ohost)
                    proxy_ssl_sock.settimeout(self.timeout)
                    #proxy_ssl_sock.set_connect_state()
                    proxy_ssl_sock.connect((ip, port))
                    proxy_ssl_sock.do_handshake()
                except Exception as e:
                    cost_time = self.timeout + 1 + random.random()
                    if ipcnt > 1:
                        self.gws_front_connection_time['ip'][proxyip] = cost_time
                    self.gws_front_connection_time[proxy] = cost_time
                    logging.error('create_gws_connection_withproxy 连接代理 [%s] 失败：%r', proxy, e)
                    continue
                else:
                    cost_time = mtime() - start_time
                    if ipcnt > 1:
                        self.gws_front_connection_time['ip'][proxyip] = cost_time
                    self.gws_front_connection_time[proxy] = cost_time
                proxy_ssl_sock.xip = proxyip, proxyport
                return proxy_ssl_sock

    def _request(self, sock, method, path, protocol_version, headers, payload, bufsize=8192):
        request_data = []
        request_data.append('%s %s %s' % (method, path, protocol_version))
        for k, v in headers.items():
            request_data.append('%s: %s' % (k.title(), v))
        #if self.proxy:
        #    _, username, password, _ = parse_proxy(self.proxy)
        #    if username and password:
        #        request_data += 'Proxy-Authorization: Basic %s\r\n' % base64.b64encode(('%s:%s' % (username, password)).encode()).decode().strip()
        request_data.append('\r\n')

        if hasattr(payload, 'read'):
            #避免发送多个小数据包
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, False)
            request_data = '\r\n'.join(request_data).encode()
            sock.sendall(request_data)
            try:
                #以下按原样转发
                readed = 0
                left_size = int(headers.get('Content-Length', 0))
                while True:
                    if left_size < 1:
                        break
                    data = payload.read(min(bufsize, left_size))
                    sock.sendall(data)
                    left_size -= len(data)
                    readed += len(data)
            finally:
                if payload.__class__.__name__ == '_PaddedFile':
                    payload.file.readed = readed
                else:
                    payload.readed = readed
            #为下个请求恢复无延迟发送
            sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
        else:
            request_data = '\r\n'.join(request_data).encode() + payload
            sock.sendall(request_data)

#        try:
#            response = HTTPResponse(sock, method=method)
#            response.begin()
#        except Exception as e:
            #这里有时会捕捉到奇怪的异常，找不到来源路径
            # py2 的 raise 不带参数会导致捕捉到错误的异常，但使用 exc_clear 或换用 py3 还是会出现
#            if hasattr(e, 'xip'):
                #logging.warning('4444 %r | %r | %r', sock.getpeername(), sock.xip, e.xip)
#                del e.xip
#            raise e
        response = HTTPResponse(sock, method=method)
        response.begin()

        response.xip =  sock.xip
        response.sock = sock
        return response

    def request(self, request_params, payload=b'', headers={}, bufsize=8192, connection_cache_key=None, getfast=None, realmethod=None, realurl=None):
        ssl = request_params.ssl
        address = request_params.host, request_params.port
        hostname = request_params.hostname
        method = request_params.command
        realmethod = realmethod or method
        url = request_params.url
        timeout = getfast or self.timeout
        has_content = realmethod in ('POST', 'PUT', 'PATCH')

        #有上传数据适当增加超时时间
        if has_content:
            timeout += 10
        #单 IP 适当增加超时时间
        elif len(dns[hostname]) == 1 and timeout < 5:
            timeout += 2
        if 'Host' not in headers:
            headers['Host'] = request_params.host
        if hasattr(payload, 'read'):
            pass
        elif payload:
            if isinstance(payload, str):
                payload = payload.encode()
            if 'Content-Length' not in headers:
                headers['Content-Length'] = str(len(payload))

        for i in range(self.max_retry):
            if not hasattr(payload, 'read') and hasattr(request_params, 'connection') and check_connection_dead(request_params.connection):
                raise socket.error(errno.ECONNABORTED, '本地连接已断开')
            remote = None
            ip = ''
            try:
                if ssl:
                    remote = self.create_ssl_connection(address, hostname, connection_cache_key, getfast=bool(getfast))
                else:
                    remote = self.create_connection(address, hostname, connection_cache_key)
                if remote:
                    remote.settimeout(timeout)
                    return self._request(remote, method, request_params.path, self.protocol_version, headers, payload, bufsize=bufsize)
            except Exception as e:
                if not realurl and isinstance(e, CertificateError):
                    raise
                if isinstance(e, LimiterFull):
                    if i < self.max_retry - 1:
                        continue
                    else:
                        logging.warning('request "%s %s" 失败：%r', realmethod, realurl or url, e)
                        raise
                if remote:
                    ip = remote.xip
                    remote.close()
                if hasattr(e, 'xip'):
                    if ssl and 'SSL' in str(e):
                        host = 'https://' + request_params.host
                        if unset_temp_fakesni(host):
                            logging.warning('%r 的 "FAKESNI" 临时规则不适用，已取消。', host)
                            continue
                    ip = e.xip
                    logging.warning('%s create_%sconnection %r 失败：%r', ip[0], 'ssl_' if ssl else '', realurl or url, e)
                elif ip:
                    e.xip = ip
                    logging.warning('%s _request "%s %s" 失败：%r', ip[0], realmethod, realurl or url, e)
                    if realurl:
                        self.ssl_connection_time[ip] = self.timeout + 1
                else:
                    logging.warning('request "%s %s" 失败：%r', realmethod, realurl or url, e)
                if not realurl and (e.args[0] in reset_errno or (remote and e.args[0] in bypass_errno)):
                    raise
                #确保不重复上传数据
                if has_content and remote:
                    return
                if 'timed out' in str(e):
                    timeout += 10

# Google video ip can act as Google Web Server if cipher suits not include
# RC4-SHA
# AES128-GCM-SHA256
# ECDHE-RSA-RC4-SHA
# ECDHE-RSA-AES128-GCM-SHA256
#不安全 cipher
# CBC
# AES128-SHA
# ECDHE-RSA-AES128-SHA
# https://docs.python.org/dev/library/ssl.html
# https://www.openssl.org/docs/manmaster/man1/openssl-ciphers.html
# 以下 GWS ciphers 设置用于 TLS v1.3 连接
gws_ciphers = (
    'TLSv1.3:'
    'ECDHE+AES256+AESGCM:'
    'ECDHE+AESGCM:'
    'ECDHE+HIGH:'
    'RSA+AES256+AESGCM:'
    'RSA+AESGCM:'
    'RSA+HIGH:'
    'HIGH:MEDIUM:'
    '!AES128-GCM-SHA256:'
    '!ECDHE-RSA-AES128-GCM-SHA256:'
    '!ECDHE-RSA-AES128-SHA:'
    '!TLSv1.0:!SSLv3:!SHA1:'
    '!aNULL:!eNULL:!EXPORT:!EXPORT40:!EXPORT56:!LOW:!CBC:!DSS:'
    '!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK'
    ).encode()

# max_window=4, timeout=8, proxy='', ssl_ciphers=None, max_retry=2
http_nor = HTTPUtil(os.path.join(cert_dir, 'cacerts'), res_ciphers, GC.LINK_WINDOW, GC.LINK_TIMEOUT, GC.proxy)
http_cfw = HTTPUtil(os.path.join(cert_dir, 'cacerts'), res_ciphers, GC.LINK_WINDOW, GC.CFW_TIMEOUT, GC.proxy)
http_gws = HTTPUtil(os.path.join(cert_dir, 'cacerts', 'gws.pem'), gws_ciphers, GC.LINK_WINDOW, GC.GAE_TIMEOUT, GC.proxy)
reset_method_list.append(http_nor.clear_all_connection_cache)
reset_method_list.append(http_cfw.clear_all_connection_cache)
reset_method_list.append(http_gws.clear_all_connection_cache)
