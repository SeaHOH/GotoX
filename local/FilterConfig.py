# coding:utf-8

import os
import re
import logging
from functools import partial
from time import sleep
from configparser import ConfigParser
from threading import _start_new_thread as start_new_thread
from .common.net import isip, isipv4, isipv6
from .common.path import config_dir
from .GlobalConfig import GC

BLOCK     = 1
FORWARD   = 2
DIRECT    = 3
FAKECERT  = 4
GAE       = 5
CFW       = 6
PROXY     = 7
REDIRECT  = 8
IREDIRECT = 9

numToAct = {
    BLOCK     : 'do_BLOCK',
    FORWARD   : 'do_FORWARD',
    DIRECT    : 'do_DIRECT',
    FAKECERT  : 'do_DIRECT',
    GAE       : 'do_GAE',
    CFW       : 'do_CFW',
    PROXY     : 'do_PROXY',
    REDIRECT  : 'do_REDIRECT',
    IREDIRECT : 'do_IREDIRECT',
}
numToSSLAct = {
    BLOCK     : 'do_FAKECERT',
    FORWARD   : 'do_FORWARD',
    DIRECT    : 'do_FAKECERT',
    FAKECERT  : 'do_FAKECERT',
    GAE       : 'do_FAKECERT',
    CFW       : 'do_FAKECERT',
    PROXY     : 'do_PROXY',
    REDIRECT  : 'do_FAKECERT',
    IREDIRECT : 'do_FAKECERT',
}
actToNum = {
    'BLOCK'     : BLOCK,
    'FORWARD'   : FORWARD,
    'DIRECT'    : DIRECT,
    'FAKECERT'  : FAKECERT,
    'GAE'       : GAE,
    'CFW'       : CFW,
    'PROXY'     : PROXY,
    'REDIRECT'  : REDIRECT,
    'IREDIRECT' : IREDIRECT,
}

isfiltername = re.compile(r'(?P<order>\d+)-(?P<action>\w+)').match
isempty = re.compile(r'^\s*$').match
if GC.LINK_PROFILE == 'ipv4':
    pickip = lambda str: [ip.strip() for ip in str.split('|') if isipv4(ip.strip())]
    isipuse = isipv4
elif GC.LINK_PROFILE == 'ipv46':
    pickip = lambda str: [ip.strip() for ip in str.split('|') if isip(ip.strip())]
    isipuse = isip
elif GC.LINK_PROFILE == 'ipv6':
    pickip = lambda str: [ip.strip() for ip in str.split('|') if isipv6(ip.strip())]
    isipuse = isipv6

class ACTION_FILTERS:

    CONFIG_FILENAME = os.path.join(config_dir, 'ActionFilter.ini')
    CONFIG = ConfigParser(inline_comment_prefixes=('#', ';'))
    CONFIG._optcre = re.compile(r'(?P<option>[^\s]+)(?P<vi>\s+=)?\s*(?P<value>.*)')

    def __init__(self):
        self.readconfig()
        self.mtime = os.path.getmtime(self.CONFIG_FILENAME)
        self.reset = False
        start_new_thread(self.check_modify, ())

    def readconfig(self):
        self.CONFIG.read(self.CONFIG_FILENAME)

        order_sections = []
        for section in self.CONFIG._sections:
            try:
                order, action = isfiltername(section).group('order', 'action')
                order_sections.append((int(order), action, section))
            except:
                continue
        order_sections.sort(key=lambda x: x[0])
        self.config = []
        for order, action, section in order_sections:
            action = action.upper()
            if action not in actToNum:
                continue
            filters = classlist()
            filters.action = actToNum[action]
            for k, v in self.CONFIG._sections[section].items():
                scheme = ''
                if k.find('://', 0, 9) > 0 :
                    scheme, _, k = k.partition('://')
                host, _, path = k.partition('/')
                if host[:1] == '@':
                    host = re.compile(host[1:]).search
                else:
                    host = host.lower()
                if path[:1] == '@':
                    path = re.compile(path[1:]).search
                v = v.rstrip()
                if filters.action in (FAKECERT, CFW):
                    if not v:
                        v = None
                elif filters.action in (BLOCK, GAE):
                    v = None
                elif filters.action in (FORWARD, DIRECT):
                    if v[:1] == '@':
                        p, _, v = v.partition(' ')
                    else:
                        p = None
                    if isempty(v):
                        v = None
                    elif '|' in v:
                        v = pickip(v.lower()) or None
                    elif isipuse(v):
                        v = [v]
                    elif isip(v) or not (v in GC.IPLIST_MAP or v.find('.') > 0):
                        v = None
                    v = v, p
                elif filters.action in (REDIRECT, IREDIRECT):
                    if v[:1] == '!':
                        v = v[1:].lstrip()
                        mhost = False
                    else:
                        mhost = True
                    if '>>' in v:
                        patterns, _, replaces = v.partition('>>')
                        patterns = patterns.rstrip()
                        replaces = replaces.lstrip()
                        if ' ' in replaces:
                            raction, _, replaces = replaces.partition(' ')
                            if raction in ('forward', 'direct', 'gae'):
                                raction = 'do_' + raction.upper()
                            elif raction.startswith('proxy='):
                                raction = 'do_PROXY', raction[6:]
                            else:
                                raction = None
                            replaces = replaces.rstrip()
                        else:
                            raction = None
                        unquote = replaces[:1] == '@'
                        if unquote:
                            replaces = replaces[1:].lstrip()
                        if patterns[:1] == '@':
                            patterns = patterns[1:].lstrip()
                            rule = partial(re.compile(patterns).sub, replaces)
                        else:
                            rule = patterns, replaces, 1
                        v = rule, unquote, mhost, raction
                    else:
                        v = v, None, mhost, None
                filters.append((scheme.lower(), host, path, v))
            self.config.append(filters)

        self.CONFIG._sections.clear()
        self.CONFIG._proxies.clear()

    def check_modify(self):
        while True:
            sleep(1)
            if self.reset:
                continue
            mtime = os.path.getmtime(self.CONFIG_FILENAME)
            if mtime > self.mtime:
                try:
                    self.readconfig()
                    self.mtime = mtime
                    self.reset = True
                except Exception as e:
                    logging.warning('%r 内容被修改，重新加载时出现错误，请检查后重新修改：\n%r', self.CONFIG_FILENAME, e)

action_filters = ACTION_FILTERS()
