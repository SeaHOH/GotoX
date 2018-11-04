# coding:utf-8

import os
import re
import threading
import logging
from functools import partial
from time import sleep
from .path import config_dir
from .compat import thread, ConfigParser
from .common import isip, isipv4, isipv6, classlist
from .GlobalConfig import GC

BLOCK     = 1
FORWARD   = 2
DIRECT    = 3
GAE       = 4
FAKECERT  = 5
PROXY     = 6
REDIRECT  = 7
IREDIRECT = 8

numToAct = {
    BLOCK     : 'do_BLOCK',
    FORWARD   : 'do_FORWARD',
    DIRECT    : 'do_DIRECT',
    REDIRECT  : 'do_REDIRECT',
    IREDIRECT : 'do_IREDIRECT',
    PROXY     : 'do_PROXY',
    FAKECERT  : 'do_DIRECT',
    GAE       : 'do_GAE',
}
numToSSLAct = {
    BLOCK     : 'do_FAKECERT',
    FORWARD   : 'do_FORWARD',
    DIRECT    : 'do_FAKECERT',
    REDIRECT  : 'do_FAKECERT',
    IREDIRECT : 'do_FAKECERT',
    PROXY     : 'do_PROXY',
    FAKECERT  : 'do_FAKECERT',
    GAE       : 'do_FAKECERT',
}
actToNum = {
    'BLOCK'     : BLOCK,
    'FORWARD'   : FORWARD,
    'DIRECT'    : DIRECT,
    'REDIRECT'  : REDIRECT,
    'IREDIRECT' : IREDIRECT,
    'PROXY'     : PROXY,
    'FAKECERT'  : FAKECERT,
    'GAE'       : GAE,
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

class actionfilterlist(list):

    CONFIG_FILENAME = os.path.join(config_dir, 'ActionFilter.ini')

    def __init__(self):
        list.__init__(self)
        self.readconfig()
        self.FILE_MTIME = os.path.getmtime(self.CONFIG_FILENAME)
        self.RESET = False
        thread.start_new_thread(self.check_modify, ())

    def readconfig(self):
        CONFIG = ConfigParser(inline_comment_prefixes=('#', ';'))
        CONFIG._optcre = re.compile(r'(?P<option>[^\s]+)(?P<vi>\s+=)?\s*(?P<value>.*)')
        CONFIG.read(self.CONFIG_FILENAME)

        sections = CONFIG.sections()
        order_sections = []
        for section in sections:
            try:
                order, action = isfiltername(section).group('order', 'action')
                order_sections.append((int(order), action, section))
            except:
                continue
        order_sections.sort(key=lambda x: x[0])
        self.clear()
        for order, action, section in order_sections:
            action = action.upper()
            if action not in actToNum:
                continue
            filters = classlist()
            filters.action = actToNum[action]
            for k, v in CONFIG.items(section):
                scheme = ''
                if k.find('://', 0, 9) > 0 :
                    scheme, _, k = k.partition('://')
                host, _, path = k.partition('/')
                if host and host[0] == '@':
                    host = re.compile(host[1:]).search
                else:
                    host = host.lower()
                if path and path[0] == '@':
                    path = re.compile(path[1:]).search
                if filters.action == FAKECERT and v and '*' not in v:
                    v = v.encode()
                if filters.action in (FORWARD, DIRECT):
                    if isempty(v):
                        v = None
                    elif '|' in v:
                        v = pickip(v.lower()) or None
                    elif isipuse(v):
                        v = [v]
                    elif isip(v) or not (v in GC.IPLIST_MAP or v.find('.') > 0):
                        v = None
                elif filters.action in (REDIRECT, IREDIRECT):
                    if v and v[0] == '!':
                        v = v[1:].lstrip(' \t')
                        mhost = False
                    else:
                        mhost = True
                    if '>>' in v:
                        patterns, _, replaces = v.partition('>>')
                        patterns = patterns.rstrip(' \t')
                        replaces = replaces.lstrip(' \t')
                        if ' ' in replaces:
                            raction, _, replaces = replaces.partition(' ')
                            if raction in ('forward', 'direct', 'gae'):
                                raction = 'do_' + raction.upper()
                            elif raction.startswith('proxy='):
                                raction = 'do_PROXY', raction[6:]
                            else:
                                raction = None
                            replaces = replaces.rstrip(' \t')
                        else:
                            raction = None
                        unquote = replaces[0] == '@'
                        if unquote:
                            replaces = replaces[1:].lstrip(' \t')
                        if patterns[0] == '@':
                            patterns = patterns[1:].lstrip(' \t')
                            rule = partial(re.compile(patterns).sub, replaces)
                        else:
                            rule = patterns, replaces, 1
                        v = rule, unquote, mhost, raction
                filters.append((scheme.lower(), host, path, v))
            self.append(filters)

    def check_modify(self):
        while True:
            sleep(1)
            if self.RESET:
                continue
            filemtime = os.path.getmtime(self.CONFIG_FILENAME)
            if filemtime > self.FILE_MTIME:
                try:
                    self.readconfig()
                    self.FILE_MTIME = filemtime
                    self.RESET = True
                except Exception as e:
                    logging.warning('%r 内容被修改，重新加载时出现错误，请检查后重新修改：\n%r', self.CONFIG_FILENAME, e)

ACTION_FILTERS = actionfilterlist()
