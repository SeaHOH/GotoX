# coding:utf-8

import threading
import logging
from time import mtime, sleep
from functools import partial
from urllib import parse
from .common.dns import reset_dns
from .common.net import random_hostname
from .common.path import config_dir
from .common.util import LRUCache
from .GlobalConfig import GC
from .FilterConfig import (
    FAKECERT,
    numToAct,
    numToSSLAct,
    ACTION_FILTERS as _ACTION_FILTERS
    )

gLock = threading.Lock()
gn = 0
ACTION_FILTERS = _ACTION_FILTERS.copy()
filters_cache = LRUCache(256)
ssl_filters_cache = LRUCache(128)
reset_method_list = [reset_dns]

def check_reset():
    if _ACTION_FILTERS.RESET:
        while _ACTION_FILTERS.RESET and gn > 0:
            sleep(0.001)
        else:
            with gLock:
                if gn == 0 and _ACTION_FILTERS.RESET:
                    global ACTION_FILTERS
                    ACTION_FILTERS = _ACTION_FILTERS.copy()
                    filters_cache.clear()
                    ssl_filters_cache.clear()
                    for reset_method in reset_method_list:
                        reset_method()
                    _ACTION_FILTERS.RESET = False
                    logging.warning('%r 内容被修改，已重新加载自动代理配置。', _ACTION_FILTERS.CONFIG_FILENAME)

def get_fake_sni(host):
    if not isinstance(host, str):
        return False
    action, rule = get_connect_action(True, host)
    if action == 'do_FAKECERT':
        if isinstance(rule, bytes):
            return None if rule == b'@none' else rule
        elif isinstance(rule, str):
            return random_hostname(None if rule == '*' else rule).encode()
    return False

def get_redirect(target, url):
    '''Get the redirect target'''
    rule, unquote, mhost, raction = target
    if isinstance(rule, str):
        return rule, (mhost, None)
    elif isinstance(rule, partial):
        url = rule(url, 1)
    elif isinstance(rule, tuple):
        url = url.replace(*rule)
    else:
        logging.error('%r 匹配重定向规则 %r，解析错误，请检查你的配置文件："%s/ActionFilter.ini"', url, target, config_dir)
        return
    return parse.unquote(url) if unquote else url, (mhost, raction)

def match_host_filter(filter, host):
    if isinstance(filter, str):
        if filter:
            if filter[0] == '^':
                if filter[-1] == '$':
                    return host == filter[1:-1]
                return host.startswith(filter[1:])
            if filter[-1] == '$':
                return host.endswith(filter[:-1])
            if '.' in filter:
                if filter[-1] != '.':
                    if filter[0] == '.':
                        return host.endswith(filter)
                    return host == filter
                if filter[0] != '.':
                    return host.startswith(filter)
        return filter in host
    return filter(host)

def match_path_filter(filter, path):
    if isinstance(filter, str):
        if filter:
            if filter[0] == '^':
                if filter[-1] == '$':
                    return path == filter[1:-1]
                return path.startswith(filter[1:])
            if filter[-1] == '$':
                return path.endswith(filter[:-1])
        else:
            return True
        return filter in path
    return filter(path)

REDIRECTS = 'do_REDIRECT', 'do_IREDIRECT'
TEMPGAE = 'do_GAE', None
#默认规则
filter_DEF = '', numToAct[GC.FILTER_ACTION], None
ssl_filter_DEF = numToSSLAct[GC.FILTER_SSLACTION], None

def set_temp_action(host):
    #将临时规则插入缓存规则中第一个位置
    try:
        filters = filters_cache[host]
    except KeyError:
        filters_cache[host] = filters = [filter_DEF]
    action = filters[0][1]
    if action != 'TEMPGAE':
        filter = '', 'TEMPGAE', mtime() + GC.LINK_TEMPTIME
        filters.insert(0, filter)
        return True

def set_temp_connect_action(host):
    #将缓存规则替换为临时规则
    filter = ssl_filters_cache[host]
    action = filter[0]
    if action != 'do_FAKECERT':
        ssl_filters_cache.set(host, ('do_FAKECERT', filter), GC.LINK_TEMPTIME)
        return True

def get_action(scheme, host, path, url):
    check_reset()
    schemes = '', scheme
    key = '%s://%s' % (scheme, host)
    filters = filters_cache.gettill(key)
    if filters:
        #是否临时规则
        _, action, expire = filters[0]
        if action is 'TEMPGAE':
            if mtime() > expire:
                del filters[0]
                logging.warning('%r 的临时 "GAE" 规则已经失效。', key)
            #符合自动多线程时不使用临时 GAE 规则，仍尝试默认规则
            #是否包含元组元素（媒体文件）
            elif not any(path.endswith(x) for x in GC.AUTORANGE_FAST_ENDSWITH):
                return TEMPGAE
        #以缓存规则进行匹配
        for pathfilter, action, target in filters:
            if action is 'TEMPGAE':
                continue
            if match_path_filter(pathfilter, path):
                #计算重定向网址
                if action in REDIRECTS:
                    target = get_redirect(target, url)
                    if target is not None:
                        durl, mhost = target
                        if durl and durl != url:
                            return action, target
                    continue
                return action, target
    global gn
    try:
        with gLock:
            gn += 1
        filter = None
        #建立缓存条目
        filters_cache.setpadding(key)
        _filters = []
        for filters in ACTION_FILTERS:
            if filters.action == FAKECERT:
                continue
            for schemefilter, hostfilter, pathfilter, target in filters:
                if schemefilter in schemes and match_host_filter(hostfilter, host):
                    action = numToAct[filters.action]
                    #填充规则到缓存
                    _filters.append((pathfilter, action, target))
                    #匹配第一个，后面忽略
                    if not filter and match_path_filter(pathfilter, path):
                        #计算重定向网址
                        if action in REDIRECTS:
                            target = get_redirect(target, url)
                            if target is not None:
                                durl, mhost = target
                                if durl and durl != url:
                                    filter = action, target
                        else:
                            filter = action, target
        #添加默认规则
        _filters.append(filter_DEF)
        filters_cache[key] = _filters
        return filter or filter_DEF[1:]
    finally:
        with gLock:
            gn -= 1

def get_connect_action(ssl, host):
    check_reset()
    scheme = 'https' if ssl else 'http'
    schemes = '', scheme
    key = '%s://%s' % (scheme, host)
    contains, expired, filter = ssl_filters_cache.getstate(key)
    if contains:
        if expired:
            logging.warning('%r 的临时 "FAKECERT" 规则已经失效。', key)
            ssl_filters_cache[key] = filter = filter[1]
        else:
            filter = ssl_filters_cache.gettill(key)
        return filter
    global gn
    try:
        with gLock:
            gn += 1
        ssl_filters_cache.setpadding(key)
        for filters in ACTION_FILTERS:
            for schemefilter, hostfilter, _, target in filters:
                if schemefilter in schemes and match_host_filter(hostfilter, host):
                    #填充结果到缓存
                    ssl_filters_cache[key] = filter = numToSSLAct[filters.action], target
                    #匹配第一个，后面忽略
                    return filter
        #添加默认规则
        ssl_filters_cache[key] = ssl_filter_DEF
        return ssl_filter_DEF
    finally:
        with gLock:
            gn -= 1
