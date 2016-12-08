# coding:utf-8

import threading
from time import time
from functools import partial
from . import clogging as logging
from .common import config_dir, LRUCache
from .compat import urlparse
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
filters_cache = LRUCache(64)
ssl_filters_cache = LRUCache(32)

def check_reset():
    with gLock:
        if gn == 0 and _ACTION_FILTERS.RESET:
            global ACTION_FILTERS
            _ACTION_FILTERS.RESET = False
            ACTION_FILTERS = _ACTION_FILTERS.copy()
            filters_cache.clear()
            ssl_filters_cache.clear()
            logging.info('%r 内容被修改，已重新加载配置。', _ACTION_FILTERS.CONFIG_FILENAME)

def get_redirect(target, url):
    '''Get the redirect target'''
    rule = target[0]
    if isinstance(rule, partial):
        url = rule(url, 1)
    elif isinstance(rule, tuple):
        url = url.replace(*rule)
    elif isinstance(target, str) and target.find('://') < 9:
        return target
    else:
        logging.error(u'%r 匹配重定向规则 %r，解析错误，请检查你的配置文件："%s/ActionFilter.ini"', url, target, config_dir)
        return
    return urlparse.unquote(url) if target[1] else url

def match_host_filter(filter, host):
    if isinstance(filter, str):
        if '.' not in filter:
            return filter in host
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
        return filter in path
    return filter(path)

REDIRECTS = ('do_REDIRECT', 'do_IREDIRECT')
TEMPGAE = 'do_GAE', None
#默认规则
filter_DEF = '', '', numToAct[GC.FILTER_ACTION], None
ssl_filter_DEF = numToSSLAct[GC.FILTER_SSLACTION], None

def get_action(scheme, host, path, url):
    check_reset()
    schemes = ('', scheme)
    key = scheme + host
    filters = filters_cache.get(key)
    if filters:
        #以缓存规则进行匹配
        for schemefilter, pathfilter, action, target in filters:
            if schemefilter in schemes and match_path_filter(pathfilter, path):
                #计算重定向网址
                if action in REDIRECTS:
                    durl = get_redirect(target, url)
                    if durl and durl != url:
                        return action, durl
                    else:
                        continue
                #是否临时规则
                if action == 'TEMPGAE':
                    # 15 分钟后恢复默认规则
                    if time() - target > 900:
                        filters[-1] = filter_DEF
                        return filter_DEF[2:]
                    #符合自动多线程时不使用临时 GAE 规则，仍尝试默认规则
                    #是否包含元组元素（媒体文件）
                    elif any(path.endswith(x) for x in GC.AUTORANGE_ENDSWITH):
                        return filter_DEF[2:]
                    else:
                        return TEMPGAE
                return action, target
    else:
        global gn
        try:
            with gLock:
                gn += 1
            filter = None
            #建立缓存条目
            filters_cache[key] = []
            for filters in ACTION_FILTERS:
                if filters.action == FAKECERT:
                    continue
                for schemefilter, hostfilter, pathfilter, target in filters:
                    if schemefilter in schemes and match_host_filter(hostfilter, host):
                        action = numToAct[filters.action]
                        #填充规则到缓存
                        filters_cache.cache[key].append((schemefilter, pathfilter, action, target))
                        #匹配第一个，后面忽略
                        if not filter and match_path_filter(pathfilter, path):
                            #计算重定向网址
                            if action in REDIRECTS:
                                durl = get_redirect(target, url)
                                if durl and durl != url:
                                    filter = action, durl
                            else:
                                filter = action, target
            #添加默认规则
            filters_cache.cache[key].append(filter_DEF)
            return filter or filter_DEF[2:]
        finally:
            with gLock:
                gn -= 1

def get_connect_action(ssl, host):
    check_reset()
    schemes = ('', 'https' if ssl else 'http')
    if host in ssl_filters_cache:
        return ssl_filters_cache[host]
    else:
        global gn
        try:
            with gLock:
                gn += 1
            for filters in ACTION_FILTERS:
                for schemefilter, hostfilter, _, target in filters:
                    if schemefilter in schemes and match_host_filter(hostfilter, host):
                        #填充结果到缓存
                        ssl_filters_cache[host] = filter = numToSSLAct[filters.action], target
                        #匹配第一个，后面忽略
                        return filter
            #添加默认规则
            ssl_filters_cache[host] = ssl_filter_DEF
            return ssl_filter_DEF
        finally:
            with gLock:
                gn -= 1
