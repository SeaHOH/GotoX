# coding:utf-8

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
    ACTION_FILTERS
    )

filters_cache = LRUCache(64)
ssl_filters_cache = LRUCache(32)

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
                    #符合自动多线程时不使用临时 GAE 规则，仍尝试默认规则
                    #是否包含元组元素（媒体文件）
                    elif any(path.endswith(x) for x in GC.AUTORANGE_ENDSWITH):
                        return filter_DEF[2:]
                    else:
                        return TEMPGAE
                return action, target
    else:
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

def get_connect_action(ssl, host):
    schemes = ('', 'https' if ssl else 'http')
    if host in ssl_filters_cache:
        return ssl_filters_cache[host]
    else:
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
