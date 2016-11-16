# coding:utf-8

from time import time
from collections import OrderedDict
from .common import LRUCache
from .GlobalConfig import GC
from .FilterConfig import FAKECERT, numToAct, numToSSLAct, ACTION_FILTERS

filters_cache = LRUCache(64)
ssl_filters_cache = LRUCache(32)

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

def get_action(scheme, host, path):
    schemes = ('', scheme)
    key = scheme + host
    if key in filters_cache:
        #以缓存规则进行匹配
        filters = filters_cache[key]
        for filter, rule in filters.items():
            if rule[1] in schemes and match_path_filter(filter, path):
                #是否临时规则
                target = rule[0][1]
                if isinstance(target, float):
                    # 15 分钟后恢复默认规则
                    if time() - target > 900:
                        filters[filter] = (numToAct[GC.FILTER_ACTION], None), ''
                    #自动多线程不持续使用临时 GAE 规则，仍尝试默认设置
                    #不包含元组元素（媒体文件）
                    elif not any(x in path for x in GC.AUTORANGE_ENDSWITH):
                        return 'do_GAE', ''
                return rule[0]
    else:
        filter = None
        for filters in ACTION_FILTERS:
            if filters.action == FAKECERT:
                continue
            for schemefilter, hostfilter, pathfilter, target in filters:
                if schemefilter in schemes and match_host_filter(hostfilter, host):
                    #建立主机条目
                    if key not in filters_cache:
                        filters_cache[key] = OrderedDict()
                    #填充规则到缓存
                    if pathfilter not in filters_cache.cache[key]:
                        filters_cache.cache[key][pathfilter] = (numToAct[filters.action], target), schemefilter
                    #匹配第一个，后面忽略
                    if not filter and match_path_filter(pathfilter, path):
                        filter = numToAct[filters.action], target
        if filter:
            return filter
    #构建默认规则
    filter = (numToAct[GC.FILTER_ACTION], None), ''
    if key not in filters_cache:
        #只有一条规则使用普通字典
        filters_cache[key] = {}
    filters_cache[key][''] = filter
    return filter[0]

def get_ssl_action(ssl, host):
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
        #构建默认规则
        ssl_filters_cache[host] = filter = numToSSLAct[GC.FILTER_SSLACTION], None
        return filter
