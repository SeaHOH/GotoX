# coding:utf-8

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
    if host in filters_cache:
        #以缓存规则进行匹配
        filters = filters_cache[host]
        for filter in filters:
            if filters[filter][1] in schemes and match_path_filter(filter, path):
                #是否默认或临时规则
                if filter == '':
                    action, target = filters[filter][0]
                    #临时 GAE 规则不包含元组元素（媒体文件）
                    if action == numToAct[GC.FILTER_ACTION] and isinstance(target, tuple) and not any(x in path for x in target):
                        return 'do_GAE', ''
                return filters[filter][0]
    else:
        filter = None
        for filters in ACTION_FILTERS:
            if filters.action == FAKECERT:
                continue
            for schemefilter, hostfilter, pathfilter, target in filters:
                if match_host_filter(hostfilter, host):
                    #建立主机条目
                    if host not in filters_cache:
                        filters_cache[host] = OrderedDict()
                    #填充规则到缓存
                    if pathfilter not in filters_cache.cache[host]:
                        filters_cache.cache[host][pathfilter] = (numToAct[filters.action], target), schemefilter
                    #匹配第一个，后面忽略
                    if not filter and schemefilter in schemes and match_path_filter(pathfilter, path):
                        filter = numToAct[filters.action], target
        if filter:
            return filter
    #构建默认规则
    filter = (numToAct[GC.FILTER_ACTION], None), ''
    if host not in filters_cache:
        #只有一条规则使用普通字典
        filters_cache[host] = {}
    filters_cache[host][''] = filter
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
