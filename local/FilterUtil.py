# coding:utf-8

from collections import OrderedDict
from .common import LRUCache
from .GlobalConfig import GC
from .FilterConfig import FAKECERT, numToAct, numToSSLAct, ACTION_FILTERS

filters_cache = LRUCache(256)
ssl_filters_cache = LRUCache(64)

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
    #不包含元组元素（媒体文件）
    elif isinstance(filter, tuple):
        return not any(x in path for x in filter)
    return filter(path)

def get_action(scheme, host, path):
    schemes = ('', scheme)
    #除去主机部分
    path = path[path.find('//')+3:]
    path = path[path.find('/')+1:]
    if host in filters_cache:
        filters = filters_cache[host]
        if isinstance(filters, tuple):
            return filters
        for filter in filters:
            if filters[filter][1] in schemes and match_path_filter(filter, path):
                return filters[filter][0]
    else:
        filter = None
        for filters in ACTION_FILTERS:
            if filters.action == FAKECERT:
                continue
            for schemefilter, hostfilter, pathfilter, target in filters:
                if match_host_filter(hostfilter, host):
                    if host not in filters_cache:
                        filters_cache[host] = OrderedDict()
                    if pathfilter not in filters_cache.cache[host]:
                        filters_cache.cache[host][pathfilter] = (numToAct[filters.action], target), schemefilter
                    if not filter and schemefilter in schemes and match_path_filter(pathfilter, path):
                        filter = numToAct[filters.action], target
        if filter:
            return filter
    filter = (numToAct[GC.FILTER_ACTION], None), ''
    if host in filters_cache:
        filters_cache[host][''] = filter
    else:
        filters_cache[host] = filter[0]
    return filter[0]

def get_ssl_action(host):
    schemes = ('', 'https')
    if host in ssl_filters_cache:
        return ssl_filters_cache[host]
    else:
        for filters in ACTION_FILTERS:
            for schemefilter, hostfilter, _, target in filters:
                if schemefilter in schemes and match_host_filter(hostfilter, host):
                    ssl_filters_cache[host] = filter = numToSSLAct[filters.action], target
                    return filter
        ssl_filters_cache[host] = filter = numToSSLAct[GC.FILTER_SSLACTION], None
        return filter
