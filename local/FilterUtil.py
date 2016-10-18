# coding:utf-8

from collections import OrderedDict
from common import LRUCache
from GlobalConfig import GC
from FilterConfig import numToAct, numToSSLAct, ACTION_FILTERS

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
    return filter(path)

def get_action(url_parts):
    schemes = ('', url_parts.scheme)
    host = url_parts.netloc.rpartition(':')[0] if ':' in url_parts.netloc else url_parts.netloc
    path = url_parts.path[1:]
    try:
        filters = filters_cache[host]
        if isinstance(filters, tuple):
            return filters
        for filter in filters:
            if filters[filter][1] in schemes and match_path_filter(filter, path):
                return filters[filter][0]
    except KeyError:
        filter = None
        for filters in ACTION_FILTERS:
            if filters.action == 5: #FAKECERT
                continue
            for schemefilter, hostfilter, pathfilter, target in filters:
                if match_host_filter(hostfilter, host):
                    if host not in filters_cache.cache:
                        filters_cache[host] = OrderedDict()
                    if pathfilter not in filters_cache.cache[host]:
                        filters_cache.cache[host][pathfilter] = (numToAct[filters.action], target), schemefilter
                    if not filter and schemefilter in schemes and match_path_filter(pathfilter, path):
                        filter = numToAct[filters.action], target
        if filter:
            return filter
    filter = (numToAct[GC.FILTER_ACTION], ''), ''
    if host in filters_cache.cache:
        filters_cache.cache[host][''] = filter
    else:
        filters_cache[host] = filter[0]
    return filter[0]

def get_ssl_action(host):
    schemes = ('', 'https')
    try:
        return ssl_filters_cache[host]
    except KeyError:
        for filters in ACTION_FILTERS:
            for schemefilter, hostfilter, _, target in filters:
                if schemefilter in schemes and match_host_filter(hostfilter, host):
                    ssl_filters_cache[host] = filter = numToSSLAct[filters.action], target
                    return filter
        ssl_filters_cache[host] = filter = numToSSLAct[GC.FILTER_SSLACTION], ''
        return filter
