# coding:utf-8

#此脚本通过域名解析测试网络状态，不支持 UDP 的前端代理无法使用
#即使前置代理支持 UDP，还需要修改套接字使用代理

import os
import queue
import socket
import random
import dnslib
import logging
import collections
from time import time, sleep
from select import select
from threading import _start_new_thread as start_new_thread
from .net import isipv4, isipv6, get_wan_ipv6
from .path import get_dirname
from .util import spawn_loop
from local.GlobalConfig import GC

#网络测试要求稳定、快速，所以选国内的 DNS IP
dns_ips_v4 = (
    #电信 114
    #https://www.114dns.com/
    '114.114.114.114',
    '114.114.115.115',
    '114.114.114.110',
    '114.114.115.110',
    '114.114.114.119',
    '114.114.115.119',
    #阿里
    #http://www.alidns.com/
    '223.5.5.5',
    '223.6.6.6',
    #百度
    #http://dudns.baidu.com/intro/publicdns/
    '180.76.76.76',
    #腾讯 DNSPod
    #https://www.dnspod.cn/Products/Public.DNS
    '119.28.28.28',
    '119.29.29.29',
    '182.254.116.116',
    '182.254.118.118',
    #DNS 派
    #http://www.dnspai.com/public.html
    '101.226.4.6',
    '218.30.118.6',
    '123.125.81.6',
    '140.207.198.6',
    #OneDNS
    #http://www.onedns.net/
    '117.50.11.11',
    '117.50.22.22',
    '112.124.47.27',
    '114.215.126.16',
    #CNNIC SDNS
    #http://public.sdns.cn/emergency_services.shtml
    '1.2.4.8',
    '210.2.4.8',
    )
dns_ips_v6 = (
    #CFIEC
    #http://www.cfiec.net/dns/s/?978.html
    #http://www.chinaipv6.com.cn/
    '240c::6666',
    '240c::6644',
    #CNNIC
    '2001:dc7:1000::1',
    #清华大学 TUNA 协会
    #https://tuna.moe/help/dns/
    '2001:da8::666',
    #北京科技大学
    '2001:da8:208:10::6', #始终回应 REFUSED
    #上海交大
    #http://ipv6.sjtu.edu.cn/dns.php
    '2001:da8:8000:1:202:120:2:100', #始终回应 REFUSED
    '2001:da8:8000:1:202:120:2:101', #始终回应 REFUSED
    #北京邮电大学
    '2001:da8:202:10::36',
    '2001:da8:202:10::37',
    #百度
    #http://dudns.baidu.com/intro/publicdns/
    '2400:da00::6666',
    )
#用于 Teredo 隧道等
dns_ips_v6w = (
    #Google
    #https://developers.google.com/speed/public-dns/docs/using
    '2001:4860:4860::8888',
    '2001:4860:4860::8844',
    #OpenDNS
    #https://www.opendns.com/about/innovations/ipv6/
    '2620:119:35::35',
    '2620:119:53::53',
    #Cloudflare
    #https://developers.cloudflare.com/1.1.1.1/setting-up-1.1.1.1/
    '2606:4700:4700::1111',
    '2606:4700:4700::1001',
    #Quad9
    #https://www.quad9.net/faq/
    '2620:fe::fe',
    '2620:fe::9',
    #Neustar UltraDNS
    #https://www.security.neustar/digital-performance/dns-services/recursive-dns
    '2610:a1:1018::1',
    '2610:a1:1019::1',
    '2610:a1:1018::5',
    '2610:a1:1019::5',
    #'2610:a1:1018::2',
    #'2610:a1:1019::2',
    #'2610:a1:1018::3',
    #'2610:a1:1019::3',
    #'2610:a1:1018::4',
    #'2610:a1:1019::4',
    )

def read_domains(file):
    domains = set()
    with open(file, 'r') as fd:
        for line in fd:
            if line[:1] not in '#;':
                domain = line.strip()
                if domain:
                    domains.add(domain)
    return list(domains)

current_dir = get_dirname(__file__)
domains_file = os.path.join(current_dir, 'domains.txt')
domains = read_domains(domains_file)

class InternetActiveCheck:
    max_qdata_num = 256
    max_check_times = 0
    only_check_ip = None

    def __init__(self, type, domains=domains):
        self.in_check = False
        self.last_stat = None
        self.qdata = None
        self._dns_servers = None
        if type.lower() == 'ipv4':
            self.type = 'IPv4'
            self.set_dns_servers(dns_ips_v4)
        elif type.lower() == 'ipv6':
            self.type = 'IPv6'
            self.only_check_ip = GC.LINK_FASTV6CHECK
            self.set_dns_servers_v6()
            spawn_loop(10, self.set_dns_servers_v6)
        domains = domains.copy()
        random.shuffle(domains)
        del domains[self.max_qdata_num:]
        self.qdata_list = collections.deque(dnslib.DNSRecord.question(qname).pack() for qname in domains)
        self.sock = socket.socket(socket.AF_INET if self.type == 'IPv4' else socket.AF_INET6, socket.SOCK_DGRAM)

    def set_dns_servers(self, dns_ips):
        dns_servers = [(ip, 53) for ip in dns_ips]
        random.shuffle(dns_servers)
        self.max_check_times = len(dns_servers)
        self._dns_servers = dns_servers
        self.dns_servers = None

    def set_dns_servers_v6(self):
        addr6 = get_wan_ipv6()
        if addr6:
            if addr6.teredo:
                if self.type != 'IPv6 Teredo':
                    if self.type != 'IPv6':
                        logging.warning('检测到 IPv6 网络变动，当前使用 Teredo 隧道，IP：%s', addr6)
                    self.type = 'IPv6 Teredo'
                if not (self._dns_servers or self.only_check_ip):
                    self.set_dns_servers(dns_ips_v6w)
            elif addr6.sixtofour:
                if self.type != 'IPv6 6to4':
                    if self.type != 'IPv6':
                        logging.warning('检测到 IPv6 网络变动，当前使用 6to4 隧道，IP：%s', addr6)
                    self.type = 'IPv6 6to4'
                if not (self._dns_servers or self.only_check_ip):
                    self.set_dns_servers(dns_ips_v6w)
            else:
                if self.type != 'IPv6 Global':
                    if self.type != 'IPv6':
                        logging.warning('检测到 IPv6 网络变动，当前使用原生网络，IP：%s', addr6)
                    self.type = 'IPv6 Global'
                if not (self._dns_servers or self.only_check_ip):
                    self.set_dns_servers(dns_ips_v6)
            if self.only_check_ip and self.last_stat != 1:
                if self.last_stat is not None:
                    logging.warning('IPv6 网络恢复连接')
                self.last_stat = 1
        else:
            if self.only_check_ip and self.last_stat != 0:
                logging.error('IPv6 网络现在不可用，将每 10 秒检测一次……')
            self.last_stat = 0
            self._dns_servers = None
            return

    def is_active(self, keep_on=None):
        if self.only_check_ip:
            while keep_on and not self.last_stat:
                sleep(5)
            return self.last_stat

        time_pass = 0
        while self.in_check:
            sleep(0.01)
            time_pass += 0.01
            if time_pass > 10:
                if not keep_on:
                    break
                time_pass = 0.01
        if time_pass:
            return self.last_stat
        
        self.in_check = True
        ok = None
        haserr = None
        ins = True
        sent = []
        check_times = 0
        #清理过期响应
        while ins:
            ins, _, _ = select([self.sock], [], [], 0)
            if ins:
                self.sock.recvfrom(512)
        while ok is None:
            check_times += 1
            if check_times > self.max_check_times:
                if not haserr:
                    if not keep_on:
                        ok = False
                        break
                    haserr = True
                    try:
                        keep_on = abs(int(keep_on))
                    except:
                        keep_on = 10
                    logging.error('%s 网络现在不可用，将每 %d 秒检测一次……', self.type, keep_on)
                sleep(keep_on)
            if self._dns_servers is None:
                check_times = self.max_check_times
                continue
            if not self.dns_servers:
                self.dns_servers = self._dns_servers.copy()
                self.qdata = self.qdata_list.pop()
                self.qdata_list.appendleft(self.qdata)
            dns_server = self.dns_servers.pop()
            try:
                self.sock.sendto(self.qdata, dns_server)
                sent.append(dns_server)
                ins, _, _ = select([self.sock], [], [], 0.5)
                if ins:
                    _, peername = self.sock.recvfrom(512)
                    if peername[:2] in sent:
                        ok = True
            except:
                pass
        self.last_stat = int(ok is True)
        self.in_check = False
        if haserr:
            logging.warning('%s 网络恢复连接', self.type)
        return self.last_stat

internet_v4 = InternetActiveCheck('ipv4')
internet_v6 = InternetActiveCheck('ipv6')

qobj_cache = queue.deque()

def _is_active(type, qobj, keep_on):
    if type == 4:
        stat = internet_v4.is_active(keep_on)
    elif type == 6:
        stat = internet_v6.is_active(keep_on)
    qobj.put(stat)

def is_active(type='ipv4', keep_on=None):
    stat = 1
    n = 0
    try:
        qobj = qobj_cache.pop()
        qobj.queue.clear()
    except IndexError:
        qobj = queue.LifoQueue()
    if type.lower() in ('ipv4', 'ipv46') or isipv4(type):
        start_new_thread(_is_active, (4, qobj, keep_on))
        n += 1
    if type.lower() in ('ipv6', 'ipv46') or isipv6(type):
        start_new_thread(_is_active, (6, qobj, keep_on))
        n += 1
    for _ in range(n):
        _stat = qobj.get()
        if _stat and keep_on:
            return _stat
        stat &= _stat
    qobj_cache.append(qobj)
    if n:
        return stat
    else:
        logging.error('is_active：错误的 type 参数：%s', type)
