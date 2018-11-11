# coding:utf-8
#此脚本通过域名解析测试网络状态，不支持 UDP 的前端代理无法使用

import os
import socket
import random
import dnslib
import logging
import collections
from time import sleep
from select import select
from . import isipv4, isipv6

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

def read_domains(file):
    domains = set()
    with open(file, 'r') as fd:
        for line in fd:
            if line[0] not in '#;':
                domain = line.strip()
                if domain:
                    domains.add(domain)
    return list(domains)

current_dir = os.path.dirname(os.path.abspath(__file__))
domains_file = os.path.join(current_dir, 'domains.txt')
domains = read_domains(domains_file)

class InternetActiveCheck:
    max_qdata_num = 256

    def __init__(self, dns_ips, domains):
        ip = dns_ips[0]
        if isipv4(ip):
            self.type = 'IPv4'
        elif isipv6(ip):
            self.type = 'IPv6'
        else:
            raise TypeError('%s 参数错误：dns_ips[0]=%r' % (self.__class__, ip))
        #生成乱序 DNS 服务器列表
        dns_servers = [(ip, 53) for ip in dns_ips]
        random.shuffle(dns_servers)
        self.max_check_times = len(dns_servers)
        self._dns_servers = dns_servers
        self.dns_servers = None
        #生成 A 类型 DNS 请求数据列表
        random.shuffle(domains)
        del domains[self.max_qdata_num:]
        self.qdata_list = collections.deque(dnslib.DNSRecord.question(qname).pack() for qname in domains)
        self.qdata = None
        #生成测试用 UDP 套接字
        self.sock = socket.socket(socket.AF_INET if self.type == 'IPv4' else socket.AF_INET6, socket.SOCK_DGRAM)
        self.in_check = False
        self.last_stat = None

    def is_active(self, keep_on=None):
        if self.in_check:
            while self.in_check:
                sleep(0.01)
            if not keep_on:
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
        #通过域名解析测试网络状态
        while ok is None:
            check_times += 1
            if check_times > self.max_check_times:
                if not haserr:
                    #发生网络故障
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
            if not self.dns_servers:
                #更换下一个域名的请求数据
                self.dns_servers = self._dns_servers.copy()
                self.qdata = self.qdata_list.pop()
                self.qdata_list.appendleft(self.qdata)
            dns_server = self.dns_servers.pop()
            sent.append(dns_server)
            self.sock.sendto(self.qdata, dns_server)
            ins, _, _ = select([self.sock], [], [], 0.5)
            if ins:
                try:
                    _, peername = self.sock.recvfrom(512)
                    if peername[:2] in sent:
                        ok = True
                except:
                    pass
        self.last_stat = int(ok is True)
        self.in_check = False
        return self.last_stat

internet_v4 = InternetActiveCheck(dns_ips_v4, domains)
internet_v6 = InternetActiveCheck(dns_ips_v6, domains)

def is_active(type='ipv4', keep_on=None):
    stat_v4 = stat_v6 = None
    if type.lower() in ('ipv4', 'ipv46') or isipv4(type):
        stat_v4 = internet_v4.is_active(keep_on)
    if type.lower() in ('ipv6', 'ipv46') or isipv6(type):
        stat_v6 = internet_v6.is_active(keep_on)
    if stat_v4 is None and stat_v6 is None:
        logging.error('is_active：错误的 type：%s', type)
    elif stat_v4 is None:
        return stat_v6
    elif stat_v6 is None:
        return stat_v4
    else:
        return stat_v4 and stat_v6
