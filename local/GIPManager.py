# coding:utf-8
'''Auto check and update google IPs'''

import os
import logging
import random
import socket
import collections
from shutil import copyfile
from copy import deepcopy
from time import time, sleep, localtime, strftime
from threading import _start_new_thread as start_new_thread
from .common.internet_active import internet_v4, internet_v6
from .common.net import NetWorkIOError, random_hostname, isip, isipv4, isipv6
from .common.decorator import make_lock_decorator
from .common.path import data_dir
from .common.util import LimiterFull
from .compat.openssl import zero_errno, zero_EOF_error, CertificateError
from .HTTPUtil import http_gws
from .ProxyServer import network_test
from .GlobalConfig import GC

#连接超时设置，单位：秒
g_timeout = 5
g_conntimeout = 1.5
g_handshaketimeout = 3

def get_index_1(o):
    return o[1]

def clear_zero_file(file):
    if os.path.isfile(file) and os.path.getsize(file) == 0:
        os.remove(file)

def exists(file):
    clear_zero_file(file)
    return os.path.exists(file)

def getmtime(file):
    st = os.stat(file)
    return max(st.st_mtime, st.st_ctime)

def backup_file(file, bak_file=None, no_copy=None):
    if exists(file):
        if bak_file is None:
            bak_file = file + '.bak'
        if no_copy:
            if exists(bak_file):
                os.remove(bak_file)
            os.rename(file, bak_file)
        else:
            copyfile(file, bak_file)

def restore_file(file, bak_file=None):
    if not exists(file):
        if bak_file is None:
            bak_file = file + '.bak'
        if exists(bak_file):
            copyfile(bak_file, file)

def get_littery_list(iter):
    l = list(iter)
    random.shuffle(l)
    return l

if GC.LINK_PROFILE == 'ipv4':
    is_ip_use = isipv4
elif GC.LINK_PROFILE == 'ipv6':
    is_ip_use = isipv6
elif GC.LINK_PROFILE == 'ipv46':
    is_ip_use = isip

_lock_file_source = make_lock_decorator()
_lock_file_stat = make_lock_decorator()
_lock_log_stat = make_lock_decorator(rlock=True)
_lock_get_ip = make_lock_decorator()
_lock_save_use = make_lock_decorator()
_lock_remove_slow = make_lock_decorator()
_lock_pick_worker = make_lock_decorator()


class IPSource:
    ip_file = os.path.join(data_dir, 'ip.txt')
    ip_file_ex = os.path.join(data_dir, 'ip_ex.txt')
    ip_file_bad = os.path.join(data_dir, 'ip_bad')
    ip_file_del = os.path.join(data_dir, 'ip_del.txt')
    ip_stat_split = '|'
    ex_del_min = 60 * 60 * 2
    ex_del_max = 60 * 60 * 12
    time_to_reload = 60 * 60 * 8
    save_stat_interval = 60 * 15
    save_per_log_stat = 200
    save_stat_bad_interval = 60 * 15
    save_per_log_stat_bad = 20

    def __init__(self):
        now = time()
        self.logger = logging.getLogger('[ip source]')
        self.log_stat_times = 0
        self.log_stat_bad_times = 0
        self.ip_mtime = 0
        self.ip_mtime_ex = 0
        self.ip_mtime_ex_start_time = 0
        self.ip_stat_block = {}
        self.ip_stat_files = []
        self.ip_set_bad = set()
        self.ip_set_assoeted = set()
        self.save_stat_time = now
        self.save_stat_bad_time = now
        self.update_time = now
        self.load_config()
        self.load_stat_bad()
        self.load_source()

    def load_config(self):
        self.block_prefixs = GC.PICKER_BLOCK
        self.stat_days = GC.PICKER_STATDAYS
        self.block_time = GC.PICKER_BLOCKTIME * 60 * 60
        self.fail_times_to_block = GC.PICKER_TIMESBLOCK
        self.block_times_to_del = GC.PICKER_TIMESDEL
        self.del_assoeted_ip = GC.PICKER_DELASSOETED
        if GC.PICKER_SORTSTAT:
            self.sort_ip_stat = lambda s: self.sort_ip_stat_good((s[-1][:-1], s[:-1]))
            self.sort_ip_stat_bad = get_index_1
        else:
            self.sort_ip_stat = None
            self.sort_ip_stat_bad = None

    def sort_ip_stat_good(self, p):
        ip, s = p
        return s[2] * 2 / max(s[0] * self.ip_stat_bad.get(ip, [1])[0], 1) - s[3] - s[1] * 10

    @_lock_file_source
    def _load_source(self, file):
        ip_cnt_source = 0
        ip_set_block = set()
        ip_set = set()
        #不自动读取备份
        if exists(file):
            with open(file, 'r') as f:
                for line in f:
                    #不检查 IP 有效性
                    ip = line.strip()
                    if ip:
                        ip_cnt_source += 1
                        if line.startswith(self.block_prefixs):
                            ip_set_block.add(ip)
                        else:
                            ip_set.add(ip)
        ip_cnt = len(ip_set)
        ip_cnt_block = len(ip_set_block)
        ip_cnt_dup = ip_cnt_source - ip_cnt - ip_cnt_block
        self.logger.debug('%r：载入 IP %d 个，未载入 %d 个，发现重复 %d 个',
                    file, ip_cnt, ip_cnt_dup, ip_cnt_block)
        return ip_set, ip_set_block, bool(ip_cnt_dup)

    def load_source(self):
        ip_set, self.ip_set_block, need_save_ip = self._load_source(self.ip_file)
        ip_set_ex, self.ip_set_ex_block, need_save_ip_ex = self._load_source(self.ip_file_ex)
        if hasattr(self, 'ip_set_del'):
            ip_set_del = self.ip_set_del
        else:
            ip_set_del, self.ip_set_del_block, _ = self._load_source(self.ip_file_del)
        self.load_time = time()

        self.ip_set = ip_set - ip_set_ex
        self.ip_set_ex = ip_set_ex
        self.ip_set_del = ip_set_del - ip_set - ip_set_ex

        if not self.ip_stat_files:
            self.load_stat()

        ip_set_add = ip_set_ex - ip_set
        if ip_set_add:
            self.logger.test('检测到新添加的 IP，数量：%d。', len(ip_set_add))
        if need_save_ip or self.ip_set != ip_set or ip_set_add:
            self.save_source(self.ip_file)
        if need_save_ip_ex:
            self.save_source(self.ip_file_ex)
        ip_set_undel = ip_set_del - self.ip_set_del
        if ip_set_undel:
            self.logger.test('检测到被撤销永久屏蔽的 IP，数量：%d。', len(ip_set_undel))
            _ip = ip_set_undel.pop()
            for ip in ip_set_undel:
                self.reset_ip_stat(ip, save=False)
            self.reset_ip_stat(_ip)

    @_lock_file_source
    def _save_source(self, ip_set, file):
        backup_file(file, no_copy=True)
        with open(file, 'w', newline='\n') as f:
            for ip in ip_set:
                f.write(ip)
                f.write('\n')
        self.logger.debug('%r：保存 IP %d 个', file, len(ip_set))

    def save_source(self, file):
        mtime = getmtime(file) if exists(file) else time()
        if file is self.ip_file:
            self._save_source(self.ip_set | self.ip_set_block |
                              self.ip_set_ex | self.ip_set_ex_block, file)
        elif file is self.ip_file_ex:
            self._save_source(self.ip_set_ex, file)
        elif file is self.ip_file_del:
            self._save_source(self.ip_set_del | self.ip_set_del_block, file)
        os.utime(file, times=(mtime, mtime))

    def get_stat_filenames(self, clear_outdated=True):
        now = time()
        filenames = []
        for i in range(self.stat_days):
            n = strftime('%y%j', localtime(now - 3600 * 24 * i))
            filename = os.path.join(data_dir, 'ip_stat_' + n)
            filenames.append(filename)
        filenames.append(os.path.join(data_dir, 'ip_stat_bak'))
        if clear_outdated:
            for name in os.listdir(data_dir):
                if name.startswith('ip_stat_'):
                    isdel = True
                    for filename in filenames:
                        if filename.endswith(name):
                            isdel = False
                            break
                    if isdel:
                        os.remove(os.path.join(data_dir, name))
        return filenames

    @_lock_file_stat
    def load_stat(self):
        ip_unstat = set()
        ip_stat = {}
        ip_stat_today = None
        ip_stat_files = self.get_stat_filenames()
        restore_file(ip_stat_files[1], ip_stat_files[-1])
        for file in ip_stat_files[:-1]:
            if not exists(file):
                continue
            with open(file, 'r') as f:
                for line in f:
                    try:
                        (check_ok_times, check_fail_times,
                        recheck_ok_times, recheck_fail_times,
                        unstat, ip) = _ip_stat = \
                        [int(x) if x.isdigit() else x 
                                for x in line.split(self.ip_stat_split)]
                    except:
                        self.logger.debug('load_stat: %r', line)
                    else:
                        ip = ip.strip()
                        if _ip_stat[4]:
                            ip_unstat.add(ip)
                        if ip in ip_unstat or \
                                ip in self.ip_set_del or \
                                ip.startswith(self.block_prefixs):
                            continue
                        if ip in ip_stat:
                            ip_stat[ip] = [x + y
                                    for x, y in zip(ip_stat[ip], _ip_stat[:-1])]
                        else:
                            ip_stat[ip] = _ip_stat[:-1]
            if file is ip_stat_files[0]:
                ip_stat_today = deepcopy(ip_stat)

        self.ip_stat_files = ip_stat_files
        self.ip_stat = ip_stat
        self.ip_stat_today = ip_stat_today or {}

    @_lock_file_stat
    def _save_stat(self, ip_stat, ip_stat_file, sort_ip_stat):
        ip_stat = (_ip_stat + [ip + '\n'] for ip, _ip_stat in ip_stat.items())
        if sort_ip_stat:
            ip_stat = sorted(ip_stat, key=sort_ip_stat)
        with open(ip_stat_file, 'w', newline='\n') as f:
            for _ip_stat in ip_stat:
                _ip_stat = (str(x) for x in _ip_stat)
                f.write(self.ip_stat_split.join(_ip_stat))

    def save_stat(self):
        backup_file(self.ip_stat_files[0], self.ip_stat_files[-1], no_copy=True)
        self._save_stat(self.ip_stat_today, self.ip_stat_files[0], self.sort_ip_stat)
        if not self.ip_stat_files[0].endswith(strftime('%y%j')):
            self.load_stat()
            self.save_stat_bad()

    @_lock_file_stat
    def load_stat_bad(self):
        ip_stat_bad = {}
        restore_file(self.ip_file_bad)
        if exists(self.ip_file_bad):
            with open(self.ip_file_bad, 'r') as f:
                for line in f:
                    try:
                        (block_times, del_times, log_time,
                        ip) = _ip_stat_bad = \
                        [int(x) if x.isdigit() else x
                                for x in line.split(self.ip_stat_split)]
                    except:
                        self.logger.debug('load_stat_bad: %r', line)
                    else:
                        ip = ip.strip()
                        ip_stat_bad[ip] = _ip_stat_bad[:-1]

        self.ip_stat_bad = ip_stat_bad

    def save_stat_bad(self):
        backup_file(self.ip_file_bad, no_copy=True)
        self._save_stat(self.ip_stat_bad, self.ip_file_bad, self.sort_ip_stat_bad)

    @_lock_log_stat
    def _log_stat(self, ip, index, save=False):
        # 0: check_ok_times
        # 1: check_fail_times
        # 2: recheck_ok_times
        # 3: recheck_fail_times
        # 4: unstat
        skip_log = True
        for ip_stat in (self.ip_stat, self.ip_stat_today):
            if ip in ip_stat:
                _ip_stat = ip_stat[ip]
                skip_log = False
            elif index is 4 and skip_log:
                continue
            else:
                ip_stat[ip] = _ip_stat = [0] * 5

            if index in (1, 3):
                _ip_stat[4] = 0
            _ip_stat[index] += 1

        if index in (1, 3):
            _, cf, _, _, _ = self.ip_stat[ip]
            _, _, _, rf, _ = self.ip_stat_today[ip]
            if ip in self.ip_stat_block:
                _ip_stat_block = self.ip_stat_block[ip]
            else:
                self.ip_stat_block[ip] = _ip_stat_block = [0] * 2
                _ip_stat_block[0] = cf
                if ip in self.ip_stat_bad:
                    _ip_stat_block[1] = self.ip_stat_bad[ip][0]
            if cf + rf - _ip_stat_block[0] > self.fail_times_to_block:
                _ip_stat_block[0] = cf
                self.block_ip(ip)

        if not save:
            if skip_log:
                return
            self.log_stat_times += 1
            save = self.log_stat_times >= self.save_per_log_stat or \
                    time() - self.save_stat_time > self.save_stat_interval 
        if save:
            self.log_stat_times = 0
            self.save_stat()
            self.save_stat_time = time()

    def report_check_ok(self, ip):
        self._log_stat(ip, 0)

    def report_check_fail(self, ip):
        self._log_stat(ip, 1)

    def report_recheck_ok(self, ip):
        self._log_stat(ip, 2)

    def report_recheck_fail(self, ip):
        self._log_stat(ip, 3)

    @_lock_log_stat
    def _log_stat_bad(self, ip, index, save=False):
        # 0: block_times
        # 1: del_times
        # 2: log_time
        if ip in self.ip_stat_bad:
            _ip_stat_bad = self.ip_stat_bad[ip]
        else:
            self.ip_stat_bad[ip] = _ip_stat_bad = [0] * 3
        _ip_stat_bad[index] += 1
        _ip_stat_bad[2] = int(time())

        if index is 0:
            bt, dt, _ = self.ip_stat_bad[ip]
            if ip in self.ip_stat_block:
                _ip_stat_block = self.ip_stat_block[ip]
            else:
                self.ip_stat_block[ip] = _ip_stat_block = [0] * 2
                if ip in self.ip_stat_today:
                    _ip_stat_block[0] = self.ip_stat[ip][1]
                _ip_stat_block[1] = bt
            if bt - _ip_stat_block[1] > self.block_times_to_del:
                _ip_stat_block[1] = bt
                self.del_ip(ip)

        if not save:
            self.log_stat_bad_times += 1
            save = self.log_stat_bad_times >= self.save_per_log_stat_bad or \
                    time() - self.save_stat_bad_time > self.save_stat_bad_interval 
        if save:
            self.log_stat_bad_times = 0
            self.save_stat_bad()
            self.save_stat_bad_time = time()

    def block_ip(self, ip):
        self._log_stat_bad(ip, 0)
        self.ip_set_bad.add(ip)

    def unblock_ip(self, ip):
        self.ip_set_bad.discard(ip)

    def del_ip(self, ip):
        if not self.del_assoeted_ip and ip in self.ip_set_assoeted:
            return
        self._log_stat_bad(ip, 1, save=True)
        self.ip_set_del.add(ip)
        self.ip_set.discard(ip)
        if ip in self.ip_set_ex:
            self.ip_set_ex.remove(ip)
            self.save_source(self.ip_file_ex)
        self.save_source(self.ip_file)
        self.save_source(self.ip_file_del)

    def undel_ip(self, ip):
        self.ip_set_del.discard(ip)
        self.ip_set.add(ip)
        self.save_source(self.ip_file)
        self.save_source(self.ip_file_del)

    def reset_ip_stat(self, ip, save=True):
        self._log_stat(ip, 4, save=save)
        self.ip_stat_bad.pop(ip, None)
        self.ip_set_bad.discard(ip)
        self.ip_set_del.discard(ip)
        if save:
            self.save_stat_bad()
            self.save_source(self.ip_file_del)

    def make_good_list(self):
        ip_list = sorted(self.ip_stat.items(), key=self.sort_ip_stat_good)
        return [ip for ip, _ in ip_list if ip in self.ip_set_good]

    def update_list(self, update_source=False):
        now = time()
        if update_source:
            self.load_source()
        elif now - self.update_time < 60:
            return

        self.update_time = now
        self.ip_set_bad = set(ip for ip, (_, _, t) in self.ip_stat_bad.items() if now - t < self.block_time) \
                          - self.ip_set_del
        self.ip_set_good = set(ip for ip, (co, _, ro, _, unstat) in self.ip_stat.items() if co and not unstat) \
                           & self.ip_set \
                           - self.ip_set_ex \
                           - self.ip_set_bad \
                           - self.ip_set_del \
                           - self.ip_set_used
        self.ip_set_weak = set(self.ip_stat_bad.keys()) \
                           & self.ip_set \
                           - self.ip_set_ex \
                           - self.ip_set_good \
                           - self.ip_set_bad \
                           - self.ip_set_del \
                           - self.ip_set_used

        self.ip_list_ex = get_littery_list(self.ip_set_ex
                                           - self.ip_set_bad
                                           - self.ip_set_used)
        self.ip_list = get_littery_list(self.ip_set
                                        - self.ip_set_ex
                                        - self.ip_set_assoeted
                                        - self.ip_set_good
                                        - self.ip_set_weak
                                        - self.ip_set_bad
                                        - self.ip_set_del
                                        - self.ip_set_used)
        self.ip_list_weak = get_littery_list(self.ip_set_weak)

    def check_update(self, force=False):
        now = time()
        update_source = False
        ip_mtime = ip_mtime_ex = 0
        if exists(self.ip_file):
            ip_mtime = getmtime(self.ip_file)
            if ip_mtime > self.ip_mtime:
                backup_file(self.ip_file)
        else:
            self.logger.error('未发现 IP 列表文件 "%s"，请创建！', self.ip_file)
        if exists(self.ip_file_ex):
            ip_mtime_ex = getmtime(self.ip_file_ex)
            if ip_mtime_ex > self.ip_mtime_ex:
                backup_file(self.ip_file_ex)
                self.ip_mtime_ex_start_time = now
        elif self.ip_mtime_ex_start_time:
            self.ip_mtime_ex_start_time = 0
            update_source = True
        if ip_mtime > self.ip_mtime or ip_mtime_ex > self.ip_mtime_ex:
            self.ip_mtime = ip_mtime
            self.ip_mtime_ex = ip_mtime_ex
            update_source = True
        elif len(self.ip_list_weak) < len(self.ip_set_weak) // 2 or \
                now - self.load_time > self.time_to_reload:
            update_source = True
        if force or update_source:
            self.update_list(update_source=update_source)
        if ip_mtime_ex:
            pass_time = now - self.ip_mtime_ex_start_time
            idle_time = self.ip_mtime_ex_start_time - ip_mtime_ex
            if idle_time > self.ex_del_max:
                ex_del_max = self.ex_del_max ** 2 // idle_time
            else:
                ex_del_max = self.ex_del_max
            if pass_time > ex_del_max or \
                    len(self.ip_list_ex) == 0 and pass_time > self.ex_del_min:
                os.remove(self.ip_file_ex)
                self.ip_mtime_ex = 0
                self.ip_mtime_ex_start_time = 0
                self.logger.test('删除优先使用 IP 列表文件：%s', self.ip_file_ex)
        return update_source

class IPPoolSource:
    check_per_ip = 50
    get_per_ip_good = 20
    get_per_ip_other = 10
    save_interval = 60 * 5
    save_per_save_cmd = 10

    def __new__(cls, ip_source, type):
        m = object.__new__(cls)
        setattr(cls, type, m)
        return m

    def __init__(self, ip_source, type):
        now = time()
        self.update_time = now
        self.last_save_time = now
        self.save_cmd_times = 0
        self.check_cnt = 0
        self._ip_source = ip_source
        self.type = type
        self.ip_file = os.path.join(data_dir, 'ip_' + type)
        self.ip_set, self.ip_set_block, _ = self._load_source(self.ip_file)
        ip_source.ip_set_assoeted |= self.ip_set
        self.ip_list_ed = collections.deque()

    def __getattr__(self, name):
        return getattr(self._ip_source, name)

    def update_list_good(self, force=False):
        now = time()
        if not force and now - self.update_time < 60:
            return

        self.update_time = now
        self.get_cnt = 0
        self.get_cnt_good = 0
        self.get_cnt_other = 0
        ip_list_good = self.make_good_list()
        ip_set = self.ip_set \
                 - self.ip_set_ex \
                 - self.ip_set_weak \
                 - self.ip_set_bad \
                 - self.ip_set_del \
                 - self.ip_set_used \
                 - set(self.ip_list_ed)
        self.ip_list_good = [ip for ip in ip_list_good if ip in ip_set]
        self.ip_list_other = get_littery_list(ip_set - set(self.ip_list_good))
        self.cnt_to_update_good = max((len(self.ip_list_good) + 1) // 2, 50)

    def check_update(self, force=False):
        if self._ip_source.check_update(force=force):
            for m in (self.gae, self.gws):
                m.update_list_good(force=force)
        elif not self.ip_list_good or self.get_cnt_good > self.cnt_to_update_good:
            self.update_list_good(force=force)

    def _get_ip(self):
        self.get_cnt += 1
        if self.ip_list_good and \
                self.get_cnt_good * self.get_per_ip_good < self.get_cnt:
            self.get_cnt_good += 1
            return self.ip_list_good.pop()
        if self.ip_list_other and \
                self.get_cnt_other * self.get_per_ip_other < self.get_cnt:
            self.get_cnt_other += 1
            return self.ip_list_other.pop()
        ip_list = self.ip_list_ex or \
                  self.ip_list or \
                  self.ip_list_good or \
                  self.ip_list_other or \
                  self.ip_list_weak
        if ip_list:
            return ip_list.pop()

    @_lock_get_ip
    def get_ip(self):
        if self.ip_list_ed:
            return self.ip_list_ed.pop(), self.type
        if self.check_cnt > self.check_per_ip:
            network_test()
            self.check_update()
            self.check_cnt = 0
        ip = self._get_ip()
        while ip and not is_ip_use(ip) and (
                not internet_v4.last_stat and isipv4(ip) or
                not internet_v6.last_stat and isipv6(ip)):
            ip = self._get_ip()
        if ip:
            self.check_cnt += 1
            if ip in self.gae.ip_set:
                type = 'gae'
            elif ip in self.gws.ip_set:
                type = 'gws'
            else:
                type = None
            return ip, type
        else:
            self.check_update(force=True)
            return None, None

    def push_ip(self, ip, type=None):
        m = getattr(self, type or self.type, self)
        m.ip_list_ed.appendleft(ip)

    def save_source(self, force=False):
        now = time()
        self.save_cmd_times += 1
        if force or self.save_cmd_times >= self.save_per_save_cmd or \
                now - self.last_save_time > self.save_interval:
            self.save_cmd_times = 0
            self._save_source(self.ip_set | self.ip_set_block, self.ip_file)
            self.last_save_time = now

    def add_ip(self, ip, type=None):
        m = getattr(self, type or self.type, self)
        m.ip_set.add(ip)
        ip_source.ip_set_assoeted.add(ip)
        m.save_source()

    def remove_ip(self, ip, type=None):
        m = getattr(self, type or self.type, self)
        m.ip_set.discard(ip)
        ip_source.ip_set_assoeted.discard(ip)
        m.save_source()

class IPManager:

    pick_http_req = (
        b'HEAD / HTTP/1.1\r\n'
        b'Host: www.appspot.com\r\n'
        b'Connection: Close\r\n\r\n'
    )
    pick_gae_req = (
        b'HEAD / HTTP/1.1\r\n'
        b'Host: gweb-cloudblog-publish.appspot.com\r\n'
        b'Connection: Close\r\n\r\n'
    )
    pick_gws_req = (
        b'HEAD / HTTP/1.1\r\n'
        b'Host: www.google.com\r\n'
        b'Connection: Close\r\n\r\n'
    )
    pick_gae_code = b'404', b'405', b'502'
    pick_gae_verify_code  = b'500', b'302'
    pick_gws_res = (
        b' Found\r\n'
        b'Location: https://console.cloud.google.com/appengine'
    )
    ip_set = set()

    def __new__(cls, ip_source):
        m = object.__new__(cls)
        setattr(cls, ip_source.type, m)
        return m

    def __init__(self, ip_source):
        self.running = False
        self.pick_worker_cnt = 0
        self.kill_pick_worker_cnt = 0
        type = ip_source.type
        if type == 'gae':
            self.check_callback = self.check_gae_callback
        elif type == 'gws':
            self.check_callback = self.check_gws_callback
        self.type = type
        self.logger = logging.getLogger('[picker %s]' % type)
        self.logger.setLevel(GC.LOG_LEVEL)
        self.list_name = 'google_' + type
        self.cache_key = self.list_name + '|:443'
        self.ip_list = collections.deque(GC.IPLIST_MAP[self.list_name])
        GC.IPLIST_MAP[self.list_name] = self.ip_list
        self.ip_set |= set(self.ip_list)
        ip_source._ip_source.ip_set_used = self.ip_set
        self.ip_source = ip_source
        self.load_config()
        now = time()
        self.last_update = now
        self.last_check = now - self.min_recheck_time

    def load_config(self):
        if self.type == 'gae':
            enable = GC.PICKER_GAE_ENABLE
            min_recheck_time = GC.PICKER_GAE_MINRECHECKTIME
            min_cnt = GC.PICKER_GAE_MINCNT
            max_timeout = GC.PICKER_GAE_MAXTIMEOUT
            max_threads = GC.PICKER_GAE_MAXTHREADS
        elif self.type == 'gws':
            enable = GC.PICKER_GWS_ENABLE
            min_recheck_time = GC.PICKER_GWS_MINRECHECKTIME
            min_cnt = GC.PICKER_GWS_MINCNT
            max_timeout = GC.PICKER_GWS_MAXTIMEOUT
            max_threads = GC.PICKER_GWS_MAXTHREADS
        self.enable = enable
        self.strict = GC.PICKER_STRICT
        self.min_recheck_time = min_recheck_time
        self.min_cnt = min_cnt
        self.max_cnt = int(min_cnt * 1.4)
        self.max_timeout = max_timeout
        self.max_threads = max_threads
        self.server_name = GC.PICKER_SERVERNAME
        self.com_domain =GC.PICKER_COMDOMAIN
        self.recheck_loop_time = max(90, GC.GAE_KEEPTIME) + min(10, min_cnt) * 20

    def get_timeout(self, type=None):
        m = getattr(self, type or self.type, self)
        return m.max_timeout

    @_lock_save_use
    def save_ip(self):
        headers = ('#coding: utf-8\n'
                   '#此文件由 GotoX 自动维护，请不要修改。\n'
                   '[iplist]\n')
        with open(GC.CONFIG_IPDB, 'w', encoding='utf_8', newline='\n') as f:
            f.write(headers)
            for m in (self.gae, self.gws):
                f.write(m.list_name)
                f.write(' = ')
                f.write('|'.join(m.ip_list))
                f.write('\n')
        self.last_update = time()

    def add_ip(self, ip, type=None):
        m = getattr(self, type or self.type, self)
        if ip not in m.ip_set:
            m.ip_set.add(ip)
            m.ip_list.append(ip)
            m.logger.test('添加 %s 到 %s', ip, m.list_name)
            if len(m.ip_list) > m.max_cnt:
                m.remove_slow_ip()
            self.save_ip()

    def remove_ip(self, ip, type=None):
        m = getattr(self, type or self.type, self)
        if ip in m.ip_set:
            m.ip_set.remove(ip)
            m.ip_list.remove(ip)
            m.logger.test('remove_ip 从 %s 移除 %s', m.list_name, ip)
            self.save_ip()

    @_lock_remove_slow
    def remove_slow_ip(self, type=None):
        m = getattr(self, type or self.type, self)
        ip_list = ((ip, http_gws.get_ssl_connection_time((ip, 443))) for ip in m.ip_list)
        ip_list = sorted(ip_list, key=get_index_1)
        while len(ip_list) > m.max_cnt:
            ip = ip_list.pop()[0]
            m.ip_set.remove(ip)
            m.ip_list.remove(ip)
            m.logger.test('remove_slow_ip 从 %s 移除 %s', m.list_name, ip)

    def check_ip(self, ip, type=None):
        m = getattr(self, type or self.type, self)
        return http_gws._create_ssl_connection((ip, 443), m.cache_key, None, None,
                                                callback=m.check_callback)

    def check_gae_callback(self, result):
        self.check_gws_callback(result)
        if isinstance(result, Exception):
            return
        try:
            http_gws.match_hostname(result, hostname='www.appspot.com')
        except CertificateError:
            ip = result.xip[0]
            if ip in self.ip_set:
                self.remove_ip(ip, 'gae')
                self.add_ip(ip, 'gws')
            self.ip_source.remove_ip(ip, 'gae')
            self.ip_source.add_ip(ip, 'gws')
            self.logger.warning('IP 类型错误，移动 %s 到 GWS 列表', ip)
            return self.gws.cache_key

    def check_gws_callback(self, result):
        timeout = self.get_timeout()
        ip = result.xip[0]
        is_recheck = ip in self.ip_set
        if isinstance(result, Exception):
            if is_recheck:
                if isinstance(result, LimiterFull):
                    self.ip_list.append(self.ip_list.popleft())
                elif len(self.ip_list) < self.max_cnt and (
                            self.max_threads == 0 or (
                            isinstance(result, socket.timeout) and
                            result.args[0][-3:] == ' ms' and
                            self.pick_worker_cnt >= self.max_threads)) or \
                            len(self.ip_list) <= self.min_cnt:
                    http_gws.ssl_connection_time[result.xip] = http_gws.timeout + 1
                    self.ip_list.append(self.ip_list.popleft())
                    self.logger.warning('%s 测试失败（超时：%d ms）%s，%s',
                            self.pick_worker_cnt, timeout, ip, result)
                    #不移除会持续记录，此处抵消
                    self.ip_source.report_recheck_ok(ip)
                else:
                    self.remove_ip(ip)
                    self.logger.warning('%s 测试失败（超时：%d ms）%s，%s，'
                                        'Bad IP 已删除',
                            self.pick_worker_cnt, timeout, ip, result)
            return
        ssl_time = int(result.ssl_time * 1000)
        if ssl_time > timeout and len(self.ip_list) > self.min_cnt:
            raise socket.timeout('%d ms' % ssl_time)
        self.logger.test('%d 测试连接（超时：%d ms）%s，%d ms',
                self.pick_worker_cnt, timeout, ip, ssl_time)
        if is_recheck:
            self.ip_list.append(self.ip_list.popleft())
        else:
            self.add_ip(ip)

    def get_ip_info(self, ip, server_name=None, callback=None,
                    conntimeout=g_conntimeout,
                    handshaketimeout=g_handshaketimeout,
                    timeout=g_timeout):
        retry = None
        server_name = server_name or self.server_name
        callback = callback or self.check_type_status
        while True:
            start_time = time()
            ssl_time = 1e5
            type = None
            domain = None
            sock = None
            ssl_sock = None
            try:
                sock = http_gws.get_tcp_socket(ip)
                http_gws.set_tcp_socket(sock, set_buffer=False)
                ssl_sock = http_gws.get_ssl_socket(sock, server_name)
                ssl_sock.settimeout(conntimeout)
                ssl_sock.connect((ip, 443))
                ssl_sock.settimeout(handshaketimeout)
                ssl_sock.do_handshake()
                ssl_sock.settimeout(timeout)
                handshaked_time = time() - start_time
                ssl_time = int(handshaked_time * 1000)
                if handshaked_time > handshaketimeout:
                    raise socket.error('handshake 超时：%d ms' % ssl_time)
                cert = http_gws.google_verify(ssl_sock)
                domain = cert.get_subject().CN
                if not domain:
                    raise CertificateError(-1, '%s 无法获取 commonName：%s' % (ip, cert))
                type = callback(ssl_sock, ip)
            except NetWorkIOError as e:
                self.logger.debug('get_ip_info 发生错误：%s', e)
                if not retry and (e.args == zero_EOF_error or e.args[0] in zero_errno):
                    retry = True
                    continue
            finally:
                if ssl_sock:
                    ssl_sock.close()
                elif sock:
                    sock.close()
            if server_name is self.server_name and domain == self.com_domain:
                domain = '*.google.com'
            if type is 'gae' and not self.test_ip_gae(ip) or \
                    type is 'gws' and not self.test_ip_gws(ip):
                type = None
            return domain, ssl_time, type

    def check_type_status(self, conn, ip):
        try:
            conn.send(self.pick_http_req)
            conn.read(9)
            if conn.read(3) in self.pick_gae_code:
                return 'gae'
            elif conn.read(60) == self.pick_gws_res:
                return 'gws'
        except NetWorkIOError as e:
            self.logger.debug('从 %s 获取服务器信息时发生错误：%r', ip, e)

    def check_gae_status(self, conn, ip):
        try:
            http_gws.match_hostname(conn, hostname='www.appspot.com')
            conn.send(self.pick_gae_req)
            conn.read(9)
            return conn.read(3) in self.pick_gae_verify_code
        except CertificateError:
            return False
        except:
            pass

    def test_ip_gae(self, ip):
        server_name = random_hostname('*com')
        _, _, type = self.get_ip_info(ip,
                server_name=server_name,
                callback=self.check_gae_status)
        if type:
            return True
        gae = self.gae
        try:
            if gae.enable:
                gae.remove_ip(ip)
            else:
                gae.ip_list.remove(ip)
        except (KeyError, ValueError):
            pass
        if type is False:
            #无法使用的 IP
            gae.ip_source.remove_ip(ip)
            gae.ip_source.del_ip(ip)
            self.logger.debug('从 gae 分类移除 %s', ip)
        else:
            #无法肯定判断，但是可先加入
            gae.ip_source.add_ip(ip)

    def check_gws_status(self, conn, ip):
        try:
            conn.send(self.pick_gws_req)
            conn.read(9)
            return conn.read(3) == b'200'  # HEAD -> 200, GET -> 302
        except CertificateError:
            return False
        except:
            pass

    def test_ip_gws(self, ip):
        _, _, type = self.get_ip_info(ip, callback=self.check_gws_status)
        if type:
            return True
        gws = self.gws
        try:
            if gws.enable:
                gws.remove_ip(ip)
            else:
                gws.ip_list.remove(ip)
        except (KeyError, ValueError):
            pass
        if type is False:
            #无法使用的 IP
            gws.ip_source.remove_ip(ip)
            gws.ip_source.del_ip(ip)
            self.logger.debug('从 gws 分类移除 %s', ip)
        else:
            #无法肯定判断，但是可先加入
            gws.ip_source.add_ip(ip)

    def pick_ip_worker(self):
        while True:
            try:
                if self.kill_pick_ip_worker():
                    break
                ip, type = self.ip_source.get_ip()
                if ip is None:
                    sleep(10)
                    continue
                checked = False
                if type is None:
                    domain, ssl_time, type = self.get_ip_info(ip)
                    if type:
                        self.ip_source.add_ip(ip, type)
                        checked = domain and ssl_time <= self.get_timeout(type)
                elif not self.strict:
                    checked = True
                elif type is 'gae':
                    checked = self.test_ip_gae(ip)
                elif type is 'gws':
                    checked = self.test_ip_gws(ip)
                if type is not self.type and checked:
                    self.ip_source.push_ip(ip, type)
                    continue
                if checked:
                    #再次 check_ip 以记录连接时间
                    checked = self.check_ip(ip, type)
                if checked:
                    self.ip_source.report_check_ok(ip)
                else:
                    self.ip_source.report_check_fail(ip)
            except Exception as e:
                self.logger.exception('pick_ip_worker 发生错误：%s', e)

    @_lock_pick_worker
    def kill_pick_ip_worker(self):
        if self.kill_pick_worker_cnt > 0:
            self.pick_worker_cnt -= 1
            self.kill_pick_worker_cnt -= 1
            return True

    @_lock_pick_worker
    def check_pick_ip_worker(self):
        new_worker_cnt = min((self.max_cnt - len(self.ip_list)) * 2,
                             self.max_threads or 1) - self.pick_worker_cnt
        if new_worker_cnt > 0:
            self.pick_worker_cnt += new_worker_cnt
            for _ in range(new_worker_cnt):
                start_new_thread(self.pick_ip_worker, ())
                sleep(0.5)
        elif new_worker_cnt < 0:
            self.kill_pick_worker_cnt = - new_worker_cnt
    
    def recheck_ip_worker(self):
        while self.running:
            try:
                sleep(1)
                if not internet_v4.last_stat and not internet_v6.last_stat:
                    self.kill_pick_worker_cnt = self.pick_worker_cnt
                    continue
                self.check_pick_ip_worker()
                pass_time = time() - self.last_check
                if not self.ip_list:
                    if pass_time > self.min_recheck_time:
                        self.logger.warning('当前 %s IP 数量为 0', self.type)
                        self.last_check = time()
                    continue
                if pass_time < self.min_recheck_time or \
                        pass_time < self.recheck_loop_time / len(self.ip_list):
                    continue

                ip = self.ip_list[0]
                if not is_ip_use(ip):
                    self.logger.warning('发现配置未使用的 IP：%s', ip)
                    self.remove_ip(ip)
                    continue
                self.last_check = time()
                if self.check_ip(ip):
                    self.ip_source.report_recheck_ok(ip)
                else:
                    self.ip_source.report_recheck_fail(ip)
            except Exception as e:
                self.logger.exception('recheck_ip_worker 发生错误：%s', e)
        else:
            self.kill_pick_worker_cnt = self.pick_worker_cnt

    @_lock_pick_worker
    def start(self):
        if self.running:
            return
        if self.enable:
            self.running = True
            if not hasattr(self.ip_source, 'get_cnt'):
                self.ip_source.check_update(force=True)
            start_new_thread(self.recheck_ip_worker, ())

    def stop(self):
        self.running = False

ip_source = IPSource()
ip_source_gae = IPPoolSource(ip_source, 'gae')
ip_source_gws = IPPoolSource(ip_source, 'gws')
ip_manager_gae = IPManager(ip_source_gae)
ip_manager_gws = IPManager(ip_source_gws)

test_ip_gae = ip_manager_gae.test_ip_gae
test_ip_gws = ip_manager_gae.test_ip_gws

def test_ip_type(ip):
    _, _, type = ip_manager_gae.get_ip_info(ip)
    if type is 'gae' and not test_ip_gae(ip) or \
            type is 'gws' and not test_ip_gws(ip):
        type = None
    return type

def start_ip_check():
    ip_manager_gae.start()
    ip_manager_gws.start()

def stop_ip_check():
    ip_manager_gae.stop()
    ip_manager_gws.stop()

def fixed_iplist():
    list_gae = []
    list_gws = []
    list_unknown = []
    cnt_gae = 0
    cnt_gws = 0
    while True:
        for ip in ip_source.ip_set_used:
            if ip in ip_source_gae.ip_set:
                type = 'gae'
            elif ip in ip_source_gws.ip_set:
                type = 'gws'
            else:
                type = test_ip_type(ip)
            if type is 'gae':
                ip_source_gae.ip_set.add(ip)
                list_gae.append(ip)
            elif type is 'gws':
                ip_source_gws.ip_set.add(ip)
                list_gws.append(ip)
            else:
                list_unknown.append(ip)
        if len(list_gae) > cnt_gae:
            ip_source_gae.save_source(True)
            cnt_gae = len(list_gae)
        if len(list_gws) > cnt_gws:
            ip_source_gws.save_source(True)
            cnt_gws = len(list_gws)
        ip_manager_gae.logger.test('更新固定 GIP 列表（共 %d 个 IP），'
                                   '包含 GAE %d 个，GWS %d 个。',
                len(ip_source.ip_set_used), cnt_gae, cnt_gws)
        GC.IPLIST_MAP['google_gae'][:] = list_gae + list_unknown
        GC.IPLIST_MAP['google_gws'][:] = list_gws + list_unknown
        list_gae.clear()
        list_gws.clear()
        list_unknown.clear()
        sleep(3600)
