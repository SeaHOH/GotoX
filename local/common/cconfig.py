# coding: utf-8

import os

class cconfig:
    def __init__(self, name, parent=None, conf=None):
        if not name:
            raise ValueError('cconfig param name can not be a %r.' % name)
        name, inname = name.lower(), name
        if name != inname:
            print('cconfig param name does not support case sensitivity!')
        if parent is None:
            self.root = self
            if conf:
                self.conf = conf
        else:
            self.root = parent.root
            parent.add(name)
            parent._children[name] = self
        self.parent = parent
        self.ext = 0
        self._name = name
        self._extlist = {}
        self._children = {}

    def close(self, close=False):
        if close or self is self.root:
            children = self.get_children()
            del self.root
            del self._children
            for child in children:
                child.close(True)
        else:
            self.root.close(True)

    def add_child(self, name):
        return self.__class__(name, self)

    def get_child(self, name):
        return self._children.get(name.lower())

    def get_children(self):
        return self._children.values()

    def add(self, names):
        if isinstance(names, str):
            names = names,
        for name in names:
            name = name.lower()
            if name in self._extlist:
                continue
            self._extlist[name] = 1 << len(self._extlist)

    def check(self, name):
        return bool(self.ext & self._extlist.get(name.lower(), 0))

    def set(self, name, sign=1, save=False):
        if name not in self:
            self.add(name)
        _ext = self._extlist[name]
        if isinstance(sign, str):
            sign = sign.lower()
        if sign in (1, True, '1', 'on', 'yes', 'true'):
            self.ext |= _ext
        elif sign in (0, False, '0', 'off', 'no', 'false') and self.ext & _ext:
            self.ext ^= _ext
        if save:
            self.save()

    def switch(self, name, save=False):
        self.ext ^= self._extlist[name.lower()]
        if save:
            self.save()

    def checked(self, name, save=False):
        self.ext = self._extlist[name.lower()]
        if save:
            self.save()

    def clear(self, save=False):
        self.ext = 0
        if save:
            self.save()

    def get_index_name(self, name=None):
        if self.parent is None:
            index_name = self.name
        else:
            index_name = '%s.%s' % (self.parent.get_index_name(), self.name)
        if name:
            index_name = '%s.%s' % (index_name, name)
        return index_name

    def check_name(self, name):
        return name.lower() == self.get_index_name().lower()

    def load(self, names=None, filename=None):
        if names:
            self.add(names)
        if not filename:
            filename = self.conf
        if os.path.exists(filename):
            with open(filename, 'r') as fd:
                for line in fd:
                    name, _, value = line.partition(':')
                    rootname, _, name = name.strip().rpartition('.')
                    if self.check_name(rootname):
                        self.set(name, value.strip())

    def save(self, filename=None):
        exts = []
        if not filename:
            filename = self.conf
        if os.path.exists(filename):
            with open(filename, 'r') as fd:
                for line in fd:
                    name, _, _ = line.partition(':')
                    rootname, _, name = name.strip().rpartition('.')
                    if not self.check_name(rootname) or name not in self:
                        exts.append(line)
        for name in self._extlist:
            ext = self.check(name) and 1
            exts.append('%s: %d\n' % (self.get_index_name(name), ext))
        exts.sort()
        with open(filename, 'w') as fd:
            for ext in exts:
                fd.write(ext)

    def __contains__(self, name):
        return name.lower() in self._extlist

    @property
    def conf(self):
        try:
            return self.root._conf
        except AttributeError:
            raise OSError('No config file supplied, cconfig can not be loaded/saved.')

    @conf.setter
    def conf(self, conf):
        if not conf:
            raise ValueError('cconfig param conf can not be a %r.' % conf)
        if os.path.isdir(conf):
            raise ValueError('cconfig param conf can not be a exists dir %r.' % conf)
        self.root._conf = conf

    @property
    def name(self):
        return self._name
