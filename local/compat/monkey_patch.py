# coding:utf-8

def patch_builtins():
    import builtins

    #重写了类方法 __getattr__ 时，修正 hasattr
    NOATTR = object()
    builtins.gethasattr = lambda o, a: getattr(o, a, NOATTR) != NOATTR

    class classlist(list): pass
    builtins.classlist = classlist

def patch_configparser():
    from configparser import _UNSET, NoSectionError, NoOptionError, RawConfigParser

    #去掉 lower 以支持选项名称大小写共存
    RawConfigParser.optionxform = lambda s, opt: opt

    #支持指定 get 结果空值的 fallback
    _get = RawConfigParser.get

    def get(self, section, option, *, raw=False, vars=None, fallback=_UNSET):
        value = _get(self, section, option, raw=raw, vars=vars, fallback=fallback)
        if not value and fallback is not _UNSET:
            return fallback
        return value

    RawConfigParser.get = get

    #支持指定 getint、getfloat、getboolean 非法值的 fallback
    def _get_conv(self, section, option, conv, *, raw=False, vars=None,
                  fallback=_UNSET, **kwargs):
        try:
            return self._get(section, conv, option, raw=raw, vars=vars, **kwargs)
        except (NoSectionError, NoOptionError, ValueError):
            if fallback is _UNSET:
                raise
            if isinstance(conv, type):
                return conv(fallback)
            else:
                return bool(fallback)

    RawConfigParser._get_conv = _get_conv

    #默认编码 utf8
    _read = RawConfigParser.read
    RawConfigParser.read = lambda s, f, encoding='utf8': _read(s, f, encoding)
