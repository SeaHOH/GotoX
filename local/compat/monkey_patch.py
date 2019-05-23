# coding:utf-8

from . import clean_after_invoked

@clean_after_invoked
def replace_logging():
    import local.clogging as clogging
    clogging.replace_logging()
    clogging.addLevelName(15, 'TEST', clogging.COLORS.GREEN)
    clogging.preferredEncoding = 'cp936'

@clean_after_invoked
def patch_builtins():
    import builtins

    #重写了类方法 __getattr__ 时，修正 hasattr
    NOATTR = object()
    builtins.gethasattr = lambda o, a: getattr(o, a, NOATTR) != NOATTR

    class classlist(list): pass
    builtins.classlist = classlist

@clean_after_invoked
def patch_configparser():
    import logging
    from configparser import _UNSET, NoSectionError, NoOptionError, RawConfigParser

    #去掉 lower 以支持选项名称大小写共存
    RawConfigParser.optionxform = lambda s, opt: opt

    #添加空值（str）作为 get 的 fallback，不影响 _get_conv
    #支持指定 get 结果空值的 fallback
    RawConfigParser._get = RawConfigParser.get

    def get(self, section, option, *, raw=False, vars=None, fallback=_UNSET):
        try:
            value = self._get(section, option, raw=raw, vars=vars)
        except (NoSectionError, NoOptionError):
            value = ''
        if not value and fallback is not _UNSET:
            return fallback
        return value

    RawConfigParser.get = get

    #支持指定 getint、getfloat、getboolean 非法值的 fallback
    def _get_conv(self, section, option, conv, *, raw=False, vars=None,
                  fallback=_UNSET, **kwargs):
        try:
            value = self._get(section, option, raw=raw, vars=vars, **kwargs)
            return conv(value)
        except (NoSectionError, NoOptionError, ValueError) as e:
            if isinstance(e, ValueError) and value:
                logging.warning('配置错误 [%s/%s] = %r：%r',
                                section, option, value, e)
            if fallback is _UNSET:
                raise
        try:
            return conv(fallback)
        except ValueError:
            if isinstance(conv, type):
                raise
            else:
                return bool(fallback)

    RawConfigParser._get_conv = _get_conv

    #默认编码 utf8
    _read = RawConfigParser.read
    RawConfigParser.read = lambda s, f, encoding='utf8': _read(s, f, encoding)
