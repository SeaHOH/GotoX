# coding:utf-8
"""
A simple colorful logging class for Python. The only format is '%H:%M:%S' +
level code in head.

To use, first 'import clogging' to replace the default logging module, then
'import logging' to use it until reload logging module.
"""

import sys, os, time, traceback

__all__ = ['CRITICAL', 'DEBUG', 'ERROR', 'FATAL', 'INFO', 'NOTSET', 'TEST',
           'WARN', 'WARNING', 'basicConfig', 'critical', 'debug', 'disable',
           'error', 'exception', 'fatal', 'getLogger', 'info', 'log',
           'setLevel', 'test', 'warn', 'warning']

CRITICAL = 50
FATAL = CRITICAL
ERROR = 40
WARNING = 30
WARN = WARNING
INFO = 20
TEST = 15
DEBUG = 10
NOTSET = 0

_levelToName = {
    CRITICAL: 'CRITICAL',
    ERROR: 'ERROR',
    WARNING: 'WARNING',
    INFO: 'INFO',
    TEST : 'TEST',
    DEBUG: 'DEBUG',
    NOTSET: 'NOTSET',
}
_nameToLevel = {
    'CRITICAL' : CRITICAL,
    'ERROR' : ERROR,
    'WARN' : WARNING,
    'WARNING' : WARNING,
    'INFO' : INFO,
    'TEST' : TEST,
    'DEBUG' : DEBUG,
    'NOTSET' : NOTSET,
}
_colors = {
    'CRITICAL' : None,
    'ERROR' : None,
    'WARNING' : None,
    'INFO' : None,
    'TEST' : None,
    'DEBUG' : None,
    'HEAD' : None,
    'RESET' : None,
}

def _checkLevel(level):
    if isinstance(level, (int, long)):
        rv = level
    elif str(level) == level:
        if level not in _nameToLevel:
            raise ValueError("Unknown level: %r" % level)
        rv = _nameToLevel[level]
    else:
        raise TypeError("Level not an integer or a valid string: %r" % level)
    return rv

if hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
    if os.name == 'nt':
        _colors['INFO'] = 0x07
        _colors['ERROR'] = 0x0c
        _colors['WARNING'] = 0x06
        _colors['DEBUG'] = 0x002
        _colors['HEAD'] = 0x03
        import ctypes
        _setCTA = ctypes.windll.kernel32.SetConsoleTextAttribute
        _getStdHandle = ctypes.windll.kernel32.GetStdHandle
        _setColor = lambda color: _setCTA(_getStdHandle(-12), color)
    elif os.name == 'posix':
        _colors['INFO'] = '\033[0m'
        _colors['ERROR'] = '\033[31m'
        _colors['WARNING'] = '\033[33m'
        _colors['DEBUG'] = '\033[32m'
        _colors['HEAD'] = '\033[1;36m'
        _setColor = lambda color: sys.stderr.write(color)
    _colors['CRITICAL'] = _colors['ERROR']
    _colors['TEST'] = _colors['DEBUG']
    _colors['RESET'] = _colors['INFO']
else:
    _setColor = lambda x: None

def getLogger(*args, **kwargs):
    return sys.modules['clogging']

def basicConfig(*args, **kwargs):
    warning('Unable to format, the only format is "%%H:%%M:%%S" + level code in head.')
    warning('Use setLevel(level) to set output level.')
    log.level = _checkLevel(kwargs.get('level', INFO))

def setLevel(level):
    log.level = _checkLevel(level)

def disable(level):
    log.disable = _checkLevel(level)

def isEnabledFor(level):
    if log.disable >= level:
        return 0
    return level >= log.level

def log(level, fmt, *args, **kwargs):
    if isEnabledFor(level):
        levelName = _levelToName[level]
        _setColor(_colors['HEAD'])
        sys.stderr.write('%s %s ' % (time.strftime('%H:%M:%S'), levelName[0]))
        _setColor(_colors[levelName])
        sys.stderr.write('%s\n' % (fmt % args))
        _setColor(_colors['RESET'])

log.level = 0
log.disable = -1

def debug(fmt, *args, **kwargs):
    log(DEBUG, fmt, *args, **kwargs)

def test(fmt, *args, **kwargs):
    log(TEST, fmt, *args, **kwargs)

def info(fmt, *args, **kwargs):
    log(INFO, fmt, *args)

def warning(fmt, *args, **kwargs):
    log(WARNING, fmt, *args, **kwargs)
    #sys.stderr.write(traceback.format_exc() + '\n')

warn = warning

def error(fmt, *args, **kwargs):
    log(ERROR, fmt, *args, **kwargs)

def exception(fmt, *args, **kwargs):
    error(fmt, *args, **kwargs)
    sys.stderr.write(traceback.format_exc() + '\n')

def critical(fmt, *args, **kwargs):
    log(CRITICAL, fmt, *args, **kwargs)

fatal = critical
