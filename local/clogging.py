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
    if isinstance(level, (int, float)):
        rv = level
    elif str(level) == level:
        if level not in _nameToLevel:
            raise ValueError("Unknown level: %r" % level)
        rv = _nameToLevel[level]
    else:
        raise TypeError("Level not an integer or a valid string: %r" % level)
    return rv

def _init_():
    '''
    When gevent.monkey.patch_all is called with ``sys=True``, call this function
    to reload the sys.stderr.(python 2)
    '''
    import sys
    global _write, _flush, _setColor
    _write = sys.stderr.write
    _flush = sys.stderr.flush
    if hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
        if os.name == 'nt':
            _colors['INFO'] = 0x07
            _colors['ERROR'] = 0x0c
            _colors['WARNING'] = 0x06
            _colors['DEBUG'] = 0x002
            _colors['HEAD'] = 0x03
            import ctypes
            SetCTA = ctypes.windll.kernel32.SetConsoleTextAttribute
            StdHandle = ctypes.windll.kernel32.GetStdHandle(-12)
            _setColor = lambda color: SetCTA(StdHandle, _colors[color])
        elif os.name == 'posix':
            _colors['INFO'] = '\033[0m'
            _colors['ERROR'] = '\033[31m'
            _colors['WARNING'] = '\033[33m'
            _colors['DEBUG'] = '\033[32m'
            _colors['HEAD'] = '\033[36m'
            _setColor = lambda color: _write(_colors[color])
        _colors['CRITICAL'] = _colors['ERROR']
        _colors['TEST'] = _colors['DEBUG']
        _colors['RESET'] = _colors['INFO']
    else:
        _setColor = lambda x: None

_init_()

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
        _setColor('HEAD')
        _write('%s %s ' % (time.strftime('%H:%M:%S'), levelName[0]))
        _setColor('HEAD') # repeat for python3 in nt
        _flush() # immediately output for python3
        _setColor(levelName)
        _write('%s\n' % (fmt % args))
        _setColor('RESET')

log.level = 0
log.disable = -1

def debug(fmt, *args, **kwargs):
    log(DEBUG, fmt, *args)

def test(fmt, *args, **kwargs):
    log(TEST, fmt, *args)

def info(fmt, *args, **kwargs):
    log(INFO, fmt, *args)

def warning(fmt, *args, **kwargs):
    log(WARNING, fmt, *args)
    #_write(traceback.format_exc() + '\n')

warn = warning

def error(fmt, *args, **kwargs):
    log(ERROR, fmt, *args)

def exception(fmt, *args, **kwargs):
    error(fmt, *args)
    _write(traceback.format_exc() + '\n')

def critical(fmt, *args, **kwargs):
    log(CRITICAL, fmt, *args)

fatal = critical
