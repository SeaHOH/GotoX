# coding:utf-8
'''
A simple colorful logging class for console or terminal output.
'''

import sys, os, threading, time, traceback

__all__ = ['CRITICAL', 'DEBUG', 'ERROR', 'FATAL', 'INFO', 'NOTSET', 'WARN',
           'WARNING', 'COLORS', 'addLevelName', 'basicConfig', 'getLogger',
           'setLevel', 'disable', 'critical', 'debug', 'error', 'exception',
           'fatal', 'info', 'log', 'warn', 'warning']

CRITICAL = 50
FATAL = CRITICAL
ERROR = 40
WARNING = 30
WARN = WARNING
INFO = 20
DEBUG = 10
NOTSET = 0

_levelToName = {
    CRITICAL: 'CRITICAL',
    ERROR: 'ERROR',
    WARNING: 'WARNING',
    INFO: 'INFO',
    DEBUG: 'DEBUG',
    NOTSET: 'NOTSET',
}
_nameToLevel = {
    'CRITICAL' : CRITICAL,
    'FATAL' : CRITICAL,
    'ERROR' : ERROR,
    'WARN' : WARNING,
    'WARNING' : WARNING,
    'INFO' : INFO,
    'DEBUG' : DEBUG,
    'NOTSET' : NOTSET,
}

class _colors(object):
    if os.name == 'nt':
        RESET = 0x07
        BLACK = 0x00
        RED = 0x0c
        GREEN = 0x02
        YELLOW = 0x06
        BLUE = 0x01
        MAGENTA = 0x05
        CYAN = 0x03
        SILVER = 0x07
        GRAY = 0x08
        WHITE = 0x0f
    elif os.name == 'posix':
        RESET = '\033[0m'
        BLACK = '\033[30m'
        RED = '\033[31m'
        GREEN = '\033[32m'
        YELLOW = '\033[33m'
        BLUE = '\033[34m'
        MAGENTA = '\033[35m'
        CYAN = '\033[36m'
        SILVER = '\033[37m'
        GRAY = '\033[1;30m'
        WHITE = '\033[1;37m'
    CRITICAL = RED
    ERROR = RED
    WARNING = YELLOW
    INFO = SILVER
    DEBUG = GREEN
    HEAD = CYAN
    DEFAULT = RESET

    def __getattr__(self, key):
        try:
            return self.__getattribute__(key)
        except:
            return self.DEFAULT

    def __getitem__(self, key):
        return self.__getattr__(key)

    def __setitem__(self, key, value):
        self.__setattr__(key, value)

COLORS = _colors()

_lock = threading.RLock()
_addedLevelNames = {}
_handlerList = []

def addLevelName(level, levelName, color=None, force=False):
    with _lock:
        levelName = levelName.upper()
        if not force and level in _levelToName or levelName in _nameToLevel:
            return
        _levelToName[level] = levelName
        _nameToLevel[levelName] = level
        if color:
            COLORS[levelName] = color
        g = globals()
        g[levelName] = level

        def wrapper(logger):
            def wrap(fmt, *args, **kwargs):
                logger.log(level, fmt, *args, **kwargs)
            return wrap

        levelName = levelName.lower()
        _addedLevelNames[levelName] = wrapper
        g[levelName] = root.__getattr__(levelName)

def _checkLevel(level):
    with _lock:
        if isinstance(level, (int, float)):
            rv = level
        elif str(level) == level:
            if level not in _nameToLevel:
                raise ValueError("Unknown level: %r" % level)
            rv = _nameToLevel[level]
        else:
            raise TypeError("Level not an integer or a valid string: %r" % level)
        return rv

def _write(msg, file=None, color=None, reset=None):
    if file is None:
        file = sys.stderr or sys.stdout
        if file is None:
            return
    try:
        colors = color and file in (sys.stderr, sys.stdout)
        if colors:
            _setColor(color)
        file.write(msg)
        if hasattr(file, 'flush'):
            file.flush()
        if colors and reset:
            _setColor('RESET')
    except OSError:
        pass

if os.name == 'nt' and hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
    import ctypes
    _SetCTA = ctypes.windll.kernel32.SetConsoleTextAttribute
    _StdHandle = ctypes.windll.kernel32.GetStdHandle(-12)
    _setColor = lambda color: _SetCTA(_StdHandle, COLORS[color])
elif os.name == 'posix':
    _setColor = lambda color: _write(COLORS[color])
else:
    _setColor = lambda x: None

class Logger(object):

    loggerDict = {}
    _disable = 0
    logName = True
    stream = None

    def __new__(cls, name, level=NOTSET):
        with _lock:
            if name in cls.loggerDict:
                return cls.loggerDict[name]
            else:
                self = super(Logger, cls).__new__(cls)
                cls.loggerDict[name] = self
                return self

    def __init__(self, name, level=NOTSET):
        self.name = name
        self.level = _checkLevel(level)

    def __getattr__(self, attr):
        try:
            return self.__getattribute__(attr)
        except Exception as e:
            try:
                log = _addedLevelNames[attr](self)
                self.__setattr__(attr, log)
                return log
            except:
                raise e

    @staticmethod
    def getLogger(name=None):
        if name:
            return Logger(name)
        else:
            return root

    def setLevel(self, level):
        self.level = _checkLevel(level)

    def disable(self, level):
        self._disable = _checkLevel(level)

    def isEnabledFor(self, level):
        if self.__class__._disable >= level or self._disable >= level:
            return False
        return level >= self.level

    def log(self, level, fmt, *args, exc_info=None, **kwargs):
        with _lock:
            if self.isEnabledFor(level):
                levelName = _levelToName[level]
                head = '%s %s ' % (time.strftime('%H:%M:%S'), levelName[0])
                if self.logName:
                    head = '%s%s ' % (head, self.name)
                _write(head, color='HEAD')
                _write('%s\n' % (fmt % args), color=levelName, reset=True)
            if exc_info:
                if isinstance(exc_info, BaseException):
                    exc_info = (type(exc_info), exc_info, exc_info.__traceback__)
                elif not isinstance(exc_info, tuple):
                    exc_info = sys.exc_info()
                _write(''.join(traceback.format_exception(*exc_info)))
                _write('\n')

    def debug(self, fmt, *args, **kwargs):
        self.log(DEBUG, fmt, *args, **kwargs)

    def info(self, fmt, *args, **kwargs):
        self.log(INFO, fmt, *args, **kwargs)

    def warning(self, fmt, *args, **kwargs):
        self.log(WARNING, fmt, *args, **kwargs)

    warn = warning

    def error(self, fmt, *args, **kwargs):
        self.log(ERROR, fmt, *args, **kwargs)

    def exception(self, fmt, *args, exc_info=True, **kwargs):
        self.error(fmt, *args, exc_info=exc_info, **kwargs)

    def critical(self, fmt, *args, **kwargs):
        self.log(CRITICAL, fmt, *args, **kwargs)

    fatal = critical

def basicConfig(*args, **kwargs):
    warning('Unable to format, the only format is "%%H:%%M:%%S" + level code '
            '+ logger name in head.')
    warning('Use setLevel(level) to set output level.')
    root.level = _checkLevel(kwargs.get('level', INFO))

getLogger = Logger.getLogger

root = Logger('root', WARNING)
root.logName = False
Logger.root = root

setLevel = root.setLevel
disable = root.disable
log = root.log
debug = root.debug
info = root.info
warning = warn = root.warning
error = root.error
exception = root.exception
critical = fatal = root.critical

def replace_logging():
    sys.modules['logging'] = sys.modules[__name__]
