# coding:utf-8
'''
A simple colorful logging class for console or terminal output.
'''

import sys, os, time, traceback
from .common.util import make_lock_decorator

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

_lock_setting = make_lock_decorator(rlock=True)
_lock_output = make_lock_decorator()
_addedLevelNames = {}
_handlerList = []

@_lock_setting
def addLevelName(level, levelName, color=None, force=False):
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
        def wrap(msg, *args, **kwargs):
            logger.log(level, msg, *args, **kwargs)
        return wrap

    levelName = levelName.lower()
    _addedLevelNames[levelName] = wrapper
    g[levelName] = root.__getattr__(levelName)

@_lock_setting
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

def _write(msg, file=None, color=None, reset=None):
    if file is None:
        file = sys.stderr or sys.stdout
        if file is None:
            return
    try:
        colors = color and hasattr(file, 'isatty') and file.isatty()
        if colors:
            _setColor(color)
        file.write(msg)
        if hasattr(file, 'flush'):
            file.flush()
        if colors and reset:
            _setColor('RESET')
    except OSError:
        pass

if os.name == 'nt':
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
    level = 0
    disabled = False
    logName = True
    _name = None
    parent = None

    def __new__(cls, name, level=NOTSET):
        return cls.root.getLogger(name)

    def __init__(self, name, level=NOTSET):
        if self._name is None:
            if self.parent not in (None, 'root'):
                name = '.'.join((self.parent._name, name))
            self._name = name
        if level:
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

    @classmethod
    @_lock_setting
    def newRootLogger(cls, name, level=NOTSET):
        try:
            return cls.loggerDict[name]
        except KeyError:
            pass
        logger = object.__new__(cls)
        logger.loggerDict = {'root': logger}
        logger.root = logger
        logger.disable = 0
        logger.__init__(name, level)
        return logger

    def getLogger(self, name=None):
        if name in (None, 'root'):
            return self.root
        names = name.split('.')
        if len(names) > 1:
            logger = self.newRootLogger(names.pop(0))
            while names:
                logger = logger.getChild(names.pop(0))
            return logger
        return self.getChild(name)

    @_lock_setting
    def getChild(self, name):
        names = name.split('.')
        if len(names) > 1:
            logger = self
            while names:
                logger = logger.getChild(names.pop(0))
            return logger
        try:
            return self.root.loggerDict[name]
        except KeyError as e:
            pass
        logger = object.__new__(self.__class__)
        logger.level = self.level
        logger.root = self.root
        logger.parent = self
        logger._name = name
        self.root.loggerDict[name] = logger
        return logger

    def setLevel(self, level):
        self.level = _checkLevel(level)

    def disable(self, level):
        self.root.disable = _checkLevel(level)

    def getEffectiveLevel(self):
        logger = self
        while logger:
            if logger.level:
                return logger.level
            logger = logger.parent
        return NOTSET

    def isEnabledFor(self, level):
        if self.root.disable >= level:
            return False
        return level >= self.getEffectiveLevel()

    @_lock_output
    def _log(self, level, msg, args, exc_info=None, **kwargs):
        if self.isEnabledFor(level):
            levelName = _levelToName[level]
            head = '%s %s ' % (time.strftime('%H:%M:%S'), levelName[0])
            if self.logName:
                head = '%s%s ' % (head, self._name)
            _write(head, color='HEAD')
            _write('%s\n' % (msg % args), color=levelName, reset=True)
        if exc_info:
            if isinstance(exc_info, BaseException):
                exc_info = (type(exc_info), exc_info, exc_info.__traceback__)
            elif not isinstance(exc_info, tuple):
                exc_info = sys.exc_info()
            _write(''.join(traceback.format_exception(*exc_info)),
                    color='DEBUG', reset=True)
            _write('\n')

    def log(self, level, msg, *args, **kwargs):
        self._log(level, msg, args, **kwargs)

    def debug(self, msg, *args, **kwargs):
        self._log(DEBUG, msg, args, **kwargs)

    def info(self, msg, *args, **kwargs):
        self._log(INFO, msg, args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        self._log(WARNING, msg, args, **kwargs)

    warn = warning

    def error(self, msg, *args, **kwargs):
        self._log(ERROR, msg, args, **kwargs)

    def exception(self, msg, *args, exc_info=True, **kwargs):
        self.error(msg, *args, exc_info=exc_info, **kwargs)

    def critical(self, msg, *args, **kwargs):
        self._log(CRITICAL, msg, args, **kwargs)

    fatal = critical

def basicConfig(*args, **kwargs):
    warning('Unable to format, the only format is "%%H:%%M:%%S" + level code '
            '+ logger name in head.')
    warning('Use setLevel(level) to set output level.')
    root.level = _checkLevel(kwargs.get('level', INFO))

root = Logger.newRootLogger('root', WARNING)
root.logName = False
Logger.root = root

getLogger = root.getLogger
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
