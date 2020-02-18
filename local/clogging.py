# coding:utf-8
'''
A simple colorful logging module for console or terminal output.
Similar, but not fully compatible with official 'logging.__init__' module.
'''

import sys, os, time, traceback
from encodings import search_function as searchCodecInfo
from codecs import CodecInfo
from .common.decorator import make_lock_decorator

__all__ = ['CRITICAL', 'FATAL', 'ERROR', 'WARNING', 'WARN', 'INFO', 'DEBUG',
           'NOTSET', 'NULL_STREAM', 'COLORS', 'addLevelName', 'getLevelName',
           'removeAddedLevelNames', 'removeAllAddedLevelNames', 'LogFile',
           'Logger', 'RootLogger', 'getLogger', 'getRootLogger', 'setLevel',
           'setStream', 'setLogFile', 'disable', 'enable', 'debug', 'info',
           'warn', 'warning', 'error', 'exception', 'fatal', 'critical', 'log',
           'basicConfig', 'replace_logging', 'remove_replace']

CRITICAL = 50
FATAL = CRITICAL
ERROR = 40
WARNING = 30
WARN = WARNING
INFO = 20
DEBUG = 10
NOTSET = 0
NULL_STREAM = object()

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

def getLevelName(level):
    return str(_levelToName.get(level) or _nameToLevel.get(level) or
            'Level %s' % level)

unicode = u''.__class__
preferredEncoding = None

def getpreferredencoding():
    global preferredEncoding
    if preferredEncoding is None:
        import locale
        preferredEncoding = locale.getpreferredencoding(False)
    return preferredEncoding

if hasattr(sys, '_getframe'):
    currentframe = lambda: sys._getframe(3)
else:
    def currentframe():
        try:
            raise Exception
        except Exception:
            return sys.exc_info()[2].tb_frame.f_back

_srcfile = os.path.normcase(getLevelName.__code__.co_filename)

class _colors(object):
    if os.name == 'nt':
        RESET   = 0x07
        BLACK   = 0x00
        RED     = 0x0c
        GREEN   = 0x02
        YELLOW  = 0x06
        BLUE    = 0x01
        MAGENTA = 0x05
        CYAN    = 0x03
        SILVER  = 0x07
        GRAY    = 0x08
        WHITE   = 0x0f
    else:
        RESET   = '\033[0m'
        BLACK   = '\033[30m'
        RED     = '\033[31m'
        GREEN   = '\033[32m'
        YELLOW  = '\033[33m'
        BLUE    = '\033[34m'
        MAGENTA = '\033[35m'
        CYAN    = '\033[36m'
        SILVER  = '\033[37m'
        GRAY    = '\033[1;30m'
        WHITE   = '\033[1;37m'
    CRITICAL = RED
    ERROR = RED
    WARNING = YELLOW
    INFO = SILVER
    DEBUG = GREEN
    HEAD = CYAN
    DEFAULT = RESET

    def __getattr__(self, name):
        try:
            return self.__getattribute__(name.upper())
        except AttributeError as e:
            if not name.startswith('_'):
                return self.DEFAULT
            raise e

    def __getitem__(self, name):
        if name.startswith('_'):
            raise ValueError('Color name "%s" use "_" prefix '
                             'were not supported!' % name)
        else:
            return self.__getattr__(name)

COLORS = _colors()

_lock_setting = make_lock_decorator(rlock=True)
_lock_output = make_lock_decorator()
_lock_logfile = make_lock_decorator()
_lock_restore_logging = make_lock_decorator()
_handlerList = []
_addedLevelNames = []

@_lock_setting
def addLevelName(level, levelName, color=None, force=False):
    '''Will not be added to `__all__`.'''
    levelName = levelName.upper()
    orig_level = _checkOrigLevel(level)
    orig_levelName = _checkOrigLevel(levelName)
    if orig_level or orig_level:
        warning('level(%s) or levelName(%s) is orig.', (level, levelName))
    if orig_levelName or \
            (not force and levelName in _addedLevelNames):
        return
    if not orig_level and \
            (force or level not in _levelToName):
        _levelToName[level] = levelName
    _nameToLevel[levelName] = level
    if color:
        setattr(_colors, levelName, color)
    g = globals()
    g[levelName] = level
    _addedLevelNames.append(levelName)

    def log(self, msg, *args, **kwargs):
        self._log(level, msg, args, **kwargs)

    levelName = levelName.lower()
    setattr(Logger, levelName, log)
    g[levelName] = getattr(root, levelName)

@_lock_setting
def removeAddedLevelName(levelName):
    levelName = levelName.upper()
    for level, name in _levelToName.items():
        if name == levelName:
            del _levelToName[level]
            break
    _nameToLevel.pop(levelName, None)
    try:
        delattr(_colors, levelName)
    except:
        pass
    g = globals()
    g.pop(levelName, None)
    try:
        _addedLevelNames.remove(levelName)
    except:
        pass

    levelName = levelName.lower()
    g.pop(levelName, None)
    try:
        delattr(Logger, levelName)
    except:
        pass

@_lock_setting
def removeAllAddedLevelNames():
    while _addedLevelNames:
        levelName = _addedLevelNames.pop()
        removeAddedLevelName(levelName)

@_lock_setting
def _checkLevel(level):
    if isinstance(level, int):
        rv = level
    elif str(level) == level:
        if level not in _nameToLevel:
            raise ValueError('Unknown level: %r' % level)
        rv = _nameToLevel[level]
    else:
        raise TypeError('Level not an integer or a valid string: %r' % level)
    return rv

@_lock_setting
def _checkOrigLevel(level):
    if isinstance(level, int):
        rv = _levelToName.get(level)
    elif str(level) == level:
        rv = level
    else:
        raise TypeError('Level not an integer or a valid string: %r' % level)
    return rv in _nameToLevel and rv not in _addedLevelNames

def _write(msg, file=None, onerr=None, color=None, reset=None):
    if file is NULL_STREAM:
        return
    stdout = sys.stdout
    stderr = sys.stderr
    stdout_isatty = stdout.isatty()
    stderr_isatty = stderr.isatty()
    if file is None:
        file = stderr if onerr else stdout
        if onerr and not (stdout_isatty and stderr_isatty):
            _write(msg, file=stdout, color=color, reset=reset)
    fd = file.fileno()
    stdout_fd = stdout.fileno()
    stderr_fd = stderr.fileno()
    if onerr:
        if stderr_isatty and fd == stderr_fd or \
                stdout_isatty and fd == stdout_fd:
            pass
        elif stderr_isatty and fd != stderr_fd:
            _write(msg, file=stderr, color=color, reset=reset)
        elif stdout_isatty and fd != stdout_fd:
            _write(msg, file=stdout, color=color, reset=reset)
    if not hasattr(file, 'writable') or not file.writable():
        return
    if fd == stdout_fd:
        isatty = stdout_isatty
        handle = _StdoutHandle
    elif fd == stderr_fd:
        isatty = stderr_isatty
        handle = _StderrHandle
    else:
        isatty = False
        handle = None
    try:
        colors = color and isatty
        if colors:
            _setColor(color, handle or file)
        file.write(msg)
        if hasattr(file, 'flush'):
            file.flush()
        if colors and reset:
            _setColor('RESET', handle or file)
    except OSError:
        pass

_StdoutHandle = None
_StderrHandle = None
if os.name == 'nt':
    import ctypes
    _SetCTA = ctypes.windll.kernel32.SetConsoleTextAttribute
    _StdoutHandle = ctypes.windll.kernel32.GetStdHandle(-11)
    _StderrHandle = ctypes.windll.kernel32.GetStdHandle(-12)
    _setColor = lambda color, handle: _SetCTA(handle, COLORS[color])
elif os.name == 'posix':
    _setColor = lambda color, file: _write(COLORS[color], file=file)
else:
    _setColor = lambda x, y: None

_logFiles = {}

class LogFile(object):

    @_lock_logfile
    def __new__(cls, filename, mode='a',
                     encoding=None, errors='backslashreplace',
                     maxsize=float('inf'), rotation=1):
        '''
        :param filename: if the string is not an absolute path, it will
                         converted with os.path.abspath.
        :param mode:     if the mode not allowed write, a ValueError will be raise.
        :param encoding: if not set, use locale.getpreferredencoding(False).
        :param maxsize:  max file size of log file.
        :param rotation: max number of log file's rotation.
        '''
        mode.replace('x', 'w')
        if 'a' not in mode:
            if 'w' not in mode and '+' not in mode:
                raise ValueError('Open log file "%s" with mode "%s" can not '
                                 'be wrote!' % (filename, mode))
            warning('Log file "%s" will be overwrote!', filename)
        filename = os.path.abspath(filename)
        encoding = encoding or getpreferredencoding()
        try:
            logfile = _logFiles[filename]
        except:
            logfile = object.__new__(cls)
            logfile.stream = None
            logfile.codecInfo = None
        else:
            if logfile.encoding != encoding and logfile.stream:
                warning('File "%s" is in use, the write encoding will change, '
                        'encoding in use: %s, new encoding: %s' % 
                        (filename, logfile.encoding, encoding))
            if logfile.encoding != encoding or logfile.mode != mode:
                logfile.close()
        logfile.filename = filename
        logfile.mode = mode
        logfile.errors = errors
        logfile.encoding = encoding
        logfile.maxsize = maxsize
        logfile.rotation = rotation
        logfile.open()
        logfile.flush()
        _logFiles[filename] = logfile
        return logfile

    def open(self):
        if self.stream:
            return
        dir = os.path.dirname(self.filename)
        if not os.path.exists(dir):
            os.makedirs(dir)
        mode = self.mode
        if 'b' not in mode:
            mode += 'b'
        self.stream = open(self.filename, mode)
        if 'a' in mode:
            self.size = os.path.getsize(self.filename)
        else:
            self.size = 0
        if not self.codecInfo or self.encoding != self.codecInfo.name:
            self.codecInfo = searchCodecInfo(self.encoding)
            if self.codecInfo:
                self.encoding = self.codecInfo.name
            else:
                self.codecInfo = CodecInfo(name=self.encoding,
                                           encode=self._encode,
                                           decode=None)

    def close(self):
        if self.stream:
            self.stream, stream = None, self.stream
            try:
                if hasattr(stream, 'flush'):
                    stream.flush()
            finally:
                if hasattr(stream, 'close'):
                    stream.close()

    def writable(self):
        return hasattr(self.stream, 'writable') and self.stream.writable()

    def encode(self, s, errors):
        return self.codecInfo.encode(s, errors)

    def _encode(self, s, errors):
        consumed = len(s)
        if isinstance(s, unicode):
            s = s.encode(self.encoding, errors)
        return s, consumed

    def write(self, s):
        if hasattr(self.stream, 'write'):
            data, consumed = self.encode(s, self.errors)
            size = len(data)
            if self.size + size > self.maxsize:
                self.rotate()
            self.stream.write(data)
            self.size += size
            return consumed
        return 0

    def flush(self):
        if hasattr(self.stream, 'flush'):
            self.stream.flush()

    def rotate(self):
        def rotate(i=0):
            old = fns[i]
            if i == self.rotation:
                if os.path.exists(old):
                    os.remove(old)
                return
            if os.path.exists(old):
                rotate(i + 1)
                new = fns[i + 1]
                os.rename(old, new)

        self.close()
        fns = [self.filename]
        fns += ['%s.%d' % (self.filename, i) for i in range(1, self.rotation + 1)]
        rotate()
        self.open()

_rootLoggerDict = {}

class Logger(object):

    def __new__(cls, *args, **kwargs):
        return cls.root.getLogger(*args, **kwargs)

    def __init__(self, name, level=NOTSET, *args, **kwargs):
        if name not in self.root.loggerDict:
            self.name = name
            level = _checkLevel(level)
            if level and self.parent and \
                    level == self.parent.getEffectiveLevel():
                self.level = NOTSET
            else:
                self.level = level
            self.root.loggerDict[name] = self
            self.disabled = False
            self.logName = True

    def getLogger(self, name=None, level=NOTSET, stream=None, logfile=None):
        if name in (None, 'root'):
            return self.root
        root, _, child = name.partition('.')
        if child:
            level = _checkLevel(level) or WARNING
            logger = RootLogger(root, level, stream, logfile)
            return logger.getChild(child)
        else:
            return self.getChild(name, level)

    @_lock_setting
    def getChild(self, name, level=NOTSET):
        names = name.split('.')
        if len(names) > 1:
            logger = self
            while names:
                logger = logger.getChild(names.pop(0), level)
            return logger
        if self.name != 'root':
            name = '.'.join((self.name, name))
        try:
            return self.root.loggerDict[name]
        except KeyError as e:
            pass
        logger = object.__new__(Logger)
        logger.root = self.root
        logger.parent = self
        logger.__init__(name, level)
        return logger

    def setLevel(self, level):
        self.level = _checkLevel(level)

    @_lock_setting
    def setStream(self, stream):
        '''
        Pass NULL_STREAM to ignore stream output.
        '''
        if stream and stream is not NULL_STREAM:
            assert stream.writable(), 'Param stream %r is not writable.' % stream
        try:
            if hasattr(self.root.stream, 'flush'):
                self.root.stream.flush()
        except:
            pass
        self.root.stream = stream

    @_lock_setting
    def setLogFile(self, logfile):
        if isinstance(logfile, str):
            logfile = LogFile(logfile)
        elif logfile and not isinstance(logfile, LogFile):
            warning('Param logfile %r is not a LogFile instance!', logfile)
            logfile = None
        if hasattr(self.root.logfile, 'close'):
            self.root.logfile.close()
        self.root.logfile = logfile

    def disable(self, level=None):
        '''
        :param level is None:  Disable this logger instance.
        :param level is other: Setting the root instance's `disable` attribute.
        '''
        if level is None:
            self.disabled = True
        else:
            self.root.disable = _checkLevel(level)

    @_lock_setting
    def enable(self, level=None):
        '''
        :param level is None:  Enable logger and all its parents.
        :param level is other: Setting the root instance's `disable` attribute.
        '''
        if level is None:
            logger = self
            while logger:
                logger.disabled = False
                logger = logger.parent
        else:
            self.root.disable = _checkLevel(level) - 1

    @_lock_setting
    def getDisabledState(self):
        logger = self
        while logger:
            if logger.disabled:
                return True
            logger = logger.parent
        return False

    @_lock_setting
    def getEffectiveLevel(self):
        logger = self
        while logger:
            if logger.level:
                return logger.level
            logger = logger.parent
        return NOTSET

    def isEnabledFor(self, level):
        if self.root.disable >= level or self.getDisabledState():
            return False
        return level >= self.getEffectiveLevel()

    @_lock_output
    def _log(self, level, msg, args, exc_info=None, stack_info=None, color=None, **kwargs):
        if not self.isEnabledFor(level):
            return
        ct = time.time()
        ctt = time.localtime(ct)
        cts = time.strftime('%H:%M:%S', ctt)
        levelName = getLevelName(level)
        onerr = level >= WARNING
        head = '%s %s ' % (cts, levelName[0])
        if self.logName:
            head = '%s%s ' % (head, self.name)
        _write(head, file=self.root.stream, onerr=onerr, color='HEAD')
        if args:
            msg = msg % args
        if msg[-1:] != '\n':
            msg += '\n'
        _write(msg, file=self.root.stream,
                onerr=onerr, color=color or levelName, reset=True)

        if exc_info:
            if isinstance(exc_info, BaseException):
                exc_info = (type(exc_info), exc_info, exc_info.__traceback__)
            elif not isinstance(exc_info, tuple):
                exc_info = sys.exc_info()
            exc_info = ''.join(traceback.format_exception(*exc_info))
            if exc_info[-1:] != '\n':
                exc_info += '\n'
            _write(exc_info, file=self.root.stream,
                    onerr=onerr, color='DEBUG', reset=True)

        if stack_info and not isinstance(stack_info, str):
            f = currentframe()
            if f is not None:
                f = f.f_back
            stack_info = None
            while hasattr(f, 'f_code'):
                co = f.f_code
                filename = os.path.normcase(co.co_filename)
                if filename == _srcfile:
                    f = f.f_back
                    continue
                stack_info = ''.join(traceback.format_stack(f))
                break
        if stack_info:
            stack_info = 'Stack (most recent call last):\n' + stack_info
            if stack_info[-1] != '\n':
                stack_info += '\n'
            _write(stack_info, file=self.root.stream,
                    onerr=onerr, color='DEBUG', reset=True)

        logfile = self.root.logfile
        if logfile:
            # More detailed time information in log file.
            cts = time.strftime('%Y-%m-%d %H:%M:%S', ctt)
            ms = ct % 1 * 1000
            logfile.write('%s.%03d %s %s: %s' %
                    (cts, ms, levelName, self.name, msg))
            if exc_info:
                logfile.write(exc_info)
            if stack_info:
                logfile.write(stack_info)
            logfile.flush()

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

class RootLogger(Logger):

    def __new__(cls, *args, **kwargs):
        return cls.getRootLogger(*args, **kwargs)

    def __init__(self, name='root', level=WARNING, stream=None, logfile=None):
        name = name.replace('.', '-')
        if name not in _rootLoggerDict:
            self.disable = 0
            self.loggerDict = {}
            self.root = self
            self.parent = None
            Logger.__init__(self, name, level)
            self.stream = None
            self.logfile = None
            self.setStream(stream)
            self.setLogFile(logfile)
            self.loggerDict['root'] = self
            _rootLoggerDict[name] = self

    @classmethod
    @_lock_setting
    def getRootLogger(cls, name='root', level=WARNING, stream=None, logfile=None):
        '''
        :param stream:  An opened stream.
        :param logfile: A log filename or an opened LogFile Instance.
        '''
        if name.find('.') >= 0:
            warning('Root logger\'s name can not contains ".", '
                    'but the giving name is "%s".', name)
            name = name.replace('.', '-')
            warning('The root logger\'s name has been replaced with "%s".', name)
        try:
            return _rootLoggerDict[name]
        except KeyError:
            pass
        logger = object.__new__(RootLogger)
        logger.__init__(name, level, stream, logfile)
        return logger

@_lock_setting
def basicConfig(**kwargs):
    handlers = kwargs.pop('handlers', None)
    if handlers:
        raise ValueError('clogging does not implemented handlers!')
    level = kwargs.pop('level', None)
    if level:
        setLevel(level)
    stream = kwargs.pop('stream', None)
    if stream:
        setStream(stream)
    filename = kwargs.pop('filename', None)
    logfile = kwargs.pop('logfile', None) or filename
    if logfile:
        setLogFile(logfile)
    if kwargs:
        warning('Unable to format, the only format is "%H:%M:%S" + level code '
                '+ logger name in head.')

getRootLogger = RootLogger.getRootLogger
root = getRootLogger()
root.logName = False
Logger.root = root

getLogger = root.getLogger
setLevel = root.setLevel
setStream = root.setStream
setLogFile = root.setLogFile
disable=root.disable
enable=root.enable
log = root.log
debug = root.debug
info = root.info
warning = warn = root.warning
error = root.error
exception = root.exception
critical = fatal = root.critical

def replace_logging():
    '''Need to re-import logging module after replaced.'''
    logging = sys.modules.get('logging')
    if logging is not sys.modules[__name__]:
        sys.modules['logging'] = sys.modules[__name__]

@_lock_restore_logging
def remove_replace():
    '''Need to re-import logging module after removed replace.'''
    logging = sys.modules.get('logging')
    if logging is sys.modules[__name__]:
        del sys.modules['logging']
