#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

sys.dont_write_bytecode = True

def no_tray():
    import subprocess
    dirname = os.path.dirname(os.path.realpath(__file__))
    app_start = os.path.realpath(os.path.join(dirname, '..', 'start.py'))
    subprocess.Popen((sys.executable, app_start))

if sys.platform.startswith('win'):
    import win_tray
elif sys.platform.startswith('linux'):
    no_tray()
elif sys.platform == 'darwin':
    no_tray()
else:
    no_tray()
