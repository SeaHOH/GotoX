#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

sys.dont_write_bytecode = True

def no_tray():
    import subprocess
    dirname = os.path.dirname(os.path.realpath(__file__))
    app_start = os.path.realpath(os.path.join(dirname, '..', 'start.py'))
    cmds = [sys.executable, app_start]
    if hasattr(sys.flags, 'safe_path'):
        cmds[1:1] = ['-P']
    subprocess.Popen(cmds)

if sys.platform.startswith('win'):
    import win_tray
elif sys.platform.startswith('linux'):
    no_tray()
elif sys.platform == 'darwin':
    no_tray()
else:
    no_tray()
