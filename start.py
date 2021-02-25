#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

sys.dont_write_bytecode = True

import warnings

warnings.filterwarnings('ignore', '"is" with a literal', SyntaxWarning, append=True) # py38+

dirname = os.path.dirname(os.path.realpath(__file__))
try:
    if os.name == 'nt' and sys.getwindowsversion() > (6, 2):
        for dirpath, _, filenames in os.walk(os.path.join(dirname, 'python')):
            for filename in filenames:
                if filename == 'install_dll.bat' or filename.endswith('.w7'):
                    os.remove(os.path.join(dirpath, filename))
            break
except:
    pass

sys.path.insert(0, dirname)
from local import proxy
proxy.main()
