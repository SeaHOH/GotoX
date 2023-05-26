#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

sys.dont_write_bytecode = True

if not getattr(sys.flags, 'safe_path', None):
    for i, path in sorted(enumerate(sys.path), reverse=True):
        if path == '':
            del sys.path[i]


import warnings

warnings.filterwarnings('ignore', '"is" with a literal', SyntaxWarning, append=True) # py38+


dirpath = os.path.dirname(os.path.realpath(__file__))
try:
    if os.name == 'nt' and sys.getwindowsversion() > (6, 2):
        for filename in os.listdir(os.path.join(dirpath, 'python')):
            if filename == 'install_dll.bat' or filename.endswith('.w7'):
                os.remove(os.path.join(dirpath, filename))
except:
    pass


from _frozen_importlib_external import spec_from_file_location
from _frozen_importlib import _load

filepath = os.path.join(dirpath, 'local', '__init__.py')
_load(spec_from_file_location('gotox', filepath))

from gotox import proxy
proxy.main()
