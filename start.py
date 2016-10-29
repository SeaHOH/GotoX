#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
sys.dont_write_bytecode = True

__file__ = os.path.abspath(__file__)
if os.path.islink(__file__):
    __file__ = getattr(os, 'readlink', lambda x: x)(__file__)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from local import proxy
proxy.main()
