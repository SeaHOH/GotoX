#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

sys.dont_write_bytecode = True

import warnings
warnings.filterwarnings('ignore', '"is" with a literal', SyntaxWarning, append=True) # py38+

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from local import proxy
proxy.main()
