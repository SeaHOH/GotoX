#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


"""Determine which implementation of the protobuf API is used in this process.
"""

import os
import sys

try:

  from google.net.proto2.python.internal import _api_implementation


  _api_version = _api_implementation.api_version
  _proto_extension_modules_exist_in_build = True
except ImportError:
  _api_version = -1
  _proto_extension_modules_exist_in_build = False

if _api_version == 1:
  raise ValueError('api_version=1 is no longer supported.')
if _api_version < 0:
  try:




    from google.net.proto2.python.public import _use_fast_cpp_protos

    if not _use_fast_cpp_protos:
      raise ImportError('_use_fast_cpp_protos import succeeded but was None')
    del _use_fast_cpp_protos
    _api_version = 2
  except ImportError:
    if _proto_extension_modules_exist_in_build:
      if sys.version_info[0] >= 3:
        _api_version = 2


_default_implementation_type = (
    'python' if _api_version <= 0 else 'cpp')





_implementation_type = os.getenv('PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION',
                                 _default_implementation_type)

if _implementation_type != 'python':
  _implementation_type = 'cpp'





_implementation_version_str = os.getenv(
    'PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION_VERSION', '2')

if _implementation_version_str != '2':
  raise ValueError(
      'unsupported PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION_VERSION: "' +
      _implementation_version_str + '" (supported versions: 2)'
      )

_implementation_version = int(_implementation_version_str)






def Type():
  return _implementation_type



def Version():
  return _implementation_version
