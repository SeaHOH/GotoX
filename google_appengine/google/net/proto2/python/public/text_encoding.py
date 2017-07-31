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


"""Encoding related utilities."""

import re
import sys


_cescape_utf8_to_str = [chr(i) for i in xrange(0, 256)]
_cescape_utf8_to_str[9] = r'\t'
_cescape_utf8_to_str[10] = r'\n'
_cescape_utf8_to_str[13] = r'\r'
_cescape_utf8_to_str[39] = r"\'"

_cescape_utf8_to_str[34] = r'\"'
_cescape_utf8_to_str[92] = r'\\'


_cescape_byte_to_str = ([r'\%03o' % i for i in xrange(0, 32)] +
                        [chr(i) for i in xrange(32, 127)] +
                        [r'\%03o' % i for i in xrange(127, 256)])
_cescape_byte_to_str[9] = r'\t'
_cescape_byte_to_str[10] = r'\n'
_cescape_byte_to_str[13] = r'\r'
_cescape_byte_to_str[39] = r"\'"

_cescape_byte_to_str[34] = r'\"'
_cescape_byte_to_str[92] = r'\\'


def CEscape(text, as_utf8):
  """Escape a bytes string for use in an ascii protocol buffer.

  text.encode('string_escape') does not seem to satisfy our needs as it
  encodes unprintable characters using two-digit hex escapes whereas our
  C++ unescaping function allows hex escapes to be any length.  So,
  "\0011".encode('string_escape') ends up being "\\x011", which will be
  decoded in C++ as a single-character string with char code 0x11.

  Args:
    text: A byte string to be escaped
    as_utf8: Specifies if result should be returned in UTF-8 encoding
  Returns:
    Escaped string
  """


  Ord = ord if isinstance(text, basestring) else lambda x: x
  if as_utf8:
    return ''.join(_cescape_utf8_to_str[Ord(c)] for c in text)
  return ''.join(_cescape_byte_to_str[Ord(c)] for c in text)


_CUNESCAPE_HEX = re.compile(r'(\\+)x([0-9a-fA-F])(?![0-9a-fA-F])')
_cescape_highbit_to_str = ([chr(i) for i in range(0, 127)] +
                           [r'\%03o' % i for i in range(127, 256)])


def CUnescape(text):
  """Unescape a text string with C-style escape sequences to UTF-8 bytes."""

  def ReplaceHex(m):


    if len(m.group(1)) & 1:
      return m.group(1) + 'x0' + m.group(2)
    return m.group(0)



  result = _CUNESCAPE_HEX.sub(ReplaceHex, text)

  if sys.version_info[0] < 3:

    return result.decode('string_escape')
  result = ''.join(_cescape_highbit_to_str[ord(c)] for c in result)
  return (result.encode('ascii')
          .decode('unicode_escape')

          .encode('raw_unicode_escape'))
