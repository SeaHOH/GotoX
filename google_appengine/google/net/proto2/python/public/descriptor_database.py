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


"""Provides a container for DescriptorProtos."""




class Error(Exception):
  pass


class DescriptorDatabaseConflictingDefinitionError(Error):
  """Raised when a proto is added with the same name & different descriptor."""


class DescriptorDatabase(object):
  """A container accepting FileDescriptorProtos and maps DescriptorProtos."""

  def __init__(self):
    self._file_desc_protos_by_file = {}
    self._file_desc_protos_by_symbol = {}

  def Add(self, file_desc_proto):
    """Adds the FileDescriptorProto and its types to this database.

    Args:
      file_desc_proto: The FileDescriptorProto to add.
    Raises:
      DescriptorDatabaseException: if an attempt is made to add a proto
        with the same name but different definition than an exisiting
        proto in the database.
    """
    proto_name = file_desc_proto.name
    if proto_name not in self._file_desc_protos_by_file:
      self._file_desc_protos_by_file[proto_name] = file_desc_proto
    elif self._file_desc_protos_by_file[proto_name] != file_desc_proto:
      raise DescriptorDatabaseConflictingDefinitionError(
          '%s already added, but with different descriptor.' % proto_name)

    package = file_desc_proto.package
    for message in file_desc_proto.message_type:
      self._file_desc_protos_by_symbol.update(
          (name, file_desc_proto) for name in _ExtractSymbols(message, package))
    for enum in file_desc_proto.enum_type:
      self._file_desc_protos_by_symbol[
          '.'.join((package, enum.name))] = file_desc_proto

  def FindFileByName(self, name):
    """Finds the file descriptor proto by file name.

    Typically the file name is a relative path ending to a .proto file. The
    proto with the given name will have to have been added to this database
    using the Add method or else an error will be raised.

    Args:
      name: The file name to find.

    Returns:
      The file descriptor proto matching the name.

    Raises:
      KeyError if no file by the given name was added.
    """

    return self._file_desc_protos_by_file[name]

  def FindFileContainingSymbol(self, symbol):
    """Finds the file descriptor proto containing the specified symbol.

    The symbol should be a fully qualified name including the file descriptor's
    package and any containing messages. Some examples:

    'some.package.name.Message'
    'some.package.name.Message.NestedEnum'

    The file descriptor proto containing the specified symbol must be added to
    this database using the Add method or else an error will be raised.

    Args:
      symbol: The fully qualified symbol name.

    Returns:
      The file descriptor proto containing the symbol.

    Raises:
      KeyError if no file contains the specified symbol.
    """

    return self._file_desc_protos_by_symbol[symbol]


def _ExtractSymbols(desc_proto, package):
  """Pulls out all the symbols from a descriptor proto.

  Args:
    desc_proto: The proto to extract symbols from.
    package: The package containing the descriptor type.

  Yields:
    The fully qualified name found in the descriptor.
  """

  message_name = '.'.join((package, desc_proto.name))
  yield message_name
  for nested_type in desc_proto.nested_type:
    for symbol in _ExtractSymbols(nested_type, message_name):
      yield symbol
  for enum_type in desc_proto.enum_type:
    yield '.'.join((message_name, enum_type.name))
