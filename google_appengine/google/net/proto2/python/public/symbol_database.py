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
"""A database of Python protocol buffer generated symbols.

SymbolDatabase makes it easy to create new instances of a registered type, given
only the type's protocol buffer symbol name. Once all symbols are registered,
they can be accessed using either the MessageFactory interface which
SymbolDatabase exposes, or the DescriptorPool interface of the underlying
pool.

Example usage:

  db = symbol_database.SymbolDatabase()

  # Register symbols of interest, from one or multiple files.
  db.RegisterFileDescriptor(my_proto_pb2.DESCRIPTOR)
  db.RegisterMessage(my_proto_pb2.MyMessage)
  db.RegisterEnumDescriptor(my_proto_pb2.MyEnum.DESCRIPTOR)

  # The database can be used as a MessageFactory, to generate types based on
  # their name:
  types = db.GetMessages(['my_proto.proto'])
  my_message_instance = types['MyMessage']()

  # The database's underlying descriptor pool can be queried, so it's not
  # necessary to know a type's filename to be able to generate it:
  filename = db.pool.FindFileContainingSymbol('MyMessage')
  my_message_instance = db.GetMessages([filename])['MyMessage']()

  # This functionality is also provided directly via a convenience method:
  my_message_instance = db.GetSymbol('MyMessage')()
"""


from google.net.proto2.python.public import descriptor_pool


class SymbolDatabase(object):
  """A database of Python generated symbols.

  SymbolDatabase also models message_factory.MessageFactory.

  The symbol database can be used to keep a global registry of all protocol
  buffer types used within a program.
  """

  def __init__(self):
    """Constructor."""

    self._symbols = {}
    self._symbols_by_file = {}
    self.pool = descriptor_pool.DescriptorPool()

  def RegisterMessage(self, message):
    """Registers the given message type in the local database.

    Args:
      message: a message.Message, to be registered.

    Returns:
      The provided message.
    """

    desc = message.DESCRIPTOR
    self._symbols[desc.full_name] = message
    if desc.file.name not in self._symbols_by_file:
      self._symbols_by_file[desc.file.name] = {}
    self._symbols_by_file[desc.file.name][desc.full_name] = message
    self.pool.AddDescriptor(desc)
    return message

  def RegisterEnumDescriptor(self, enum_descriptor):
    """Registers the given enum descriptor in the local database.

    Args:
      enum_descriptor: a descriptor.EnumDescriptor.

    Returns:
      The provided descriptor.
    """
    self.pool.AddEnumDescriptor(enum_descriptor)
    return enum_descriptor

  def RegisterFileDescriptor(self, file_descriptor):
    """Registers the given file descriptor in the local database.

    Args:
      file_descriptor: a descriptor.FileDescriptor.

    Returns:
      The provided descriptor.
    """
    self.pool.AddFileDescriptor(file_descriptor)

  def GetSymbol(self, symbol):
    """Tries to find a symbol in the local database.

    Currently, this method only returns message.Message instances, however, if
    may be extended in future to support other symbol types.

    Args:
      symbol: A str, a protocol buffer symbol.

    Returns:
      A Python class corresponding to the symbol.

    Raises:
      KeyError: if the symbol could not be found.
    """

    return self._symbols[symbol]

  def GetPrototype(self, descriptor):
    """Builds a proto2 message class based on the passed in descriptor.

    Passing a descriptor with a fully qualified name matching a previous
    invocation will cause the same class to be returned.

    Args:
      descriptor: The descriptor to build from.

    Returns:
      A class describing the passed in descriptor.
    """

    return self.GetSymbol(descriptor.full_name)

  def GetMessages(self, files):
    """Gets all the messages from a specified file.

    This will find and resolve dependencies, failing if they are not registered
    in the symbol database.


    Args:
      files: The file names to extract messages from.

    Returns:
      A dictionary mapping proto names to the message classes. This will include
      any dependent messages as well as any messages defined in the same file as
      a specified message.

    Raises:
      KeyError: if a file could not be found.
    """

    result = {}
    for f in files:
      result.update(self._symbols_by_file[f])
    return result

_DEFAULT = SymbolDatabase()


def Default():
  """Returns the default SymbolDatabase."""
  return _DEFAULT
