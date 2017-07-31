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


"""Provides a factory class for generating dynamic messages.

The easiest way to use this class is if you have access to the FileDescriptor
protos containing the messages you want to create you can just do the following:

message_classes = message_factory.GetMessages(iterable_of_file_descriptors)
my_proto_instance = message_classes['some.proto.package.MessageName']()
"""



from google.net.proto2.python.public import descriptor_pool
from google.net.proto2.python.public import message
from google.net.proto2.python.public import reflection


class MessageFactory(object):
  """Factory for creating Proto2 messages from descriptors in a pool."""

  def __init__(self, pool=None):
    """Initializes a new factory."""
    self.pool = pool or descriptor_pool.DescriptorPool()


    self._classes = {}

  def GetPrototype(self, descriptor):
    """Builds a proto2 message class based on the passed in descriptor.

    Passing a descriptor with a fully qualified name matching a previous
    invocation will cause the same class to be returned.

    Args:
      descriptor: The descriptor to build from.

    Returns:
      A class describing the passed in descriptor.
    """
    if descriptor.full_name not in self._classes:
      descriptor_name = descriptor.name
      if str is bytes:
        descriptor_name = descriptor.name.encode('ascii', 'ignore')
      result_class = reflection.GeneratedProtocolMessageType(
          descriptor_name,
          (message.Message,),
          {'DESCRIPTOR': descriptor, '__module__': None})

      self._classes[descriptor.full_name] = result_class
      for field in descriptor.fields:
        if field.message_type:
          self.GetPrototype(field.message_type)
      for extension in result_class.DESCRIPTOR.extensions:
        if extension.containing_type.full_name not in self._classes:
          self.GetPrototype(extension.containing_type)
        extended_class = self._classes[extension.containing_type.full_name]
        extended_class.RegisterExtension(extension)
    return self._classes[descriptor.full_name]

  def GetMessages(self, files):
    """Gets all the messages from a specified file.

    This will find and resolve dependencies, failing if the descriptor
    pool cannot satisfy them.

    Args:
      files: The file names to extract messages from.

    Returns:
      A dictionary mapping proto names to the message classes. This will include
      any dependent messages as well as any messages defined in the same file as
      a specified message.
    """
    result = {}
    for file_name in files:
      file_desc = self.pool.FindFileByName(file_name)
      for desc in file_desc.message_types_by_name.values():
        result[desc.full_name] = self.GetPrototype(desc)










      for extension in file_desc.extensions_by_name.values():
        if extension.containing_type.full_name not in self._classes:
          self.GetPrototype(extension.containing_type)
        extended_class = self._classes[extension.containing_type.full_name]
        extended_class.RegisterExtension(extension)
    return result


_FACTORY = MessageFactory()


def GetMessages(file_protos):
  """Builds a dictionary of all the messages available in a set of files.

  Args:
    file_protos: A sequence of file protos to build messages out of.

  Returns:
    A dictionary mapping proto names to the message classes. This will include
    any dependent messages as well as any messages defined in the same file as
    a specified message.
  """
  for file_proto in file_protos:
    _FACTORY.pool.Add(file_proto)
  return _FACTORY.GetMessages([file_proto.name for file_proto in file_protos])
