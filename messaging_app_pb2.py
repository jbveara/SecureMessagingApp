# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: messaging-app.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x13messaging-app.proto\"6\n\x04User\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x12\n\nip_address\x18\x02 \x01(\t\x12\x0c\n\x04port\x18\x03 \x01(\x05\"\x1f\n\x0bListRequest\x12\x10\n\x08\x64\x65tailed\x18\x01 \x01(\x08\"5\n\x0cListResponse\x12\x13\n\x04user\x18\x01 \x03(\x0b\x32\x05.User\x12\x10\n\x08\x64\x65tailed\x18\x02 \x01(\x08\":\n\x0fUserInfoRequest\x12\x12\n\nrequest_id\x18\x01 \x01(\x05\x12\x13\n\x04user\x18\x02 \x01(\x0b\x32\x05.User\";\n\x10UserInfoResponse\x12\x12\n\nrequest_id\x18\x01 \x01(\x05\x12\x13\n\x04user\x18\x02 \x01(\x0b\x32\x05.User\"\x17\n\x08\x42\x61sicMsg\x12\x0b\n\x03msg\x18\x01 \x01(\tb\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'messaging_app_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _USER._serialized_start=23
  _USER._serialized_end=77
  _LISTREQUEST._serialized_start=79
  _LISTREQUEST._serialized_end=110
  _LISTRESPONSE._serialized_start=112
  _LISTRESPONSE._serialized_end=165
  _USERINFOREQUEST._serialized_start=167
  _USERINFOREQUEST._serialized_end=225
  _USERINFORESPONSE._serialized_start=227
  _USERINFORESPONSE._serialized_end=286
  _BASICMSG._serialized_start=288
  _BASICMSG._serialized_end=311
# @@protoc_insertion_point(module_scope)
