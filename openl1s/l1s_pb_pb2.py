# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: l1s_pb.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import descriptor_pb2 as google_dot_protobuf_dot_descriptor__pb2
from google.protobuf import empty_pb2 as google_dot_protobuf_dot_empty__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0cl1s_pb.proto\x12\x06l1s_pb\x1a google/protobuf/descriptor.proto\x1a\x1bgoogle/protobuf/empty.proto\"%\n\x06\x43onfig\x12\x1b\n\x05links\x18\x01 \x03(\x0b\x32\x0c.l1s_pb.Link\"\xb6\x01\n\x04Link\x12\x10\n\x03src\x18\x01 \x01(\tH\x00\x88\x01\x01\x12\x10\n\x03\x64st\x18\x02 \x01(\tH\x01\x88\x01\x01\x12)\n\x04mode\x18\x03 \x01(\x0e\x32\x16.l1s_pb.Link.Mode.EnumH\x02\x88\x01\x01\x1a\x46\n\x04Mode\">\n\x04\x45num\x12\x0f\n\x0bunspecified\x10\x00\x12\x12\n\x0eunidirectional\x10\x01\x12\x11\n\rbidirectional\x10\x02\x42\x06\n\x04_srcB\x06\n\x04_dstB\x07\n\x05_mode\"\xa7\x01\n\x05\x45rror\x12\x11\n\x04\x63ode\x18\x01 \x01(\x05H\x00\x88\x01\x01\x12*\n\x04kind\x18\x02 \x01(\x0e\x32\x17.l1s_pb.Error.Kind.EnumH\x01\x88\x01\x01\x12\x0e\n\x06\x65rrors\x18\x03 \x03(\t\x1a=\n\x04Kind\"5\n\x04\x45num\x12\x0f\n\x0bunspecified\x10\x00\x12\x0e\n\nvalidation\x10\x01\x12\x0c\n\x08internal\x10\x02\x42\x07\n\x05_codeB\x07\n\x05_kind\"\x1b\n\x07Warning\x12\x10\n\x08warnings\x18\x01 \x03(\t\"\x91\x01\n\x07Version\x12\x1d\n\x10\x61pi_spec_version\x18\x01 \x01(\tH\x00\x88\x01\x01\x12\x18\n\x0bsdk_version\x18\x02 \x01(\tH\x01\x88\x01\x01\x12\x18\n\x0b\x61pp_version\x18\x03 \x01(\tH\x02\x88\x01\x01\x42\x13\n\x11_api_spec_versionB\x0e\n\x0c_sdk_versionB\x0e\n\x0c_app_version\"+\n\x07Success\x12 \n\x07warning\x18\x01 \x01(\x0b\x32\x0f.l1s_pb.Warning\"\'\n\x07\x46\x61ilure\x12\x1c\n\x05\x65rror\x18\x01 \x01(\x0b\x32\r.l1s_pb.Error\"2\n\x10SetConfigRequest\x12\x1e\n\x06\x63onfig\x18\x01 \x01(\x0b\x32\x0e.l1s_pb.Config\"#\n\x11SetConfigResponse\x12\x0e\n\x06string\x18\x01 \x01(\t\"6\n\x12GetVersionResponse\x12 \n\x07version\x18\x01 \x01(\x0b\x32\x0f.l1s_pb.Version2\x8d\x01\n\x07Openapi\x12@\n\tSetConfig\x12\x18.l1s_pb.SetConfigRequest\x1a\x19.l1s_pb.SetConfigResponse\x12@\n\nGetVersion\x12\x16.google.protobuf.Empty\x1a\x1a.l1s_pb.GetVersionResponseB\x11Z\x0f./l1s_pb;l1s_pbb\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'l1s_pb_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'Z\017./l1s_pb;l1s_pb'
  _CONFIG._serialized_start=87
  _CONFIG._serialized_end=124
  _LINK._serialized_start=127
  _LINK._serialized_end=309
  _LINK_MODE._serialized_start=214
  _LINK_MODE._serialized_end=284
  _LINK_MODE_ENUM._serialized_start=222
  _LINK_MODE_ENUM._serialized_end=284
  _ERROR._serialized_start=312
  _ERROR._serialized_end=479
  _ERROR_KIND._serialized_start=400
  _ERROR_KIND._serialized_end=461
  _ERROR_KIND_ENUM._serialized_start=408
  _ERROR_KIND_ENUM._serialized_end=461
  _WARNING._serialized_start=481
  _WARNING._serialized_end=508
  _VERSION._serialized_start=511
  _VERSION._serialized_end=656
  _SUCCESS._serialized_start=658
  _SUCCESS._serialized_end=701
  _FAILURE._serialized_start=703
  _FAILURE._serialized_end=742
  _SETCONFIGREQUEST._serialized_start=744
  _SETCONFIGREQUEST._serialized_end=794
  _SETCONFIGRESPONSE._serialized_start=796
  _SETCONFIGRESPONSE._serialized_end=831
  _GETVERSIONRESPONSE._serialized_start=833
  _GETVERSIONRESPONSE._serialized_end=887
  _OPENAPI._serialized_start=890
  _OPENAPI._serialized_end=1031
# @@protoc_insertion_point(module_scope)
