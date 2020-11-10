// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.12.4
// source: objectID.proto

package protos

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type ObjectID struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hex string `protobuf:"bytes,1,opt,name=hex,proto3" json:"hex,omitempty"`
}

func (x *ObjectID) Reset() {
	*x = ObjectID{}
	if protoimpl.UnsafeEnabled {
		mi := &file_objectID_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ObjectID) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ObjectID) ProtoMessage() {}

func (x *ObjectID) ProtoReflect() protoreflect.Message {
	mi := &file_objectID_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ObjectID.ProtoReflect.Descriptor instead.
func (*ObjectID) Descriptor() ([]byte, []int) {
	return file_objectID_proto_rawDescGZIP(), []int{0}
}

func (x *ObjectID) GetHex() string {
	if x != nil {
		return x.Hex
	}
	return ""
}

var File_objectID_proto protoreflect.FileDescriptor

var file_objectID_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x44, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x22, 0x1c, 0x0a, 0x08, 0x4f, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x49, 0x44, 0x12, 0x10, 0x0a, 0x03, 0x68, 0x65, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x68, 0x65, 0x78, 0x42, 0x0a, 0x5a, 0x08, 0x2e, 0x3b, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_objectID_proto_rawDescOnce sync.Once
	file_objectID_proto_rawDescData = file_objectID_proto_rawDesc
)

func file_objectID_proto_rawDescGZIP() []byte {
	file_objectID_proto_rawDescOnce.Do(func() {
		file_objectID_proto_rawDescData = protoimpl.X.CompressGZIP(file_objectID_proto_rawDescData)
	})
	return file_objectID_proto_rawDescData
}

var file_objectID_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_objectID_proto_goTypes = []interface{}{
	(*ObjectID)(nil), // 0: protos.ObjectID
}
var file_objectID_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_objectID_proto_init() }
func file_objectID_proto_init() {
	if File_objectID_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_objectID_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ObjectID); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_objectID_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_objectID_proto_goTypes,
		DependencyIndexes: file_objectID_proto_depIdxs,
		MessageInfos:      file_objectID_proto_msgTypes,
	}.Build()
	File_objectID_proto = out.File
	file_objectID_proto_rawDesc = nil
	file_objectID_proto_goTypes = nil
	file_objectID_proto_depIdxs = nil
}