// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v5.26.1
// source: envoy/extensions/filters/http/lua/v3/lua.proto

package luav3

import (
	_ "github.com/cncf/xds/go/udpa/annotations"
	_ "github.com/emissary-ingress/emissary/v3/pkg/api/envoy/annotations"
	v3 "github.com/emissary-ingress/emissary/v3/pkg/api/envoy/config/core/v3"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
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

type Lua struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The Lua code that Envoy will execute. This can be a very small script that
	// further loads code from disk if desired. Note that if JSON configuration is used, the code must
	// be properly escaped. YAML configuration may be easier to read since YAML supports multi-line
	// strings so complex scripts can be easily expressed inline in the configuration.
	//
	// This field is deprecated. Please use
	// :ref:`default_source_code <envoy_v3_api_field_extensions.filters.http.lua.v3.Lua.default_source_code>`.
	// Only one of :ref:`inline_code <envoy_v3_api_field_extensions.filters.http.lua.v3.Lua.inline_code>`
	// or :ref:`default_source_code <envoy_v3_api_field_extensions.filters.http.lua.v3.Lua.default_source_code>`
	// can be set for the Lua filter.
	//
	// Deprecated: Marked as deprecated in envoy/extensions/filters/http/lua/v3/lua.proto.
	InlineCode string `protobuf:"bytes,1,opt,name=inline_code,json=inlineCode,proto3" json:"inline_code,omitempty"`
	// Map of named Lua source codes that can be referenced in :ref:`LuaPerRoute
	// <envoy_v3_api_msg_extensions.filters.http.lua.v3.LuaPerRoute>`. The Lua source codes can be
	// loaded from inline string or local files.
	//
	// Example:
	//
	// .. code-block:: yaml
	//
	//	source_codes:
	//	  hello.lua:
	//	    inline_string: |
	//	      function envoy_on_response(response_handle)
	//	        -- Do something.
	//	      end
	//	  world.lua:
	//	    filename: /etc/lua/world.lua
	SourceCodes map[string]*v3.DataSource `protobuf:"bytes,2,rep,name=source_codes,json=sourceCodes,proto3" json:"source_codes,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// The default Lua code that Envoy will execute. If no per route config is provided
	// for the request, this Lua code will be applied.
	DefaultSourceCode *v3.DataSource `protobuf:"bytes,3,opt,name=default_source_code,json=defaultSourceCode,proto3" json:"default_source_code,omitempty"`
	// Optional additional prefix to use when emitting statistics. By default
	// metrics are emitted in *.lua.* namespace. If multiple lua filters are
	// configured in a filter chain, the stats from each filter instance can
	// be emitted using custom stat prefix to distinguish emitted
	// statistics. For example:
	//
	// .. code-block:: yaml
	//
	//	http_filters:
	//	  - name: envoy.filters.http.lua
	//	    typed_config:
	//	      "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
	//	      stat_prefix: foo_script # This emits lua.foo_script.errors etc.
	//	  - name: envoy.filters.http.lua
	//	    typed_config:
	//	      "@type": type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua
	//	      stat_prefix: bar_script # This emits lua.bar_script.errors etc.
	StatPrefix string `protobuf:"bytes,4,opt,name=stat_prefix,json=statPrefix,proto3" json:"stat_prefix,omitempty"`
}

func (x *Lua) Reset() {
	*x = Lua{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_filters_http_lua_v3_lua_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Lua) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Lua) ProtoMessage() {}

func (x *Lua) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_filters_http_lua_v3_lua_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Lua.ProtoReflect.Descriptor instead.
func (*Lua) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_http_lua_v3_lua_proto_rawDescGZIP(), []int{0}
}

// Deprecated: Marked as deprecated in envoy/extensions/filters/http/lua/v3/lua.proto.
func (x *Lua) GetInlineCode() string {
	if x != nil {
		return x.InlineCode
	}
	return ""
}

func (x *Lua) GetSourceCodes() map[string]*v3.DataSource {
	if x != nil {
		return x.SourceCodes
	}
	return nil
}

func (x *Lua) GetDefaultSourceCode() *v3.DataSource {
	if x != nil {
		return x.DefaultSourceCode
	}
	return nil
}

func (x *Lua) GetStatPrefix() string {
	if x != nil {
		return x.StatPrefix
	}
	return ""
}

type LuaPerRoute struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Override:
	//
	//	*LuaPerRoute_Disabled
	//	*LuaPerRoute_Name
	//	*LuaPerRoute_SourceCode
	Override isLuaPerRoute_Override `protobuf_oneof:"override"`
}

func (x *LuaPerRoute) Reset() {
	*x = LuaPerRoute{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_filters_http_lua_v3_lua_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LuaPerRoute) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LuaPerRoute) ProtoMessage() {}

func (x *LuaPerRoute) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_filters_http_lua_v3_lua_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LuaPerRoute.ProtoReflect.Descriptor instead.
func (*LuaPerRoute) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_http_lua_v3_lua_proto_rawDescGZIP(), []int{1}
}

func (m *LuaPerRoute) GetOverride() isLuaPerRoute_Override {
	if m != nil {
		return m.Override
	}
	return nil
}

func (x *LuaPerRoute) GetDisabled() bool {
	if x, ok := x.GetOverride().(*LuaPerRoute_Disabled); ok {
		return x.Disabled
	}
	return false
}

func (x *LuaPerRoute) GetName() string {
	if x, ok := x.GetOverride().(*LuaPerRoute_Name); ok {
		return x.Name
	}
	return ""
}

func (x *LuaPerRoute) GetSourceCode() *v3.DataSource {
	if x, ok := x.GetOverride().(*LuaPerRoute_SourceCode); ok {
		return x.SourceCode
	}
	return nil
}

type isLuaPerRoute_Override interface {
	isLuaPerRoute_Override()
}

type LuaPerRoute_Disabled struct {
	// Disable the Lua filter for this particular vhost or route. If disabled is specified in
	// multiple per-filter-configs, the most specific one will be used.
	Disabled bool `protobuf:"varint,1,opt,name=disabled,proto3,oneof"`
}

type LuaPerRoute_Name struct {
	// A name of a Lua source code stored in
	// :ref:`Lua.source_codes <envoy_v3_api_field_extensions.filters.http.lua.v3.Lua.source_codes>`.
	Name string `protobuf:"bytes,2,opt,name=name,proto3,oneof"`
}

type LuaPerRoute_SourceCode struct {
	// A configured per-route Lua source code that can be served by RDS or provided inline.
	SourceCode *v3.DataSource `protobuf:"bytes,3,opt,name=source_code,json=sourceCode,proto3,oneof"`
}

func (*LuaPerRoute_Disabled) isLuaPerRoute_Override() {}

func (*LuaPerRoute_Name) isLuaPerRoute_Override() {}

func (*LuaPerRoute_SourceCode) isLuaPerRoute_Override() {}

var File_envoy_extensions_filters_http_lua_v3_lua_proto protoreflect.FileDescriptor

var file_envoy_extensions_filters_http_lua_v3_lua_proto_rawDesc = []byte{
	0x0a, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x2f,
	0x6c, 0x75, 0x61, 0x2f, 0x76, 0x33, 0x2f, 0x6c, 0x75, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x24, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e,
	0x6c, 0x75, 0x61, 0x2e, 0x76, 0x33, 0x1a, 0x1f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x33, 0x2f, 0x62, 0x61, 0x73,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x23, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x61,
	0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x64, 0x65, 0x70, 0x72, 0x65,
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75, 0x64,
	0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73,
	0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x21, 0x75, 0x64, 0x70,
	0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17,
	0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x93, 0x03, 0x0a, 0x03, 0x4c, 0x75, 0x61, 0x12,
	0x2c, 0x0a, 0x0b, 0x69, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x42, 0x0b, 0x92, 0xc7, 0x86, 0xd8, 0x04, 0x03, 0x33, 0x2e, 0x30, 0x18,
	0x01, 0x52, 0x0a, 0x69, 0x6e, 0x6c, 0x69, 0x6e, 0x65, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x5d, 0x0a,
	0x0c, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x73, 0x18, 0x02, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x3a, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65,
	0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x68,
	0x74, 0x74, 0x70, 0x2e, 0x6c, 0x75, 0x61, 0x2e, 0x76, 0x33, 0x2e, 0x4c, 0x75, 0x61, 0x2e, 0x53,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x43, 0x6f, 0x64, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52,
	0x0b, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x43, 0x6f, 0x64, 0x65, 0x73, 0x12, 0x50, 0x0a, 0x13,
	0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x5f, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x63,
	0x6f, 0x64, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x65, 0x6e, 0x76, 0x6f,
	0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x33,
	0x2e, 0x44, 0x61, 0x74, 0x61, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x52, 0x11, 0x64, 0x65, 0x66,
	0x61, 0x75, 0x6c, 0x74, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x1f,
	0x0a, 0x0b, 0x73, 0x74, 0x61, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0a, 0x73, 0x74, 0x61, 0x74, 0x50, 0x72, 0x65, 0x66, 0x69, 0x78, 0x1a,
	0x60, 0x0a, 0x10, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x43, 0x6f, 0x64, 0x65, 0x73, 0x45, 0x6e,
	0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x36, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x33, 0x2e, 0x44, 0x61, 0x74, 0x61,
	0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38,
	0x01, 0x3a, 0x2a, 0x9a, 0xc5, 0x88, 0x1e, 0x25, 0x0a, 0x23, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x2e, 0x68, 0x74,
	0x74, 0x70, 0x2e, 0x6c, 0x75, 0x61, 0x2e, 0x76, 0x32, 0x2e, 0x4c, 0x75, 0x61, 0x22, 0xa9, 0x01,
	0x0a, 0x0b, 0x4c, 0x75, 0x61, 0x50, 0x65, 0x72, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x12, 0x25, 0x0a,
	0x08, 0x64, 0x69, 0x73, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x42,
	0x07, 0xfa, 0x42, 0x04, 0x6a, 0x02, 0x08, 0x01, 0x48, 0x00, 0x52, 0x08, 0x64, 0x69, 0x73, 0x61,
	0x62, 0x6c, 0x65, 0x64, 0x12, 0x1d, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02, 0x10, 0x01, 0x48, 0x00, 0x52, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x12, 0x43, 0x0a, 0x0b, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x63, 0x6f,
	0x64, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x33, 0x2e,
	0x44, 0x61, 0x74, 0x61, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x48, 0x00, 0x52, 0x0a, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x43, 0x6f, 0x64, 0x65, 0x42, 0x0f, 0x0a, 0x08, 0x6f, 0x76, 0x65, 0x72,
	0x72, 0x69, 0x64, 0x65, 0x12, 0x03, 0xf8, 0x42, 0x01, 0x42, 0x9b, 0x01, 0xba, 0x80, 0xc8, 0xd1,
	0x06, 0x02, 0x10, 0x02, 0x0a, 0x32, 0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73,
	0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x68, 0x74, 0x74,
	0x70, 0x2e, 0x6c, 0x75, 0x61, 0x2e, 0x76, 0x33, 0x42, 0x08, 0x4c, 0x75, 0x61, 0x50, 0x72, 0x6f,
	0x74, 0x6f, 0x50, 0x01, 0x5a, 0x51, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67, 0x6f, 0x2d, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x65, 0x6e, 0x76,
	0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x66, 0x69,
	0x6c, 0x74, 0x65, 0x72, 0x73, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x6c, 0x75, 0x61, 0x2f, 0x76,
	0x33, 0x3b, 0x6c, 0x75, 0x61, 0x76, 0x33, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_extensions_filters_http_lua_v3_lua_proto_rawDescOnce sync.Once
	file_envoy_extensions_filters_http_lua_v3_lua_proto_rawDescData = file_envoy_extensions_filters_http_lua_v3_lua_proto_rawDesc
)

func file_envoy_extensions_filters_http_lua_v3_lua_proto_rawDescGZIP() []byte {
	file_envoy_extensions_filters_http_lua_v3_lua_proto_rawDescOnce.Do(func() {
		file_envoy_extensions_filters_http_lua_v3_lua_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_extensions_filters_http_lua_v3_lua_proto_rawDescData)
	})
	return file_envoy_extensions_filters_http_lua_v3_lua_proto_rawDescData
}

var file_envoy_extensions_filters_http_lua_v3_lua_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_envoy_extensions_filters_http_lua_v3_lua_proto_goTypes = []interface{}{
	(*Lua)(nil),           // 0: envoy.extensions.filters.http.lua.v3.Lua
	(*LuaPerRoute)(nil),   // 1: envoy.extensions.filters.http.lua.v3.LuaPerRoute
	nil,                   // 2: envoy.extensions.filters.http.lua.v3.Lua.SourceCodesEntry
	(*v3.DataSource)(nil), // 3: envoy.config.core.v3.DataSource
}
var file_envoy_extensions_filters_http_lua_v3_lua_proto_depIdxs = []int32{
	2, // 0: envoy.extensions.filters.http.lua.v3.Lua.source_codes:type_name -> envoy.extensions.filters.http.lua.v3.Lua.SourceCodesEntry
	3, // 1: envoy.extensions.filters.http.lua.v3.Lua.default_source_code:type_name -> envoy.config.core.v3.DataSource
	3, // 2: envoy.extensions.filters.http.lua.v3.LuaPerRoute.source_code:type_name -> envoy.config.core.v3.DataSource
	3, // 3: envoy.extensions.filters.http.lua.v3.Lua.SourceCodesEntry.value:type_name -> envoy.config.core.v3.DataSource
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_envoy_extensions_filters_http_lua_v3_lua_proto_init() }
func file_envoy_extensions_filters_http_lua_v3_lua_proto_init() {
	if File_envoy_extensions_filters_http_lua_v3_lua_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_extensions_filters_http_lua_v3_lua_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Lua); i {
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
		file_envoy_extensions_filters_http_lua_v3_lua_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LuaPerRoute); i {
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
	file_envoy_extensions_filters_http_lua_v3_lua_proto_msgTypes[1].OneofWrappers = []interface{}{
		(*LuaPerRoute_Disabled)(nil),
		(*LuaPerRoute_Name)(nil),
		(*LuaPerRoute_SourceCode)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_envoy_extensions_filters_http_lua_v3_lua_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_extensions_filters_http_lua_v3_lua_proto_goTypes,
		DependencyIndexes: file_envoy_extensions_filters_http_lua_v3_lua_proto_depIdxs,
		MessageInfos:      file_envoy_extensions_filters_http_lua_v3_lua_proto_msgTypes,
	}.Build()
	File_envoy_extensions_filters_http_lua_v3_lua_proto = out.File
	file_envoy_extensions_filters_http_lua_v3_lua_proto_rawDesc = nil
	file_envoy_extensions_filters_http_lua_v3_lua_proto_goTypes = nil
	file_envoy_extensions_filters_http_lua_v3_lua_proto_depIdxs = nil
}
