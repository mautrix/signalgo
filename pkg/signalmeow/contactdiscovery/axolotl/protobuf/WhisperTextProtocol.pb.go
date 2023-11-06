// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.4
// source: WhisperTextProtocol.proto

//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package textsecure

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

type SignalMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RatchetKey      []byte  `protobuf:"bytes,1,opt,name=ratchet_key,json=ratchetKey" json:"ratchet_key,omitempty"`
	Counter         *uint32 `protobuf:"varint,2,opt,name=counter" json:"counter,omitempty"`
	PreviousCounter *uint32 `protobuf:"varint,3,opt,name=previous_counter,json=previousCounter" json:"previous_counter,omitempty"`
	Ciphertext      []byte  `protobuf:"bytes,4,opt,name=ciphertext" json:"ciphertext,omitempty"`
}

func (x *SignalMessage) Reset() {
	*x = SignalMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_WhisperTextProtocol_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignalMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignalMessage) ProtoMessage() {}

func (x *SignalMessage) ProtoReflect() protoreflect.Message {
	mi := &file_WhisperTextProtocol_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignalMessage.ProtoReflect.Descriptor instead.
func (*SignalMessage) Descriptor() ([]byte, []int) {
	return file_WhisperTextProtocol_proto_rawDescGZIP(), []int{0}
}

func (x *SignalMessage) GetRatchetKey() []byte {
	if x != nil {
		return x.RatchetKey
	}
	return nil
}

func (x *SignalMessage) GetCounter() uint32 {
	if x != nil && x.Counter != nil {
		return *x.Counter
	}
	return 0
}

func (x *SignalMessage) GetPreviousCounter() uint32 {
	if x != nil && x.PreviousCounter != nil {
		return *x.PreviousCounter
	}
	return 0
}

func (x *SignalMessage) GetCiphertext() []byte {
	if x != nil {
		return x.Ciphertext
	}
	return nil
}

type PreKeySignalMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	RegistrationId *uint32 `protobuf:"varint,5,opt,name=registration_id,json=registrationId" json:"registration_id,omitempty"`
	PreKeyId       *uint32 `protobuf:"varint,1,opt,name=pre_key_id,json=preKeyId" json:"pre_key_id,omitempty"`
	SignedPreKeyId *uint32 `protobuf:"varint,6,opt,name=signed_pre_key_id,json=signedPreKeyId" json:"signed_pre_key_id,omitempty"`
	BaseKey        []byte  `protobuf:"bytes,2,opt,name=base_key,json=baseKey" json:"base_key,omitempty"`
	IdentityKey    []byte  `protobuf:"bytes,3,opt,name=identity_key,json=identityKey" json:"identity_key,omitempty"`
	Message        []byte  `protobuf:"bytes,4,opt,name=message" json:"message,omitempty"` // SignalMessage
}

func (x *PreKeySignalMessage) Reset() {
	*x = PreKeySignalMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_WhisperTextProtocol_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PreKeySignalMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PreKeySignalMessage) ProtoMessage() {}

func (x *PreKeySignalMessage) ProtoReflect() protoreflect.Message {
	mi := &file_WhisperTextProtocol_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PreKeySignalMessage.ProtoReflect.Descriptor instead.
func (*PreKeySignalMessage) Descriptor() ([]byte, []int) {
	return file_WhisperTextProtocol_proto_rawDescGZIP(), []int{1}
}

func (x *PreKeySignalMessage) GetRegistrationId() uint32 {
	if x != nil && x.RegistrationId != nil {
		return *x.RegistrationId
	}
	return 0
}

func (x *PreKeySignalMessage) GetPreKeyId() uint32 {
	if x != nil && x.PreKeyId != nil {
		return *x.PreKeyId
	}
	return 0
}

func (x *PreKeySignalMessage) GetSignedPreKeyId() uint32 {
	if x != nil && x.SignedPreKeyId != nil {
		return *x.SignedPreKeyId
	}
	return 0
}

func (x *PreKeySignalMessage) GetBaseKey() []byte {
	if x != nil {
		return x.BaseKey
	}
	return nil
}

func (x *PreKeySignalMessage) GetIdentityKey() []byte {
	if x != nil {
		return x.IdentityKey
	}
	return nil
}

func (x *PreKeySignalMessage) GetMessage() []byte {
	if x != nil {
		return x.Message
	}
	return nil
}

type SenderKeyMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DistributionUuid []byte  `protobuf:"bytes,1,opt,name=distribution_uuid,json=distributionUuid" json:"distribution_uuid,omitempty"`
	ChainId          *uint32 `protobuf:"varint,2,opt,name=chain_id,json=chainId" json:"chain_id,omitempty"`
	Iteration        *uint32 `protobuf:"varint,3,opt,name=iteration" json:"iteration,omitempty"`
	Ciphertext       []byte  `protobuf:"bytes,4,opt,name=ciphertext" json:"ciphertext,omitempty"`
}

func (x *SenderKeyMessage) Reset() {
	*x = SenderKeyMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_WhisperTextProtocol_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SenderKeyMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SenderKeyMessage) ProtoMessage() {}

func (x *SenderKeyMessage) ProtoReflect() protoreflect.Message {
	mi := &file_WhisperTextProtocol_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SenderKeyMessage.ProtoReflect.Descriptor instead.
func (*SenderKeyMessage) Descriptor() ([]byte, []int) {
	return file_WhisperTextProtocol_proto_rawDescGZIP(), []int{2}
}

func (x *SenderKeyMessage) GetDistributionUuid() []byte {
	if x != nil {
		return x.DistributionUuid
	}
	return nil
}

func (x *SenderKeyMessage) GetChainId() uint32 {
	if x != nil && x.ChainId != nil {
		return *x.ChainId
	}
	return 0
}

func (x *SenderKeyMessage) GetIteration() uint32 {
	if x != nil && x.Iteration != nil {
		return *x.Iteration
	}
	return 0
}

func (x *SenderKeyMessage) GetCiphertext() []byte {
	if x != nil {
		return x.Ciphertext
	}
	return nil
}

type SenderKeyDistributionMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DistributionUuid []byte  `protobuf:"bytes,1,opt,name=distribution_uuid,json=distributionUuid" json:"distribution_uuid,omitempty"`
	ChainId          *uint32 `protobuf:"varint,2,opt,name=chain_id,json=chainId" json:"chain_id,omitempty"`
	Iteration        *uint32 `protobuf:"varint,3,opt,name=iteration" json:"iteration,omitempty"`
	ChainKey         []byte  `protobuf:"bytes,4,opt,name=chain_key,json=chainKey" json:"chain_key,omitempty"`
	SigningKey       []byte  `protobuf:"bytes,5,opt,name=signing_key,json=signingKey" json:"signing_key,omitempty"`
}

func (x *SenderKeyDistributionMessage) Reset() {
	*x = SenderKeyDistributionMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_WhisperTextProtocol_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SenderKeyDistributionMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SenderKeyDistributionMessage) ProtoMessage() {}

func (x *SenderKeyDistributionMessage) ProtoReflect() protoreflect.Message {
	mi := &file_WhisperTextProtocol_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SenderKeyDistributionMessage.ProtoReflect.Descriptor instead.
func (*SenderKeyDistributionMessage) Descriptor() ([]byte, []int) {
	return file_WhisperTextProtocol_proto_rawDescGZIP(), []int{3}
}

func (x *SenderKeyDistributionMessage) GetDistributionUuid() []byte {
	if x != nil {
		return x.DistributionUuid
	}
	return nil
}

func (x *SenderKeyDistributionMessage) GetChainId() uint32 {
	if x != nil && x.ChainId != nil {
		return *x.ChainId
	}
	return 0
}

func (x *SenderKeyDistributionMessage) GetIteration() uint32 {
	if x != nil && x.Iteration != nil {
		return *x.Iteration
	}
	return 0
}

func (x *SenderKeyDistributionMessage) GetChainKey() []byte {
	if x != nil {
		return x.ChainKey
	}
	return nil
}

func (x *SenderKeyDistributionMessage) GetSigningKey() []byte {
	if x != nil {
		return x.SigningKey
	}
	return nil
}

type DeviceConsistencyCodeMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Generation *uint32 `protobuf:"varint,1,opt,name=generation" json:"generation,omitempty"`
	Signature  []byte  `protobuf:"bytes,2,opt,name=signature" json:"signature,omitempty"`
}

func (x *DeviceConsistencyCodeMessage) Reset() {
	*x = DeviceConsistencyCodeMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_WhisperTextProtocol_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeviceConsistencyCodeMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeviceConsistencyCodeMessage) ProtoMessage() {}

func (x *DeviceConsistencyCodeMessage) ProtoReflect() protoreflect.Message {
	mi := &file_WhisperTextProtocol_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeviceConsistencyCodeMessage.ProtoReflect.Descriptor instead.
func (*DeviceConsistencyCodeMessage) Descriptor() ([]byte, []int) {
	return file_WhisperTextProtocol_proto_rawDescGZIP(), []int{4}
}

func (x *DeviceConsistencyCodeMessage) GetGeneration() uint32 {
	if x != nil && x.Generation != nil {
		return *x.Generation
	}
	return 0
}

func (x *DeviceConsistencyCodeMessage) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

var File_WhisperTextProtocol_proto protoreflect.FileDescriptor

var file_WhisperTextProtocol_proto_rawDesc = []byte{
	0x0a, 0x19, 0x57, 0x68, 0x69, 0x73, 0x70, 0x65, 0x72, 0x54, 0x65, 0x78, 0x74, 0x50, 0x72, 0x6f,
	0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x11, 0x73, 0x69, 0x67,
	0x6e, 0x61, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x77, 0x69, 0x72, 0x65, 0x22, 0x95,
	0x01, 0x0a, 0x0d, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
	0x12, 0x1f, 0x0a, 0x0b, 0x72, 0x61, 0x74, 0x63, 0x68, 0x65, 0x74, 0x5f, 0x6b, 0x65, 0x79, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x72, 0x61, 0x74, 0x63, 0x68, 0x65, 0x74, 0x4b, 0x65,
	0x79, 0x12, 0x18, 0x0a, 0x07, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x07, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x12, 0x29, 0x0a, 0x10, 0x70,
	0x72, 0x65, 0x76, 0x69, 0x6f, 0x75, 0x73, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x6f, 0x75, 0x73, 0x43,
	0x6f, 0x75, 0x6e, 0x74, 0x65, 0x72, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72,
	0x74, 0x65, 0x78, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x63, 0x69, 0x70, 0x68,
	0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x22, 0xdf, 0x01, 0x0a, 0x13, 0x50, 0x72, 0x65, 0x4b, 0x65,
	0x79, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x27,
	0x0a, 0x0f, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69,
	0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0e, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x12, 0x1c, 0x0a, 0x0a, 0x70, 0x72, 0x65, 0x5f, 0x6b,
	0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x70, 0x72, 0x65,
	0x4b, 0x65, 0x79, 0x49, 0x64, 0x12, 0x29, 0x0a, 0x11, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x5f,
	0x70, 0x72, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x0e, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x50, 0x72, 0x65, 0x4b, 0x65, 0x79, 0x49, 0x64,
	0x12, 0x19, 0x0a, 0x08, 0x62, 0x61, 0x73, 0x65, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x07, 0x62, 0x61, 0x73, 0x65, 0x4b, 0x65, 0x79, 0x12, 0x21, 0x0a, 0x0c, 0x69,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x0b, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x4b, 0x65, 0x79, 0x12, 0x18,
	0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x22, 0x98, 0x01, 0x0a, 0x10, 0x53, 0x65, 0x6e,
	0x64, 0x65, 0x72, 0x4b, 0x65, 0x79, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x2b, 0x0a,
	0x11, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x75, 0x75,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x10, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69,
	0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x55, 0x75, 0x69, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x63, 0x68,
	0x61, 0x69, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x63, 0x68,
	0x61, 0x69, 0x6e, 0x49, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78,
	0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x63, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74,
	0x65, 0x78, 0x74, 0x22, 0xc2, 0x01, 0x0a, 0x1c, 0x53, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x4b, 0x65,
	0x79, 0x44, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x12, 0x2b, 0x0a, 0x11, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75,
	0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x75, 0x75, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x10, 0x64, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x55, 0x75, 0x69,
	0x64, 0x12, 0x19, 0x0a, 0x08, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x07, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x49, 0x64, 0x12, 0x1c, 0x0a, 0x09,
	0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x09, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x68,
	0x61, 0x69, 0x6e, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x63,
	0x68, 0x61, 0x69, 0x6e, 0x4b, 0x65, 0x79, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x69, 0x67, 0x6e, 0x69,
	0x6e, 0x67, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x73, 0x69,
	0x67, 0x6e, 0x69, 0x6e, 0x67, 0x4b, 0x65, 0x79, 0x22, 0x5c, 0x0a, 0x1c, 0x44, 0x65, 0x76, 0x69,
	0x63, 0x65, 0x43, 0x6f, 0x6e, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x43, 0x6f, 0x64,
	0x65, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x67, 0x65, 0x6e, 0x65,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x67, 0x65,
	0x6e, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1c, 0x0a, 0x09, 0x73, 0x69, 0x67, 0x6e,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67,
	0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x42, 0x43, 0x0a, 0x25, 0x6f, 0x72, 0x67, 0x2e, 0x77, 0x68,
	0x69, 0x73, 0x70, 0x65, 0x72, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2e, 0x6c, 0x69, 0x62,
	0x73, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x42,
	0x0c, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x6c, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x5a, 0x0c, 0x2e,
	0x3b, 0x74, 0x65, 0x78, 0x74, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65,
}

var (
	file_WhisperTextProtocol_proto_rawDescOnce sync.Once
	file_WhisperTextProtocol_proto_rawDescData = file_WhisperTextProtocol_proto_rawDesc
)

func file_WhisperTextProtocol_proto_rawDescGZIP() []byte {
	file_WhisperTextProtocol_proto_rawDescOnce.Do(func() {
		file_WhisperTextProtocol_proto_rawDescData = protoimpl.X.CompressGZIP(file_WhisperTextProtocol_proto_rawDescData)
	})
	return file_WhisperTextProtocol_proto_rawDescData
}

var file_WhisperTextProtocol_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_WhisperTextProtocol_proto_goTypes = []interface{}{
	(*SignalMessage)(nil),                // 0: signal.proto.wire.SignalMessage
	(*PreKeySignalMessage)(nil),          // 1: signal.proto.wire.PreKeySignalMessage
	(*SenderKeyMessage)(nil),             // 2: signal.proto.wire.SenderKeyMessage
	(*SenderKeyDistributionMessage)(nil), // 3: signal.proto.wire.SenderKeyDistributionMessage
	(*DeviceConsistencyCodeMessage)(nil), // 4: signal.proto.wire.DeviceConsistencyCodeMessage
}
var file_WhisperTextProtocol_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_WhisperTextProtocol_proto_init() }
func file_WhisperTextProtocol_proto_init() {
	if File_WhisperTextProtocol_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_WhisperTextProtocol_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignalMessage); i {
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
		file_WhisperTextProtocol_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PreKeySignalMessage); i {
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
		file_WhisperTextProtocol_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SenderKeyMessage); i {
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
		file_WhisperTextProtocol_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SenderKeyDistributionMessage); i {
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
		file_WhisperTextProtocol_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeviceConsistencyCodeMessage); i {
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
			RawDescriptor: file_WhisperTextProtocol_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_WhisperTextProtocol_proto_goTypes,
		DependencyIndexes: file_WhisperTextProtocol_proto_depIdxs,
		MessageInfos:      file_WhisperTextProtocol_proto_msgTypes,
	}.Build()
	File_WhisperTextProtocol_proto = out.File
	file_WhisperTextProtocol_proto_rawDesc = nil
	file_WhisperTextProtocol_proto_goTypes = nil
	file_WhisperTextProtocol_proto_depIdxs = nil
}
