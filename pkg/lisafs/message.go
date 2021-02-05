// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lisafs

import (
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

// MID (message ID) is used to identify messages to parse from payload.
//
// +marshal slice:MIDSlice
type MID uint16

// These constants are used to identify their corresponding message types.
// Note that this order must be preserved across versions and new messages must
// only be appended at the end.
const (
	// Error is only used in responses to pass errors to client.
	Error MID = iota

	// Close is used to close the connection.
	Close

	// Mount is used to establish connection and set up server side filesystem.
	Mount

	// Channel request starts a new channel.
	Channel
)

// MaxMessageSize is the largest possible message in bytes.
const MaxMessageSize uint32 = 1 << 20

// sockHeader is the header present in front of each message received on a UDS.
//
// +marshal
type sockHeader struct {
	size    uint32
	message MID
	_       uint16
}

// channelHeader is the header present in front of each message received on
// flipcall endpoint.
//
// +marshal
type channelHeader struct {
	message MID
	numFDs  uint8
	_       uint8
}

// sizedString represents a string in memory.
//
// +marshal dynamic
type sizedString struct {
	size primitive.Uint32
	str  []byte `marshal:"unaligned"`
}

var _ marshal.Marshallable = (*sizedString)(nil)

func (s *sizedString) toString() string {
	return string(s.str)
}

func (s *sizedString) setString(str string) {
	if len(str) > int(^uint16(0)) {
		panic("string too long")
	}
	s.size = primitive.Uint32(len(str))
	s.str = []byte(str)
}

func (s *sizedString) reset() {
	s.size = 0
	s.str = s.str[:0]
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *sizedString) SizeBytes() int {
	if s == nil {
		// Only return the size of primitive.Uint32 as no string actually exists.
		return (*primitive.Uint32)(nil).SizeBytes()
	}
	return s.size.SizeBytes() + len(s.str)
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *sizedString) MarshalBytes(dst []byte) {
	s.size.MarshalBytes(dst)
	copy(dst[s.size.SizeBytes():], s.str)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *sizedString) UnmarshalBytes(src []byte) {
	s.size.UnmarshalBytes(src)
	// Try to reuse s.str as much as possible.
	if cap(s.str) < int(s.size) {
		s.str = make([]byte, s.size)
	} else {
		s.str = s.str[:s.size]
	}
	sizeSize := s.size.SizeBytes()
	copy(s.str, src[sizeSize:sizeSize+int(s.size)])
}

// MountReq represents a Mount request.
//
// +marshal dynamic
type MountReq struct {
	mountPath sizedString
}

var _ marshal.Marshallable = (*MountReq)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MountReq) SizeBytes() int {
	return m.mountPath.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MountReq) MarshalBytes(dst []byte) {
	m.mountPath.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MountReq) UnmarshalBytes(src []byte) {
	m.mountPath.UnmarshalBytes(src)
}

// MountResp represents a Mount response.
//
// +marshal dynamic
type MountResp struct {
	root           FDID
	maxM           MID
	numUnsupported primitive.Uint16
	unsupportedMs  []MID
}

var _ marshal.Marshallable = (*MountResp)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MountResp) SizeBytes() int {
	return m.root.SizeBytes() +
		m.maxM.SizeBytes() +
		m.numUnsupported.SizeBytes() +
		(int(m.numUnsupported) * (*MID)(nil).SizeBytes())
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MountResp) MarshalBytes(dst []byte) {
	m.root.MarshalBytes(dst)
	dst = dst[m.root.SizeBytes():]
	m.maxM.MarshalBytes(dst)
	dst = dst[m.maxM.SizeBytes():]
	m.numUnsupported.MarshalBytes(dst)
	dst = dst[m.numUnsupported.SizeBytes():]
	MarshalUnsafeMIDSlice(m.unsupportedMs, dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MountResp) UnmarshalBytes(src []byte) {
	m.root.UnmarshalBytes(src)
	src = src[m.root.SizeBytes():]
	m.maxM.UnmarshalBytes(src)
	src = src[m.maxM.SizeBytes():]
	m.numUnsupported.UnmarshalBytes(src)
	src = src[m.numUnsupported.SizeBytes():]
	m.unsupportedMs = make([]MID, m.numUnsupported)
	UnmarshalUnsafeMIDSlice(m.unsupportedMs, src)
}

// ChannelResp is the response to the create channel request.
//
// +marshal
type ChannelResp struct {
	dataOffset int64
	dataLength uint64
}

// ErrorRes is returned to represent an error while handling a request.
// A field holding value 0 indicates no error on that field.
//
// +marshal
type ErrorRes struct {
	errno uint32
}
