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

// Package test holds testing utilites for lisafs.
package test

import (
	"math/rand"

	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

// MsgSimple is a sample packed struct which can be used to test message passing.
//
// +marshal slice:Msg1Slice
type MsgSimple struct {
	A uint16
	B uint16
	C uint32
	D uint64
}

// Randomize randomizes the contents of m.
func (m *MsgSimple) Randomize() {
	m.A = uint16(rand.Uint32())
	m.B = uint16(rand.Uint32())
	m.C = rand.Uint32()
	m.D = rand.Uint64()
}

// MsgDynamic is a sample dynamic struct which can be used to test message passing.
//
// +marshal dynamic
type MsgDynamic struct {
	N   primitive.Uint32
	Arr []MsgSimple `marshal:"unaligned"`
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MsgDynamic) SizeBytes() int {
	return m.N.SizeBytes() +
		(int(m.N) * (*MsgSimple)(nil).SizeBytes())
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MsgDynamic) MarshalBytes(dst []byte) {
	m.N.MarshalBytes(dst)
	dst = dst[m.N.SizeBytes():]
	MarshalUnsafeMsg1Slice(m.Arr, dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MsgDynamic) UnmarshalBytes(src []byte) {
	m.N.UnmarshalBytes(src)
	src = src[m.N.SizeBytes():]
	m.Arr = make([]MsgSimple, m.N)
	UnmarshalUnsafeMsg1Slice(m.Arr, src)
}
