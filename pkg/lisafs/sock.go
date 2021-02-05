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
	"io"
	"syscall"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/unet"
)

// sockHeaderLen is (*sockHeader)(nil).SizeBytes(). It exists to make static
// headerBuf declaration possible without having to call make([]byte).
const sockHeaderLen uint32 = 8

// sockMaxFDsDonate is the maximum number of FDs that one write operation on
// the socket can donate.
const sockMaxFDsDonate int = 2

// writeMessageTo writes the header followed by the payload to the UDS.
func writeMessageTo(sock *unet.Socket, m MID, payload marshal.Marshallable, fds []int) error {
	var headerBuf [sockHeaderLen]byte
	var payloadBuf []byte

	header := sockHeader{size: sockHeaderLen, message: m}
	if payload != nil {
		pSize := payload.SizeBytes()
		header.size += uint32(pSize)
		if header.size > MaxMessageSize {
			log.Warningf("message size too big: %d", header.size)
			return syscall.EINVAL
		}
		payloadBuf = make([]byte, pSize)
		payload.MarshalBytes(payloadBuf)
	}
	header.MarshalBytes(headerBuf[:])

	return writeTo(sock, [][]byte{headerBuf[:], payloadBuf}, int(header.size), fds)
}

// writeTo writes the passed iovec to the UDS and donates any passed FDs. Note
// that FD donation is destructive: the passed fds are closed after donation.
func writeTo(sock *unet.Socket, iovec [][]byte, totalLen int, fds []int) error {
	w := sock.Writer(true)
	if len(fds) > 0 {
		defer closeFDs(fds)
		if len(fds) > sockMaxFDsDonate {
			log.Warningf("trying to donate %d FDs, but only %d can be donated in one write", len(fds), sockMaxFDsDonate)
			fds = fds[:sockMaxFDsDonate]
		}
		w.PackFDs(fds...)
	}

	for n := 0; n < totalLen; {
		cur, err := w.WriteVec(iovec)
		if err != nil {
			return err
		}
		n += cur

		// Consume iovecs.
		for consumed := 0; consumed < cur; {
			if len(iovec[0]) <= cur-consumed {
				consumed += len(iovec[0])
				iovec = iovec[1:]
			} else {
				iovec[0] = iovec[0][cur-consumed:]
				break
			}
		}

		if n > 0 && n < totalLen {
			// Don't resend any control message.
			w.UnpackFDs()
		}
	}
	return nil
}

// readMessageFrom reads the message header and payload from the UDS. It also
// returns any donated FDs.
func readMessageFrom(sock *unet.Socket) (MID, []byte, []int, error) {
	var fds []int
	var err error
	var headerBuf [sockHeaderLen]byte
	if fds, err = readFrom(sock, headerBuf[:]); err != nil {
		return 0, nil, nil, err
	}

	var header sockHeader
	header.UnmarshalBytes(headerBuf[:])

	if header.size < sockHeaderLen || header.size > MaxMessageSize {
		log.Warningf("inappropriate message size specified in header: %d", header.size)
		return 0, nil, nil, syscall.EINVAL
	}

	// No payload? We are done.
	if header.size == sockHeaderLen {
		return header.message, nil, fds, nil
	}

	payload := make([]byte, header.size-sockHeaderLen)
	if extraFDs, err := readFrom(sock, payload); err != nil {
		return 0, nil, nil, err
	} else if len(extraFDs) > 0 {
		log.Warningf("received %d extra FDs whie reading message payload, closing and ignoring them", len(extraFDs))
		closeFDs(extraFDs)
	}

	return header.message, payload, fds, nil
}

// readFrom fills the passed buffer with data from the socket. It also returns
// any donated FDs.
func readFrom(sock *unet.Socket, buf []byte) ([]int, error) {
	r := sock.Reader(true)
	r.EnableFDs(sockMaxFDsDonate)

	var fds []int
	var fdInit bool

	n := len(buf)
	var got int
	for got < n {
		cur, err := r.ReadVec([][]byte{buf[got:]})

		// Ignore EOF if cur > 0.
		if err != nil && (err != io.EOF || cur == 0) {
			r.CloseFDs()
			closeFDs(fds)
			return nil, err
		}

		if !fdInit && cur > 0 {
			fds, err = r.ExtractFDs()
			if err != nil {
				return nil, err
			}
			fdInit = true
			r.EnableFDs(0)
		}

		got += cur
	}
	return fds, nil
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		syscall.Close(fd)
	}
}
