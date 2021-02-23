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
	"bytes"
	"math/rand"
	"reflect"
	"syscall"
	"testing"

	"gvisor.dev/gvisor/pkg/lisafs/test"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
)

func TestSockHeaderLen(t *testing.T) {
	// sockHeaderLen must be equal to sockHeader.SizeBytes().
	want := (*sockHeader)(nil).SizeBytes()
	if got := int(sockHeaderLen); got != want {
		t.Errorf("sockHeaderLen has incorrect value: want %d, got %d", want, got)
	}
}

func runSocketTest(t *testing.T, fun1 func(*unet.Socket), fun2 func(*unet.Socket)) {
	sock1, sock2, err := unet.SocketPair(false)
	if err != nil {
		t.Fatalf("socketpair got err %v expected nil", err)
	}
	defer sock1.Close()
	defer sock2.Close()

	var testWg sync.WaitGroup
	testWg.Add(2)

	go func() {
		fun1(sock1)
		testWg.Done()
	}()

	go func() {
		fun2(sock2)
		testWg.Done()
	}()

	testWg.Wait()
}

func TestReadWrite(t *testing.T) {
	// Create random data to send.
	n := 10000
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand.Read(data) failed: %v", err)
	}

	runSocketTest(t, func(sock *unet.Socket) {
		// Scatter that data into two parts using Iovecs while sending.
		mid := n / 2
		if err := writeTo(sock, [][]byte{data[:mid], data[mid:]}, n, nil); err != nil {
			t.Errorf("writeTo socket failed: %v", err)
		}
	}, func(sock *unet.Socket) {
		gotData := make([]byte, n)
		if fds, err := readFrom(sock, gotData); err != nil {
			t.Fatalf("reading from socket failed: %v", err)
		} else if len(fds) > 0 {
			closeFDs(fds)
			t.Errorf("recieved upexpected FDs: %v", fds)
		}

		// Make sure we got the right data.
		if res := bytes.Compare(data, gotData); res != 0 {
			t.Errorf("data recieved differs from data sent, want = %v, got = %v", data, gotData)
		}
	})
}

func TestFDDonation(t *testing.T) {
	n := 10
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand.Read(data) failed: %v", err)
	}

	// Try donating FDs to these files.
	path1 := "/dev/null"
	path2 := "/dev"

	runSocketTest(t, func(sock *unet.Socket) {
		devNullFD, err := syscall.Open(path1, syscall.O_RDONLY, 0)
		if err != nil {
			t.Fatalf("open(%s) failed: %v", path1, err)
		}
		devFD, err := syscall.Open(path2, syscall.O_RDONLY, 0)
		if err != nil {
			syscall.Close(devNullFD)
			t.Fatalf("open(%s) failed: %v", path2, err)
		}
		if err := writeTo(sock, [][]byte{data}, n, []int{devNullFD, devFD}); err != nil {
			t.Errorf("writeTo socket failed: %v", err)
		}
	}, func(sock *unet.Socket) {
		gotData := make([]byte, n)
		fds, err := readFrom(sock, gotData)
		if err != nil {
			t.Fatalf("reading from socket failed: %v", err)
		}
		defer closeFDs(fds)

		if res := bytes.Compare(data, gotData); res != 0 {
			t.Errorf("data recieved differs from data sent, want = %v, got = %v", data, gotData)
		}

		if len(fds) != 2 {
			t.Fatalf("wanted 2 FD, got %d", len(fds))
		}

		// Check that the FDs actually point to the correct file.
		compareFDWithFile(t, fds[0], path1)
		compareFDWithFile(t, fds[1], path2)
	})
}

func compareFDWithFile(t *testing.T, fd int, path string) {
	var want syscall.Stat_t
	if err := syscall.Stat(path, &want); err != nil {
		t.Fatalf("stat(%s) failed: %v", path, err)
	}

	var got syscall.Stat_t
	if err := syscall.Fstat(fd, &got); err != nil {
		t.Fatalf("fstat on donated FD failed: %v", err)
	}

	if got.Ino != want.Ino || got.Dev != want.Dev {
		t.Errorf("FD does not point to %s, want = %+v, got = %+v", path, want, got)
	}
}

func TestSndRcvMessage(t *testing.T) {
	req := &test.MsgSimple{}
	req.Randomize()
	reqM := MID(1)

	// Create a massive random response.
	arrLen := 100
	resp := &test.MsgDynamic{N: primitive.Uint32(arrLen), Arr: make([]test.MsgSimple, arrLen)}
	for i := 0; i < arrLen; i++ {
		resp.Arr[i].Randomize()
	}
	respM := MID(2)

	runSocketTest(t, func(sock *unet.Socket) {
		if err := writeMessageTo(sock, reqM, req, nil); err != nil {
			t.Errorf("writeMessageTo failed: %v", err)
		}
		checkMessageReceive(t, sock, respM, resp)
	}, func(sock *unet.Socket) {
		checkMessageReceive(t, sock, reqM, req)
		if err := writeMessageTo(sock, respM, resp, nil); err != nil {
			t.Errorf("writeMessageTo failed: %v", err)
		}
	})
}

func TestSndRcvMessageNoPayload(t *testing.T) {
	reqM := MID(1)
	respM := MID(2)
	runSocketTest(t, func(sock *unet.Socket) {
		if err := writeMessageTo(sock, reqM, nil, nil); err != nil {
			t.Errorf("writeMessageTo failed: %v", err)
		}
		checkMessageReceive(t, sock, respM, nil)
	}, func(sock *unet.Socket) {
		checkMessageReceive(t, sock, reqM, nil)
		if err := writeMessageTo(sock, respM, nil, nil); err != nil {
			t.Errorf("writeMessageTo failed: %v", err)
		}
	})
}

func checkMessageReceive(t *testing.T, sock *unet.Socket, wantM MID, wantMsg marshal.Marshallable) {
	gotM, gotB, gotFDs, err := readMessageFrom(sock)
	if err != nil {
		t.Fatalf("readMessageFrom failed: %v", err)
	}
	if gotM != wantM {
		t.Errorf("got incorrect message ID: got = %d, want = %d", gotM, wantM)
	}
	if len(gotFDs) > 0 {
		t.Errorf("got %d unexpected FDs", len(gotFDs))
	}
	if wantMsg == nil {
		if len(gotB) != 0 {
			t.Errorf("no payload expect but got %d bytes", len(gotB))
		}
	} else {
		gotMsg := reflect.New(reflect.ValueOf(wantMsg).Elem().Type()).Interface().(marshal.Marshallable)
		gotMsg.UnmarshalBytes(gotB)
		if !reflect.DeepEqual(wantMsg, gotMsg) {
			t.Errorf("msg differs: want = %+v, got = %+v", wantMsg, gotMsg)
		}
	}
}
