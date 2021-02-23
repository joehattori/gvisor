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
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/flipcall"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/unet"
)

// Client helps manage a connection to the lisafs server and pass messages
// efficiently. There is a 1:1 mapping between a Connection and a Client.
type Client struct {
	// sock is the main socket by which this connections is established.
	// Communication over the socket is synchronized by sockMu.
	sock   *unet.Socket
	sockMu sync.Mutex

	// root is the file descriptor to the mount point on the server.
	root FDID

	// channelsMu protects channels and availableChannels.
	channelsMu sync.Mutex
	// channels tracks all the channels.
	channels []*channel
	// availableChannels is a LIFO (stack) of channels available to be used.
	availableChannels []*channel
	// activeWg represents active channels.
	activeWg sync.WaitGroup

	// watchdogWg only holds the watchdog goroutine.
	watchdogWg sync.WaitGroup

	// unsupported caches information about which messages are supported . It is
	// indexed by MID. An MID is unsupported if unsupported[MID] is true.
	unsupported []bool
}

// NewClient creates a new client for communication with the server. It mounts
// the server and creates channels for fast IPC.
func NewClient(sock *unet.Socket, aname string) (*Client, error) {
	c := &Client{
		sock:              sock,
		channels:          make([]*channel, 0, maxChannels),
		availableChannels: make([]*channel, 0, maxChannels),
	}

	// Mount the server first.
	var mountMsg MountReq
	mountMsg.mountPath.setString(aname)
	mountRespBuf, _, err := c.SndRcvMessage(Mount, &mountMsg)
	if err != nil {
		return nil, err
	}

	// Interpret the response and initialise client.
	var mountResp MountResp
	mountResp.UnmarshalBytes(mountRespBuf)
	c.root = mountResp.root
	c.unsupported = make([]bool, mountResp.maxM+1)
	for _, unsupportedM := range mountResp.unsupportedMs {
		if unsupportedM > mountResp.maxM {
			panic(fmt.Sprintf("server responded with invalid unsupported message ID: %d", unsupportedM))
		}
		c.unsupported[unsupportedM] = true
	}

	// Create channels parallely so that channels can be used to create more
	// channels and costly initialization like flipcall.Endpoint.Connect can
	// proceed parallely.
	for i := 0; i < maxChannels; i++ {
		go func() {
			ch, err := c.createChannel()
			if err != nil {
				log.Warningf("channel creation failed: %v", err)
				// This error is not a deal breaker. The client can at least
				// communicate using the healthy initialized socket.
				return
			}
			c.channelsMu.Lock()
			c.channels = append(c.channels, ch)
			c.availableChannels = append(c.availableChannels, ch)
			c.channelsMu.Unlock()
		}()
	}

	// Channel creation can continue in the background, move on. Start a
	// goroutine to check socket health.
	c.watchdogWg.Add(1)
	go c.watchdog()

	return c, nil
}

func (c *Client) watchdog() {
	defer c.watchdogWg.Done()

	events := []unix.PollFd{
		{
			Fd:     int32(c.sock.FD()),
			Events: unix.POLLHUP | unix.POLLRDHUP,
		},
	}

	// Wait for a shutdown event.
	for {
		n, err := unix.Ppoll(events, nil, nil)
		if err == syscall.EINTR || err == syscall.EAGAIN {
			continue
		}
		if err != nil {
			log.Warningf("lisafs.Client.watch(): %v", err)
		} else if n != 1 {
			log.Warningf("lisafs.Client.watch(): got %d events, wanted 1", n)
		}
		break
	}

	// Shutdown all active channels and wait for them to complete.
	c.channelsMu.Lock()
	for _, ch := range c.channels {
		if ch.active {
			log.Debugf("shutting down active channel@%p...", ch)
			ch.shutdown()
		}
	}

	// Prevent channels from becoming available and serving new requests.
	c.availableChannels = nil
	c.channelsMu.Unlock()
	c.activeWg.Wait()

	// Close all channels.
	c.channelsMu.Lock()
	for _, ch := range c.channels {
		ch.destroy()
	}
	c.channelsMu.Unlock()

	// Close main socket.
	c.sock.Close()
}

// Close shuts down the main socket and waits for the watchdog to clean up.
func (c *Client) Close() {
	// This shutdown has no effect if the watchdog has already fired and closed
	// the main socket.
	if err := c.sock.Shutdown(); err != nil {
		log.Warningf("Socket.Shutdown() failed (FD: %d): %v", c.sock.FD(), err)
	}
	c.watchdogWg.Wait()
}

func (c *Client) createChannel() (*channel, error) {
	chanRespBuf, fds, err := c.SndRcvMessage(Channel, nil)
	if err != nil {
		return nil, err
	}
	if len(fds) != 2 {
		closeFDs(fds)
		return nil, fmt.Errorf("%d FDs provided in Channel response", len(fds))
	}

	// Lets create the channel.
	var chanResp ChannelResp
	chanResp.UnmarshalBytes(chanRespBuf)

	defer closeFDs(fds[:1]) // The data FD is not needed after this.
	desc := flipcall.PacketWindowDescriptor{
		FD:     fds[0],
		Offset: chanResp.dataOffset,
		Length: int(chanResp.dataLength),
	}

	ch := &channel{}
	if err := ch.data.Init(flipcall.ClientSide, desc); err != nil {
		closeFDs(fds[1:])
		return nil, err
	}
	ch.fdChan.Init(fds[1]) // fdChan now owns this FD.

	// Only a connected channel is usable.
	if err := ch.data.Connect(); err != nil {
		ch.destroy()
		return nil, err
	}
	return ch, nil
}

// IsSupported returns true if this connection supports the passed message.
func (c *Client) IsSupported(m MID) bool {
	return int(m) < len(c.unsupported) && !c.unsupported[m]
}

// SndRcvMessage marshals the passed message, sends it over to the server,
// waits for the response and returns with the response.
func (c *Client) SndRcvMessage(m MID, msg marshal.Marshallable) ([]byte, []int, error) {
	respM, respBuf, fds, err := c.sndRcvMessage(m, msg)
	if err != nil {
		return nil, nil, err
	}
	// The response MID can either be error or the request MID itself.
	if respM == Error {
		var resp ErrorRes
		resp.UnmarshalBytes(respBuf)
		return nil, nil, syscall.Errno(resp.errno)
	}
	if respM != m {
		log.Warningf("sent %d message but got %d in response", m, respM)
		return nil, nil, syscall.EINVAL
	}
	return respBuf, fds, nil
}

func (c *Client) sndRcvMessage(m MID, msg marshal.Marshallable) (MID, []byte, []int, error) {
	// Prefer using channel over socket because:
	// - Channel uses a shared memory region for passing messages. IO from shared
	//   memory is faster and does not involve making a syscall.
	// - No intermediate buffer allocation needed. With a channel, the message
	//   can be directly pasted into the shared memory region.
	if ch := c.getChannel(); ch != nil {
		reinsert := true
		defer c.releaseChannel(ch, &reinsert)

		sndDataLen, err := ch.writeMsg(m, msg, nil)
		if err != nil {
			return 0, nil, nil, err
		}

		// One-shot communication.
		rcvDataLen, err := ch.data.SendRecv(sndDataLen)
		if err != nil {
			// This channel is unusable. Don't reinsert it.
			reinsert = false
			// Map the transport errors to EIO, but also log the real error.
			log.Warningf("lisafs.sndRcvMessage: flipcall.Endpoint.SendRecv: %v", err)
			return 0, nil, nil, syscall.EIO
		}

		return ch.readMsg(rcvDataLen)
	}

	// TODO(ayushranjan): Support multiple in-flight requests on the socket.
	// For now, only allow one thread to use this socket to send and receive.
	c.sockMu.Lock()
	defer c.sockMu.Unlock()
	if err := writeMessageTo(c.sock, m, msg, nil); err != nil {
		return 0, nil, nil, err
	}

	return readMessageFrom(c.sock)
}

// getChannel pops a channel from the available channels stack. It also
// increments the activeWg. The caller must ensure that activeWg is decremented
// after the channel is done being used.
func (c *Client) getChannel() *channel {
	c.channelsMu.Lock()
	defer c.channelsMu.Unlock()
	if len(c.availableChannels) == 0 {
		return nil
	}

	idx := len(c.availableChannels) - 1
	ch := c.availableChannels[idx]
	ch.active = true
	c.availableChannels = c.availableChannels[:idx]
	c.activeWg.Add(1)
	return ch
}

// releaseChannel pushes the passed channel onto the available channel stack if
// reinsert is true. It also decrements activeWg.
func (c *Client) releaseChannel(ch *channel, reinsert *bool) {
	c.channelsMu.Lock()
	defer c.channelsMu.Unlock()
	ch.active = false
	if *reinsert {
		// If availableChannels is nil, then watchdog has fired and the client is
		// shutting down. So don't make this channel available again.
		if c.availableChannels != nil {
			c.availableChannels = append(c.availableChannels, ch)
		}
	}
	c.activeWg.Done()
}
