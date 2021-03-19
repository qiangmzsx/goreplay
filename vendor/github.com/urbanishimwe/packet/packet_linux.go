// +build linux

package packet

import (
	"errors"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

type handle struct {
	fd            int // read file descriptor
	breakLoopfd   int // break loop file desciptor
	headerVersion int
	pollTimeout   int
	p             packetScanner
	netIf         *net.Interface
	closeOnce     *sync.Once
	config        *Config
	stats         *Stats // use pointer to Stats to align 64-bit variables for atomic operation
	breakLoop     uint32 // break loop indicator
}

func newHandler(iff string, c *Config) (*handle, error) {
	if c == nil {
		c = DefaultConfig()
	}
	if !c.CheckIntegrity() {
		return nil, unix.EINVAL
	}
	var netIf *net.Interface
	var err error
	if iff != "" {
		netIf, err = net.InterfaceByName(iff)
		if err != nil {
			return nil, err
		}
	}
	link := InterfaceLinkType(iff)
	sockType := unix.SOCK_RAW
	// if interface is not ethernet, use cooked socket
	if c.NoLinkLayer || link != LinkTypeEthernet {
		sockType = unix.SOCK_DGRAM
		c.NoLinkLayer = true
	}
	// set protocol to 0, to avoid reading packets before creating buffer
	fd, err := unix.Socket(unix.AF_PACKET, sockType, 0)
	if err != nil {
		return nil, os.NewSyscallError("socket.AF_PACKET", err)
	}
	// break loop events file descriptor
	breakLoopfd, err := unix.Eventfd(0, unix.EFD_NONBLOCK)
	if err != nil {
		unix.Close(fd)
		return nil, os.NewSyscallError("socket.Eventfd", err)
	}
	h := &handle{
		closeOnce:   new(sync.Once),
		stats:       new(Stats),
		fd:          fd,
		breakLoopfd: breakLoopfd,
		netIf:       netIf,
		config:      c,
	}
	// we can set finalizer by now
	runtime.SetFinalizer(h, (*handle).Close)
	err = h.setPromiscuous(c.Promiscuous)
	if err != nil {
		return nil, err
	}
	err = h.setNonBlock(c.NonBlock)
	if err != nil {
		return nil, err
	}
	if len(c.Filter) > 0 {
		if err = h.SetBPF(c.Filter); err != nil {
			return nil, err
		}
	}
	err = h.setPacketVersion(&config{
		link:   link,
		dir:    c.Direction,
		tPresc: c.TstampResolution,
		loop:   h.loopBackIndex(c.Promiscuous),
	}, c.ImmediateMode)
	if err != nil {
		return nil, err
	}
	flag := c.ReadTimeout
	if h.headerVersion == unix.TPACKET_V2 {
		flag = 0
		if netIf != nil {
			flag = int64(netIf.MTU)
		}
	}
	c.ReadBufferSize, err = h.p.createRing(h.fd, c.ReadBufferSize, flag)
	if err != nil {
		return nil, err
	}
	h.setPollTimeout()
	err = h.bind(c.Proto)
	return h, err
}

func (h *handle) Fd() uintptr {
	return uintptr(h.fd)
}

func (h *handle) LinkType() LinkType {
	return h.p.link()
}

func (h *handle) Config() *Config {
	return h.config
}

func (h *handle) Read(poll bool) (raw []byte, p *Info, err error) {
	maxNilRead := h.config.MaxNilRead
repeat:
	if h.p.hasNext() {
		raw, p = h.p.next()
		if p == nil && maxNilRead > 0 {
			maxNilRead--
			goto repeat
		}
		return
	}
	if poll {
		err = h.poll()
		if err == nil {
			goto repeat
		}
		return
	}
	err = eWouldPoll
	return
}

func (h *handle) Write(buf []byte, iff *net.Interface, proto Proto) (int, error) {
	if iff == nil {
		if h.netIf == nil {
			return 0, unix.EINVAL
		}
		iff = h.netIf
	}
	var addr [8]byte
	if len(iff.HardwareAddr) > 8 {
		return 0, unix.EINVAL
	}
	if len(buf) == 0 {
		return 0, nil
	}
	copy(addr[:], iff.HardwareAddr)
	ssl := &unix.RawSockaddrLinklayer{
		Family:   unix.AF_PACKET,
		Protocol: bswap16(uint16(proto)),
		Ifindex:  int32(iff.Index),
		Halen:    uint8(len(iff.HardwareAddr)),
		Addr:     addr,
	}
	n, _, e := unix.Syscall6(
		unix.SYS_SENDTO,
		uintptr(h.fd),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0, uintptr(unsafe.Pointer(ssl)), unix.SizeofSockaddrLinklayer,
	)
	if e != 0 {
		return 0, unix.Errno(e)
	}
	return int(n), nil
}

func (h *handle) BreakLoop() error {
	v := uint64(1)
	/*
		we don't expect this to fail nor to return EAGAIN (which would happen
		if this function was called ^uint64(0) number of times before read)
		unless the handle was closed!
	*/
	_, _, e := unix.Syscall(unix.SYS_WRITE, uintptr(h.breakLoopfd), uintptr(unsafe.Pointer(&v)), 8)
	if e != 0 {
		return unix.Errno(e)
	}
	atomic.StoreUint32(&h.breakLoop, 1)
	return nil
}

func (h *handle) Stats(total bool) *Stats {
	var st = &Stats{}
	if h.headerVersion == unix.TPACKET_V3 {
		st3, _ := unix.GetsockoptTpacketStatsV3(h.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
		if st3 != nil {
			st.Recvs = uint64(st3.Packets)
			st.Drops = uint64(st3.Drops)
		}
	} else if h.headerVersion == unix.TPACKET_V2 {
		st2, _ := unix.GetsockoptTpacketStats(h.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
		if st2 == nil {
			st.Recvs = uint64(st2.Packets)
			st.Drops = uint64(st2.Drops)
		}
	}
	recvs := atomic.AddUint64(&h.stats.Recvs, st.Recvs)
	drops := atomic.AddUint64(&h.stats.Drops, st.Drops)
	if total {
		st.Drops = drops
		st.Recvs = recvs
	}
	return st
}

func (h *handle) SetBPF(filter []bpf.RawInstruction) error {
	if len(filter) < 1 {
		return os.NewSyscallError(
			"setsockopt.SO_DETACH_FILTER",
			unix.SetsockoptInt(int(h.fd), unix.SOL_SOCKET, unix.SO_DETACH_FILTER, 0),
		)
	}
	if len(filter) > int(^uint16(0)) {
		return errors.New("filter too large")
	}
	var p unix.SockFprog
	p.Len = uint16(len(filter))
	fltr := make([]unix.SockFilter, p.Len)
	// we could have casted this with unsafe pointer!
	for i := range filter {
		fltr[i].Code = filter[i].Op
		fltr[i].Jt = filter[i].Jt
		fltr[i].Jf = filter[i].Jf
		fltr[i].K = filter[i].K
	}
	p.Filter = &fltr[0]
	return os.NewSyscallError(
		"setsockopt.SO_ATTACH_FILTER",
		unix.SetsockoptSockFprog(int(h.fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &p),
	)
}

func (h *handle) Close() error {
	var err error
	h.closeOnce.Do(func() {
		err = unix.Close(h.fd)
		err = unix.Close(h.breakLoopfd)
		if h.p != nil {
			err = unix.Munmap(h.p.ring())
		}
	})
	return err
}

func (h *handle) setPacketVersion(c *config, immediate bool) (err error) {
	// the only way we MAY NOT read packets as soon they arrive is by using
	// TPACKET_V3.
	if !immediate {
		err = unix.SetsockoptInt(h.fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V3)
		if err != nil {
			return os.NewSyscallError("setsockopt.TPACKET_V3", err)
		}
		h.p = newtPacketv3(c)
		h.headerVersion = unix.TPACKET_V3
		return
	}
	err = unix.SetsockoptInt(h.fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V2)
	if err != nil {
		return os.NewSyscallError("setsockopt.TPACKET_V2", err)
	}
	h.p = newtPacketv2(c)
	h.headerVersion = unix.TPACKET_V2
	return
}

func (h *handle) setNonBlock(v bool) error {
	return os.NewSyscallError("fcntl.O_NONBLOCK", unix.SetNonblock(h.fd, v))
}

func (h *handle) bind(protocol Proto) error {
	ifindex := int32(0)
	if h.netIf != nil {
		ifindex = int32(h.netIf.Index)
	}
	proto := bswap16(unix.ETH_P_ALL)
	if protocol != 0 {
		proto = bswap16(uint16(protocol))
	}
	addr := unix.RawSockaddrLinklayer{
		Family:   unix.AF_PACKET,
		Ifindex:  ifindex,
		Protocol: proto,
	}
	_, _, e := unix.Syscall(unix.SYS_BIND, uintptr(h.fd), uintptr(unsafe.Pointer(&addr)), unix.SizeofSockaddrLinklayer)
	if e != 0 {
		return os.NewSyscallError("bind", e)
	}
	return nil
}

func (h *handle) setPromiscuous(v bool) error {
	ifindex := int32(0)
	if h.netIf != nil {
		ifindex = int32(h.netIf.Index)
	}
	var mr = unix.PacketMreq{
		Ifindex: ifindex,
		Type:    unix.PACKET_MR_PROMISC,
	}
	if v {
		return os.NewSyscallError("setsockopt.promiscuous",
			unix.SetsockoptPacketMreq(h.fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mr),
		)
	}
	return os.NewSyscallError("setsockopt.promiscuous",
		unix.SetsockoptPacketMreq(h.fd, unix.SOL_PACKET, unix.PACKET_DROP_MEMBERSHIP, &mr),
	)
}

func (h *handle) resetBreakLoop() {
	var value uint64
	_, _, _ = unix.Syscall(unix.SYS_READ,
		uintptr(h.breakLoopfd),
		uintptr(unsafe.Pointer(&value)), 8,
	)
	atomic.StoreUint32(&h.breakLoop, 0)
}

func (h *handle) shouldBreakLoop() bool {
	return atomic.CompareAndSwapUint32(&h.breakLoop, 1, 1)
}

func (h *handle) setPollTimeout() {
	timeout := int(h.config.ReadTimeout)
	if h.config.NonBlock {
		/*
			Non-blocking mode; we call poll() to pick up error
			indications, but we don't want it to wait for
			anything.
		*/
		h.pollTimeout = 0
	} else if timeout == 0 {
		if h.headerVersion == unix.TPACKET_V3 && hasBrokenTPacketV3() {
			// to quote libpcap:
			/*
				XXX - due to a set of (mis)features in the TPACKET_V3
				kernel code prior to the 3.19 kernel, blocking forever
				with a TPACKET_V3 socket can, if few packets are
				arriving and passing the socket filter, cause most
				packets to be dropped.  See libpcap issue #335 for the
				full painful story.

				The workaround is to have poll() time out very quickly,
				so we grab the frames handed to us, and return them to
				the kernel, ASAP.
			*/
			h.pollTimeout = 1
		} else {
			h.pollTimeout = -1
		}
	} else if timeout > 0 {
		if h.headerVersion == unix.TPACKET_V3 && !hasBrokenTPacketV3() {
			// block forever, let TPACKET_V3 wake us up
			h.pollTimeout = -1
		} else {
			h.pollTimeout = int(timeout)
		}
	} else {
		// they asked for it!
		h.pollTimeout = -1
	}
}

var (
	eAGAIN     error = unix.EAGAIN
	eTIMEDOUT  error = unix.ETIMEDOUT
	eBreakLoop error = ^ErrBreakLoop(0)
	eWouldPoll error = ^ErrWouldPoll(0)
)

// poll for descriptors readiness
func (h *handle) poll() error {
	var pollinfo = [2]unix.PollFd{
		{Fd: int32(h.fd), Events: unix.POLLIN, Revents: 0},
		{Fd: int32(h.breakLoopfd), Events: unix.POLLIN, Revents: 0},
	}
	n, _, err := unix.Syscall(unix.SYS_POLL, uintptr(unsafe.Pointer(&pollinfo)), uintptr(2), uintptr(h.pollTimeout))
	switch {
	case n > 0:
		/*
			check if we have told to break from loop, before checking if we can read.
			we don't want to keep reading while the user has requested to break from loop.
		*/
		if pollinfo[1].Revents == unix.POLLIN {
			h.resetBreakLoop()
			return eBreakLoop
		}
		if pollinfo[0].Revents == unix.POLLIN {
			// we have something to read
			return nil
		}
		// something else other than "you can read on these descriptors".
		if pollinfo[0].Revents != 0 {
			if pollinfo[0].Revents&unix.POLLNVAL != 0 {
				// socket closed!
				return unix.EINVAL
			}
			// there is no current known possiblilities for this error to ever occur on
			// AF_PACKET socket. at this point you can even open an issue on GitHub :P
			if pollinfo[0].Revents&(unix.POLLHUP|unix.POLLRDHUP) != 0 {
				// socket hangup! check if interface is still alive
				if err := h.interfaceAlive(); err != nil {
					return err
				}
				return errors.New("AF_POCKET socket hangup")
			}
			if pollinfo[0].Revents&unix.POLLERR != 0 {
				v, err := unix.GetsockoptInt(h.fd, unix.SOL_SOCKET, unix.SO_ERROR)
				if err != nil {
					return os.NewSyscallError("getsockopt.SO_ERROR", err)
				}
				return os.NewSyscallError("poll.AF_PACKET", unix.Errno(v))
			}
		}
		if pollinfo[1].Revents != 0 {
			if pollinfo[0].Revents&unix.POLLNVAL != 0 {
				// socket closed!
				return unix.EINVAL
			}
		}
	case err != 0:
		// if we've received a signal, check if it's break loop
		// and return break loop error
		if err == unix.EINTR && h.shouldBreakLoop() {
			h.resetBreakLoop()
			return eBreakLoop
		}
		return os.NewSyscallError("poll", err)
	default:
		if h.pollTimeout > 0 {
			return eTIMEDOUT
		}
		if h.pollTimeout == -1 {
			if err := h.interfaceAlive(); err != nil {
				return err
			}
		}
	}
	// if none of the above occured return EAGAIN
	return eAGAIN
}

func (h *handle) interfaceAlive() error {
	// listening on "any" interface
	if h.netIf == nil {
		return nil
	}
	iff, err := net.InterfaceByIndex(h.netIf.Index)
	if err != nil {
		return err
	}
	// interface went down?
	if iff.Flags&net.FlagUp != 0 {
		return unix.ENETDOWN
	}
	return nil
}

func (h *handle) loopBackIndex(promisc bool) int {
	if h.netIf != nil && h.netIf.Flags&net.FlagLoopback == 0 {
		return h.netIf.Index
	}
	if !promisc {
		return -1
	}
	/*
		We check for loopback interface if this interface is not loopback.
		this check can only matter with promiscuous mode, where interface will parse
		packets that are not designated to it.
		what if there are more than one loopback interface?
	*/
	ifs, _ := net.Interfaces()
	for i := range ifs {
		if ifs[i].Flags&net.FlagLoopback != 0 {
			return ifs[i].Index
		}
	}
	return -1
}
