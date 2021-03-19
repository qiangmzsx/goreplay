// +build linux

package packet

import (
	"math"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type packetScanner interface {
	createRing(fd int, size int64, flag int64) (int64, error)
	hasNext() bool         // true if there is packet available to read
	next() ([]byte, *Info) // next packet if any
	ring() []byte
	link() LinkType
}

const (
	minBuffer     = 256 * 1024 // buffer for at least one packet
	defaultBuffer = 2 * 1024 * 1024
)

type config struct {
	link   LinkType
	loop   int
	dir    Direction
	tPresc TstampResolution
}

type tPacketv3 struct {
	r      []byte // read ring
	iovec  []unix.Iovec
	n      unsafe.Pointer // pointer to the current packet
	total  int            // total packet available
	block  int            // current block
	config *config
}

func newtPacketv3(config *config) *tPacketv3 {
	return &tPacketv3{
		r:      nil,
		iovec:  nil,
		n:      nil,
		total:  0,
		block:  0,
		config: config,
	}
}

func (t *tPacketv3) createRing(fd int, size, timeout int64) (int64, error) {
	size = alignBuffer(size)
	var tReq = unix.TpacketReq3{}
	tReq.Frame_size = minBuffer
	if size <= minBuffer*2 {
		// small buffer was requested. set frame size to the half of the buffer size
		// to leave block(s) to the kernel the time we will be processing another block
		tReq.Frame_size = minBuffer / 2
	}
	size = alignVals(size, int64(tReq.Frame_size))
	tReq.Frame_nr = uint32(size) / tReq.Frame_size
	tReq.Block_nr = tReq.Frame_nr
	tReq.Block_size = tReq.Frame_size
	// time to retire block
	if timeout > 0 {
		tReq.Retire_blk_tov = uint32(timeout)
	} else if timeout == 0 {
		// "0" timeout means don't timeout,
		tReq.Retire_blk_tov = math.MaxUint32
	} else {
		/*
			if the user set negative timeout we let the kernel chose the default,
			which can be problematic for some versions of linux
			https://github.com/the-tcpdump-group/libpcap/issues/335#issuecomment-30358172
		*/
		tReq.Retire_blk_tov = 0
	}
	tReq.Sizeof_priv = 0
	tReq.Feature_req_word = 0
	err := unix.SetsockoptTpacketReq3(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, &tReq)
	if err != nil {
		return 0, &os.SyscallError{Syscall: "setsockopt.PACKET_RX_RING", Err: err}
	}
	t.r, err = createRing(fd, size)
	if err != nil {
		return 0, err
	}
	t.iovec = make([]unix.Iovec, int(tReq.Block_nr))
	for i := range t.iovec {
		t.iovec[i].Base = &t.r[i*int(tReq.Block_size)]
		t.iovec[i].Len = uint64(tReq.Block_size)
	}
	return size, nil
}

type blockDesc struct {
	version, offsetToPriv uint32
	unix.TpacketHdrV1
}

func (t *tPacketv3) hasNext() bool {
	if t.n != nil {
		return true
	}
	p := unsafe.Pointer(t.iovec[t.block].Base)
	pbd := (*blockDesc)(p)
	if atomic.LoadUint32(&pbd.Block_status)&unix.TP_STATUS_USER != 0 {
		if pbd.Num_pkts > 0 {
			t.total = int(pbd.Num_pkts)
			t.n = offPointer(p, pbd.Offset_to_first_pkt)
			return true
		}
		/*
			if block is available in userland and there is no packet in the block we
			give back block to the kernel space. check
			https://github.com/the-tcpdump-group/libpcap/issues/335#issuecomment-30266631
			for full story!
		*/
		t.flushBlock()
	}
	return false
}

func (t *tPacketv3) moveNext(offset uint32) {
	t.total--
	if t.total > 0 {
		t.n = offPointer(t.n, offset)
		return
	}
	t.flushBlock()
}

func (t *tPacketv3) flushBlock() {
	pbd := (*blockDesc)(unsafe.Pointer(t.iovec[t.block].Base))
	atomic.StoreUint32(&pbd.Block_status, unix.TP_STATUS_KERNEL)
	t.n = nil
	t.block++
	if t.block >= len(t.iovec) {
		t.block = 0
	}
}

func (t *tPacketv3) next() (raw []byte, p *Info) {
	if t.n == nil {
		return
	}
	hdr := (*unix.Tpacket3Hdr)(t.n)
	ssl := (*unix.RawSockaddrLinklayer)(offPointer(t.n, unix.SizeofTpacket3Hdr))
	if checkDirection(ssl, t.config) {
		nsec := int64(hdr.Nsec)
		if t.config.tPresc == TstampMicro {
			nsec = (nsec / 1000) * 1000
		}
		p = &Info{
			Len:     int(hdr.Snaplen),
			Time:    time.Unix(int64(hdr.Sec), nsec),
			Status:  hdr.Status,
			Ifindex: ssl.Ifindex,
			Link: Link{
				Protocol: Proto(bswap16(ssl.Protocol)),
				LinkType: LinkType(ssl.Hatype),
			},
			VLAN: VLAN{
				TPID: hdr.Hv1.Vlan_tpid,
				TCI:  uint16(hdr.Hv1.Vlan_tci),
			},
		}
		raw = make([]byte, hdr.Snaplen)
		p.CapLen = copy(
			raw,
			buildSlice(
				offPointer(t.n, uint32(hdr.Mac)),
				int(hdr.Snaplen),
			),
		)
	}
	t.moveNext(hdr.Next_offset)
	return
}

func (t *tPacketv3) link() LinkType {
	return t.config.link
}

func (t *tPacketv3) ring() []byte {
	return t.r
}

type tPacketv2 struct {
	r      []byte
	iovec  []unix.Iovec
	n      unsafe.Pointer // pointer to the current packet
	block  int            // current block
	config *config
}

func newtPacketv2(c *config) *tPacketv2 {
	return &tPacketv2{
		r:      nil,
		iovec:  nil,
		n:      nil,
		block:  0,
		config: c,
	}
}

func (t *tPacketv2) createRing(fd int, size, mtu int64) (int64, error) {
	size = alignBuffer(size)
	var tReq = unix.TpacketReq{}
	if mtu > 0 {
		tReq.Frame_size = uint32(mtu)
		if t.link() == LinkTypeEthernet {
			tReq.Frame_size += 14
		}
		tReq.Frame_size += unix.SizeofTpacket2Hdr + unix.SizeofSockaddrLinklayer
	} else {
		tReq.Frame_size = math.MaxUint16
	}
	tReq.Frame_size = uint32(alignVals(int64(tReq.Frame_size), unix.TPACKET_ALIGNMENT))
	tReq.Block_size = uint32(alignVals(int64(tReq.Frame_size), pageSize))
	/*
		round the read buffer size to multiples of Block_size
		to atleast have the ring size user requested
	*/
	size = alignVals(size, int64(tReq.Block_size))
	tReq.Block_nr = uint32(size) / tReq.Block_size
	tReq.Frame_nr = (tReq.Block_size / tReq.Frame_size) * tReq.Block_nr
	err := unix.SetsockoptTpacketReq(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, &tReq)
	if err != nil {
		return 0, &os.SyscallError{Syscall: "setsockopt.PACKET_RX_RING", Err: err}
	}
	t.r, err = createRing(fd, size)
	if err != nil {
		return 0, err
	}
	t.iovec = make([]unix.Iovec, int(tReq.Frame_nr))
	fPerB := int(tReq.Frame_nr / tReq.Block_nr)
	for block := 0; block < int(tReq.Block_nr); block++ {
		for frame := 0; frame < fPerB; frame++ {
			off := (block * int(tReq.Block_size)) + (frame * int(tReq.Frame_size))
			t.iovec[(fPerB*block)+frame].Base = &t.r[off]
			t.iovec[(fPerB*block)+frame].Len = uint64(tReq.Frame_size)
		}
	}
	return size, nil
}

func (t *tPacketv2) hasNext() bool {
	if t.n != nil {
		return true
	}
	p := unsafe.Pointer(t.iovec[t.block].Base)
	hdr := (*unix.Tpacket2Hdr)(p)
	if atomic.LoadUint32(&hdr.Status)&unix.TP_STATUS_USER != 0 {
		t.n = p
		return true
	}
	return false
}

func (t *tPacketv2) moveNext() {
	p := unsafe.Pointer(t.iovec[t.block].Base)
	hdr := (*unix.Tpacket2Hdr)(p)
	atomic.StoreUint32(&hdr.Status, unix.TP_STATUS_KERNEL)
	t.n = nil
	t.block++
	if t.block >= len(t.iovec) {
		t.block = 0
	}
}

func (t *tPacketv2) next() (raw []byte, p *Info) {
	if t.n == nil {
		return
	}
	hdr := (*unix.Tpacket2Hdr)(t.n)
	ssl := (*unix.RawSockaddrLinklayer)(offPointer(t.n, unix.SizeofTpacket2Hdr))
	if checkDirection(ssl, t.config) {
		nsec := int64(hdr.Nsec)
		if t.config.tPresc == TstampMicro {
			nsec = (nsec / 1000) * 1000
		}
		p = &Info{
			Len:     int(hdr.Snaplen),
			Time:    time.Unix(int64(hdr.Sec), nsec),
			Status:  hdr.Status,
			Ifindex: ssl.Ifindex,
			Link: Link{
				Protocol: Proto(bswap16(ssl.Protocol)),
				LinkType: LinkType(ssl.Hatype),
			},
			VLAN: VLAN{
				TPID: hdr.Vlan_tpid,
				TCI:  hdr.Vlan_tci,
			},
		}
		raw = make([]byte, hdr.Snaplen)
		p.CapLen = copy(
			raw,
			buildSlice(
				offPointer(t.n, uint32(hdr.Mac)),
				int(hdr.Snaplen),
			),
		)
	}
	t.moveNext()
	return
}

func (t *tPacketv2) link() LinkType {
	return t.config.link
}

func (t *tPacketv2) ring() []byte {
	return t.r
}

func checkDirection(sll *unix.RawSockaddrLinklayer, config *config) bool {
	if sll.Pkttype == unix.PACKET_OUTGOING {
		if config.dir == DirIn {
			return false
		}
		// drop packets looped back by loopback interface with the hope
		// of seeing them again as incoming packet
		if sll.Ifindex == int32(config.loop) && config.dir != DirOut {
			return false
		}
		return true
	}
	return config.dir != DirOut
}

func alignBuffer(bufferSize int64) int64 {
	if bufferSize <= 0 {
		return defaultBuffer
	}
	if bufferSize < minBuffer {
		return minBuffer
	}
	return alignVals(bufferSize, pageSize)
}

func createRing(fd int, size int64) ([]byte, error) {
	buf, err := unix.Mmap(fd, 0, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	return buf, os.NewSyscallError("mmap", err)
}
