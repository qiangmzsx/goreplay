// Package packet provides basic APIs for linux packet socket.
/*
This package uses memory mapping to increase performance and reduce system calls during packets reading.
Most errors returned by this package are of type syscall.Errno, *os.SyscallError,
and others listed in the documentation.

Handler.Fd() is there to help users of this package to implements functionalities that are not provided
by this package. However, it should be used with great care.
*/
package packet

import (
	"errors"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
)

// Handler is an interface for a linux packet socket.
type Handler interface {
	// read a packet from the socket.
	//
	// poll, if true, Read will wait for a packet(s), an error, a timeout, or an event on the socket.
	// if poll is false and there no packets to read, Read will return immediately with an error set to ErrWouldPoll.
	//
	// it is recommended to read documentation of Config and Handler.BreakLoop before using this method.
	Read(poll bool) (raw []byte, info *Info, err error)
	// transmit a packet to the socket.
	//
	// if iff is nil, interface bound to this socket is used.
	// EINVAL is returned if iff is nil and socket is not bound to an interface or values in iff are invalid
	// or protocol value is invalid.
	//
	// protocol is an ethernet protocol. values of common protocols are exposed by this library.
	Write(buf []byte, iff *net.Interface, protocol Proto) (int, error)
	// returns packet socket file descriptor, always.
	Fd() uintptr
	// poll happening in the middle or after a call to this method will return ErrBreakLoop.
	BreakLoop() error
	// similar to (*Config).Filter, attaches an assembled BPF program to the socket.
	// if filter length is 0, this method will detach recently added filters.
	SetBPF(filter []bpf.RawInstruction) error
	// if total is true Stats returns the total stats since the socket lifetime or stats
	// since the recent call to this method otherwise.
	//
	// in case of any error, this method returns *Stats with zero values.
	Stats(total bool) *Stats
	// returns pointer to the internal Config used this handle.
	Config() *Config
	// returns the link type of the interface bound to this socket or LinkTypeNone.
	LinkType() LinkType
	// close the handle sockets. reads and writes operations after this call should return EINVAL.
	Close() error
}

// NewHandler activates and configure a linux packet socket and return its handler.
//
// socket is bound to iff interface. if iff is empty string, socket receives packets from all interfaces
// and config.NoLinkLayer is set to true.
// if config is nil, default configuration is used.
// it returns an error or a non-nil handler.
func NewHandler(iff string, config *Config) (Handler, error) {
	return newHandler(iff, config)
}

// Info useful information of a packet
type Info struct {
	Time    time.Time // unix timestamp this packet was captured, if that is known.
	CapLen  int       // the total number of bytes read off of the wire.
	Len     int       // original packet length. should be>= CapLen.
	Ifindex int32     // interface index.
	Status  uint32    // linux status variable in t_packet header. can be used to validate timestamp and vlan tags.
	VLAN    VLAN
	Link    Link
}

// Link is packet's link layer info
type Link struct {
	Protocol Proto    // ethernet protocol type
	LinkType LinkType // arp type
}

// VLAN IEEE 802.1Q
type VLAN struct {
	TPID uint16
	TCI  uint16
}

// Stats contains statistics about a handle.
type Stats struct {
	// number of packets received by the socket(excluding those that failed the BPF filter check).
	Recvs uint64
	// number of packets dropped(due to the short buffer size). this number does not include packets that failed BPF filters.
	Drops uint64
}

// ErrNotImplemented requested functionality is not implemented for the host operating system.
var ErrNotImplemented = errors.New("not implemented")

// ErrBreakLoop returned when loop was terminated by BreakLoop.
type ErrBreakLoop uint8

func (e ErrBreakLoop) Error() string {
	return "loop terminated"
}

// Temporary ErrBreakLoop is a temporary error
func (e ErrBreakLoop) Temporary() bool {
	return true
}

// ErrWouldPoll read would rather poll.
type ErrWouldPoll uint8

func (e ErrWouldPoll) Error() string {
	return "read would rather poll"
}

// Temporary ErrWouldPoll is a temporary error
func (e ErrWouldPoll) Temporary() bool {
	return true
}

// Direction the flow of the packet
type Direction uint8

const (
	// DirInOut incoming and outgoing
	DirInOut Direction = iota
	// DirIn incoming only
	DirIn
	// DirOut outgoing only
	DirOut
)

// TstampResolution Time stamp resolution types.
type TstampResolution uint8

const (
	// TstampNano use timestamps with nanosecond precision, default
	TstampNano TstampResolution = iota
	// TstampMicro use timestamps with microsecond precision
	TstampMicro
)

// LinkType data link layer type
type LinkType uint16

var (
	// LinkTypeEthernet standard ethernet type
	LinkTypeEthernet LinkType
	// LinkTypeNone no link type or nothing is known
	LinkTypeNone LinkType
)

// Proto ethernet protocol
type Proto uint16

// common protocols
var (
	ProtoIP  Proto
	ProtoIP6 Proto
	ProtoARP Proto
	ProtoAll Proto
)

func (l LinkType) String() string {
	switch l {
	case LinkTypeEthernet:
		return "ethernet"
	case LinkTypeNone:
		return "none"
	default:
		return ""
	}
}

// Config is used to configure a packet handler. all fields are optional.
//
// configuration should be initialized from calling DefaultConfig.
// Default value of the field is the value resulted from calling DefaultConfig().
// a care must be taken when modifying Config values(read docs of the fields).
//
// if you want to limit the packet size("snapshot") use BPF filters.
type Config struct {
	// the duration in milliseconds,
	//
	// 1. if socket is not in non-blocking mode, read will return ETIMEDOUT after waiting socket
	// readiness for this long.
	//
	// 2. if immediate mode is turned off, this is the maximum milliseconds we wait for a block of buffer
	// to become full so we can read many packets on a single poll.
	//
	// 0 means "do not timeout"; negative timeout may mean "let the kernel decide the buffer timeout"
	// and/or "wait for the socket to be ready (possibly) forever".
	ReadTimeout int64
	// Packets that arrive for a capture are stored in a buffer, so that they do not have to be read by the application as soon as they arrive.
	// a size that's too small could mean that, if too many packets are being captured,
	// packets could be dropped if the buffer fills up before the application can read packets from it,
	// while a size that's too large could use more non-pageable operating system memory than is necessary to prevent packets from being dropped.
	// custom value may be increased for buffer alignment.
	ReadBufferSize int64
	// pre-attach an assembled BPF program to the socket.
	Filter []bpf.RawInstruction
	// deliver packets as soon as they arrive, with no buffering. unless there is a special reason for this,
	// callers should not enable this feature. it many cause huge unused memory, truncating some packets and relatively higher CPU usages.
	ImmediateMode bool
	// enable promiscuous mode on an interface.
	Promiscuous bool
	// enable non-blocking mode. read/write will return immediately with EAGAIN  if the operation
	// can not be performed immediately.
	NonBlock bool
	// writes and reads will provide packet buffer with link-layer header removed(cooked mode).
	NoLinkLayer bool
	// ethernet protocol to use in socket.
	Proto Proto
	// timestamp resolution in nano or micro seconds.
	TstampResolution TstampResolution
	// flow of packet to allow.
	Direction Direction
	// the maximum number of consecutive undesired Direction of the packet that should happen
	// before a single call to Read decides to return a nil packet and a nil error.
	// this field will not matter if Direction is DirInOut.
	MaxNilRead uint64
}

// CheckIntegrity checks values in this Config and return true if all of them are valid.
func (c *Config) CheckIntegrity() bool {
	if c == nil {
		return true
	}
	if c.TstampResolution > 1 {
		return false
	}
	if c.Direction > 2 {
		return false
	}
	return true
}

var isOSSupported bool

// IsOSSupported returns true if the calling OS is supported by this library
func IsOSSupported() bool {
	return isOSSupported
}

// Temporary checks if this error is a temporary error and return true or false otherwise.
// timeout errors should also be temporary errors.
func Temporary(err error) bool {
	if e, ok := err.(interface{ Temporary() bool }); ok {
		// ErrBreakLoop, ErrWouldPoll, syscall.Errno
		return e.Temporary()
	}
	if e, ok := err.(interface{ Unwrap() error }); ok {
		if e, ok := e.Unwrap().(interface{ Temporary() bool }); ok {
			return e.Temporary()
		}
	}
	return false
}

// Timeout checks if this error is a timeout error and return true or false otherwise.
func Timeout(err error) bool {
	if e, ok := err.(interface{ Timeout() bool }); ok {
		// syscall.Errno, *os.SyscallError
		return e.Timeout()
	}
	if e, ok := err.(interface{ Unwrap() error }); ok {
		if e, ok := e.Unwrap().(interface{ Timeout() bool }); ok {
			return e.Timeout()
		}
	}
	return false
}

// TstampValid returns
/*
0: for timestamp generated by the kernel,

1: for timestamp generated by network adapter, and

-1: timestamp is invalid or something else.

status should be the value from (*Info).Status
*/
func TstampValid(status uint32) int8 {
	return tstampValid(status)
}

// VlanValid returns true if all values in VLAN struct are valid and false otherwise.
// status should be the value from (*Info).Status
func VlanValid(status uint32) bool {
	return vlanValid(status)
}

// InterfaceLinkType returns LinkType of the "iff" network interface.
// it returns LinkTypeNone if interface with "iff" name does not exists or
// we can't query such info using standard linux mechanisms
func InterfaceLinkType(iff string) (link LinkType) {
	return interfaceLinkType(iff)
}

// KernelVersion returns linux kernel major and minor version since the first check.
// these values will be -1 on error.
func KernelVersion() (major int32, minor int32) {
	return kernelVersion()
}

// DefaultConfig user should call this before creating custom Config object
func DefaultConfig() *Config {
	return &Config{
		ReadBufferSize:   -1,
		ReadTimeout:      0,
		ImmediateMode:    false,
		NonBlock:         false,
		Promiscuous:      false,
		TstampResolution: TstampNano,
		Direction:        DirInOut,
		NoLinkLayer:      false,
		Proto:            ProtoAll,
		MaxNilRead:       1024,
	}
}

var pageSize = int64(syscall.Getpagesize())

func alignVals(a, b int64) int64 {
	return ((a + b - 1) / b) * b
}

func buildSlice(data unsafe.Pointer, len int) []byte {
	return *(*[]byte)(unsafe.Pointer(&struct {
		data unsafe.Pointer
		len  int
		cap  int
	}{data, len, len}))
}

func offPointer(p unsafe.Pointer, off uint32) unsafe.Pointer {
	return unsafe.Pointer(uintptr(p) + uintptr(off))
}

var isBigEndian bool

// convert from/to big endian
func bswap16(v uint16) uint16 {
	if isBigEndian {
		return v
	}
	return (v<<8)&0xFF00 | (v>>8)&0x00FF
}
