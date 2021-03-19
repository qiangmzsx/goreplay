// +build linux

package packet

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

func tstampValid(status uint32) int8 {
	if status&unix.TP_STATUS_TS_SOFTWARE != 0 {
		return 0
	}
	if status&unix.TP_STATUS_TS_RAW_HARDWARE != 0 {
		return 1
	}
	return -1
}

func vlanValid(status uint32) bool {
	return status&unix.TP_STATUS_VLAN_TPID_VALID != 0 &&
		status&unix.TP_STATUS_VLAN_VALID != 0
}

func interfaceLinkType(iff string) (link LinkType) {
	link = LinkTypeNone
	if iff == "" {
		return
	}
	b, err := ioutil.ReadFile(fmt.Sprintf("/sys/class/net/%s/type", iff))
	if err != nil {
		return
	}
	n, err := strconv.Atoi(string(b))
	if err != nil {
		return
	}
	if n == unix.ARPHRD_LOOPBACK {
		// loopback (mostly) use ethernet header. we are going to assume that
		// until someone prove us wrong!
		link = LinkTypeEthernet
	}
	return
}

func kernelVersion() (major int32, minor int32) {
	hasBrokenTPacketV3()
	if brokenTPacketV3 == -1 /* uname failed */ {
		return -1, -1
	}
	return _major, _minor
}

var (
	brokenTPacketV3   int8 = -1
	brokenTPacketV3Mu sync.Mutex
	_major, _minor    int32
)

/*
it is said linux <3.19 have "misfeatures" in handling of TPacketv3.
detect those systems
*/
func hasBrokenTPacketV3() bool {
	brokenTPacketV3Mu.Lock()
	defer brokenTPacketV3Mu.Unlock()
	if brokenTPacketV3 != -1 {
		return brokenTPacketV3 == 1
	}
	var b unix.Utsname
	err := unix.Uname(&b)
	if err != nil {
		// we don't expect uname to fail buf if it does we assume broken.
		return true
	}
	n, _ := fmt.Sscanf(string(b.Release[:]), "%d.%d", &_major, &_minor)
	if _major > 3 || (_major == 3 && _minor >= 19) {
		// OK, a fixed version.
		brokenTPacketV3 = 0
		return false
	}
	if n < 2 {
		_major = -1
		_minor = -1
	}
	brokenTPacketV3 = 1
	return true
}

func init() {
	LinkTypeEthernet = unix.ARPHRD_ETHER
	LinkTypeNone = unix.ARPHRD_VOID
	ProtoIP = unix.ETH_P_IP
	ProtoIP6 = unix.ETH_P_IPV6
	ProtoARP = unix.ETH_P_ARP
	ProtoAll = unix.ETH_P_ALL
	isOSSupported = true
	v := uint32(0xff000000)
	isBigEndian = *(*byte)(unsafe.Pointer(&v)) == 0xff
}
