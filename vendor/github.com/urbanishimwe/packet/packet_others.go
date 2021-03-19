// +build !linux

package packet

func newHandler(iff string, c *Config) (Handler, error) {
	return nil, ErrNotImplemented
}

func tstampValid(status uint32) int8 {
	return -1
}

func vlanValid(status uint32) bool {
	return false
}

func interfaceLinkType(iff string) (link LinkType) {
	return LinkTypeNone
}

func kernelVersion() (major int32, minor int32) {
	return -1, -1
}

func init() {
	isOSSupported = false
}
