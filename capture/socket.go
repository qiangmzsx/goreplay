package capture

import (
	"github.com/google/gopacket"
	raw "github.com/urbanishimwe/packet"
)

type socket struct {
	h raw.Handler
}

func newSocket(iff string, config *raw.Config) (*socket, error) {
	h, err := raw.NewHandler(iff, config)
	if err != nil {
		return nil, err
	}
	return &socket{h}, nil
}

func (s *socket) ReadPacketData() (buf []byte, i gopacket.CaptureInfo, err error) {
	var p *raw.Info
	buf, p, err = s.h.Read(true)
	if err != nil {
		return
	}
	i = gopacket.CaptureInfo{
		CaptureLength:  p.CapLen,
		Length:         p.Len,
		Timestamp:      p.Time,
		InterfaceIndex: int(p.Ifindex),
		AncillaryData:  []interface{}{p.Link, p.VLAN},
	}
	return
}

func (s *socket) isCooked() bool {
	return s.h.Config().NoLinkLayer
}

func (s *socket) Close() error {
	s.h.BreakLoop()
	return s.h.Close()
}
