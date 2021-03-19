package capture

import (
	"context"
	"net"
	"runtime"
	"testing"
	"unsafe"

	"github.com/google/gopacket/pcap"
	raw "github.com/urbanishimwe/packet"
	"golang.org/x/sys/unix"
)

var LoopBack = func() net.Interface {
	ifis, _ := net.Interfaces()
	for _, v := range ifis {
		if v.Flags&net.FlagLoopback != 0 {
			return v
		}
	}
	return ifis[0]
}()

func TestSetInterfaces(t *testing.T) {
	l := &Listener{}
	l.host = "127.0.0.1"
	l.setInterfaces()
	if len(l.Interfaces) != 1 {
		t.Error("expected a single interface")
	}
	l.host = LoopBack.HardwareAddr.String()
	l.setInterfaces()
	if l.Interfaces[0].Name != LoopBack.Name && len(l.Interfaces) != 1 {
		t.Error("interface should be loop back interface")
	}
	l.host = ""
	l.setInterfaces()
	if len(l.Interfaces) < 1 {
		t.Error("should get all interfaces")
	}
}

func TestBPFFilter(t *testing.T) {
	l := &Listener{}
	l.host = "127.0.0.1"
	l.Transport = "tcp"
	l.setInterfaces()
	filter := l.Filter(l.Interfaces[0])
	if filter != "(tcp dst portrange 0-65535 and host 127.0.0.1)" {
		t.Error("wrong filter", filter)
	}
	l.port = 8000
	l.trackResponse = true
	filter = l.Filter(l.Interfaces[0])
	if filter != "(tcp port 8000 and host 127.0.0.1)" {
		t.Error("wrong filter")
	}
}

func TestPcapHandler(t *testing.T) {
	l, err := NewListener(LoopBack.Name, 8000, "", EnginePcap, true)
	if err != nil {
		t.Errorf("expected error to be nil, got %v", err)
		return
	}
	err = l.Activate()
	if err != nil {
		t.Errorf("expected error to be nil, got %v", err)
		return
	}
	defer l.Handles[LoopBack.Name].(*pcap.Handle).Close()
	if err != nil {
		t.Errorf("expected error to be nil, got %v", err)
		return
	}
	for i := 0; i < 5; i++ {
		_, _ = net.Dial("tcp", "127.0.0.1:8000")
	}
	sts, _ := l.Handles[LoopBack.Name].(*pcap.Handle).Stats()
	if sts.PacketsReceived < 5 {
		t.Errorf("expected >=5 packets got %d", sts.PacketsReceived)
	}
}

func TestWriteRawSocket(t *testing.T) {
	l, err := initListener(LoopBack.Name, 8000, EngineRawSocket, true, nil)
	err = l.Activate()
	if err != nil {
		return
	}
	defer l.closeHandles(LoopBack.Name)
	h := l.Handles[LoopBack.Name].(*socket).h
	if err = writeSocket(h); err != nil {
		t.Fatal(err.Error())
		return
	}
}

func BenchmarkPcapFile(b *testing.B) {
	runtime.GOMAXPROCS(1)
	ps := 0
	for i := 0; i < b.N; i++ {
		ps = 0
		b.StopTimer()
		l, err := initListener("testdata/ip6", 0, EnginePcapFile, true, nil)
		if err != nil {
			b.Fatal(err.Error())
		}
		b.StartTimer()
		l.Listen(context.Background(), func(*Packet) {
			ps++
		})
	}
	b.ReportMetric(float64(ps), "packets/op")
}

func BenchmarkReadSocketBufferFull(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		l, err := initListener(LoopBack.Name, 0, EngineRawSocket, true, nil)
		if err != nil {
			b.Skip(err.Error())
		}
		h := l.Handles[LoopBack.Name].(*socket).h
		if err = writeSocket(h); err != nil {
			b.Fatal(err.Error())
		}
		ctx, cancel := context.WithCancel(context.Background())
		b.StartTimer()
		ps := 0
		l.Listen(ctx, func(*Packet) {
			ps++
			if ps >= 1000 {
				b.StopTimer()
				h.BreakLoop()
				cancel()
			}
		})
		b.StopTimer()
		cancel()
		b.ReportMetric(float64(ps), "packets/op")
		ps = 0
	}
}

func BenchmarkReadPcapBufferFull(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		l, err := initListener(LoopBack.Name, 0, EnginePcap, true, &PcapOptions{BufferTimeout: 1})
		if err != nil {
			b.Skip(err.Error())
		}
		h := l.Handles[LoopBack.Name].(*pcap.Handle)
		if err = writePcap(h); err != nil {
			b.Fatal(err.Error())
		}
		ctx, cancel := context.WithCancel(context.Background())
		b.StartTimer()
		ps := 0
		l.Listen(ctx, func(*Packet) {
			ps++
			if ps >= 1000 {
				b.StopTimer()
				h.Close()
				cancel()
			}
		})
		b.StopTimer()
		cancel()
		b.ReportMetric(float64(ps), "packets/op")
		ps = 0
	}
}

func initListener(addr string, port uint16, eng EngineType, response bool, opt *PcapOptions) (l *Listener, err error) {
	l, err = NewListener(addr, port, "", eng, true)
	if err != nil {
		return
	}
	err = l.Activate()
	if err != nil {
		return
	}
	if opt != nil {
		l.SetPcapOptions(*opt)
	}
	return
}

func readPackets(f string) [][]byte {
	ps := make([][]byte, 0, 10)
	handle, err := pcap.OpenOffline(f)
	if err != nil {
		return nil
	}
	var r []byte
	for err == nil {
		r, _, err = handle.ReadPacketData()
		if len(r) > 0 {
			ps = append(ps, r)
		}
	}
	return ps[:len(ps):len(ps)]
}

var wholeBuffer = func() [][]byte {
	buffer := 256 * 1024
	ps := readPackets("testdata/ip")
	if len(ps) < 1 {
		return nil
	}
	hdrSize := unix.SizeofSockaddrLinklayer + unix.SizeofTpacket3Hdr
	totalLen := func(p [][]byte) (_len int) {
		for i := range p {
			_len += (len(p[i]) + hdrSize)
		}
		return _len + int(unsafe.Sizeof(unix.TpacketBlockDesc{}))
	}
	full := ps
	for (totalLen(full) - totalLen(ps)) <= buffer {
		full = append(full, ps...)
	}
	_len := int(unsafe.Sizeof(unix.TpacketBlockDesc{}))
	for i := range full {
		_len += (len(full[i]) + hdrSize)
		if _len > buffer {
			_len = i
			break
		}
	}
	return full[:_len]
}()

func writeSocket(h raw.Handler) error {
	for _, v := range wholeBuffer {
		_, err := h.Write(v, nil, raw.ProtoIP)
		if err != nil {
			return err
		}
	}
	return nil
}

func writePcap(h *pcap.Handle) error {
	for _, v := range wholeBuffer {
		err := h.WritePacketData(v)
		if err != nil {
			return err
		}
	}
	return nil
}
