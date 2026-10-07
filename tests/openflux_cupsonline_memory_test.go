package cupsonline

import (
	"encoding/binary"
	"runtime"
	"testing"

	"openflux/transport"
)

// This drives the real Send method with 200,000 distinct network flows. Only
// its WebSocket egress is replaced with a one-packet, synchronously drained
// queue, so no network, credentials, accumulating test queue or timers obscure
// the transport's retained heap. Existing flow-to-channel affinity is asserted.
func TestCupsonlineFlowChurnRetainedMemory(t *testing.T) {
	tr := NewCupsonlineTransport("", transport.DefaultConfig(), false)
	for i := 0; i < 4; i++ {
		tr.wss = append(tr.wss, &cupsWS{
			auth:   &cupsAuth{roomUUID: "synthetic-room"},
			config: DefaultCupsonlineConfig(), ctx: make(chan struct{}),
			sendQueue: make(chan []byte, 1), stats: &channelStats{},
		})
	}
	packet := make([]byte, 24)
	packet[0], packet[9] = 0x45, 17
	binary.BigEndian.PutUint32(packet[16:20], 0x0a000001)
	binary.BigEndian.PutUint16(packet[20:22], 12345)
	binary.BigEndian.PutUint16(packet[22:24], 443)
	send := func(flow uint32) {
		binary.BigEndian.PutUint32(packet[12:16], flow)
		want := int(flowHash(extractFlowKey(packet)) % uint64(len(tr.wss)))
		if err := tr.Send(packet); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-tr.wss[want].sendQueue:
			if string(got) != string(packet) {
				t.Fatal("packet changed")
			}
		default:
			t.Fatalf("flow %d did not select its existing hash channel %d", flow, want)
		}
	}
	for i := uint32(0); i < 100; i++ {
		send(i)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < 200000; i++ {
		send(1)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	repeated := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("200000 repeated same-flow sends: retained heap growth %d bytes", repeated)
	if repeated > 1<<20 {
		t.Fatalf("control retained %d bytes", repeated)
	}
	before = after
	for i := uint32(100); i < 200100; i++ {
		send(i)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(tr)
	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("200000 additional flows: retained heap growth %d bytes", growth)
	if growth > 1<<20 {
		t.Fatalf("transport retained %d bytes after drained flow churn; want <= 1 MiB", growth)
	}
}
