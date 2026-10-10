package flow

import (
	"testing"
	"time"

	"netsentinel/internal/model"
)

func TestFiveTupleKey(t *testing.T) {
	p := model.PacketInfo{SrcIP: "2001:db8::1", DstIP: "2001:db8::2", SrcPort: 1234, DstPort: 443, Protocol: "TCP"}
	id := KeyFor(p).ID()
	for name, change := range map[string]func(*model.PacketInfo){
		"source IP":        func(p *model.PacketInfo) { p.SrcIP = "2001:db8::3" },
		"destination IP":   func(p *model.PacketInfo) { p.DstIP = "2001:db8::3" },
		"source port":      func(p *model.PacketInfo) { p.SrcPort++ },
		"destination port": func(p *model.PacketInfo) { p.DstPort++ },
		"protocol":         func(p *model.PacketInfo) { p.Protocol = "UDP" },
		"direction": func(p *model.PacketInfo) {
			p.SrcIP, p.DstIP = p.DstIP, p.SrcIP
			p.SrcPort, p.DstPort = p.DstPort, p.SrcPort
		},
	} {
		t.Run(name, func(t *testing.T) {
			other := p
			change(&other)
			if KeyFor(other).ID() == id {
				t.Fatal("different tuple produced same ID")
			}
		})
	}
	p.Protocol = "tcp"
	if KeyFor(p).ID() != id {
		t.Fatal("protocol case changed key")
	}
}

func TestFlowCountersLRUAndExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	tracker := New(2, 10*time.Second)
	p := model.PacketInfo{Timestamp: now, SrcIP: "192.0.2.1", DstIP: "198.51.100.1", SrcPort: 1000, DstPort: 443, Protocol: "TCP", PacketSize: 60, SYN: true}
	tracker.Observe(p, now)
	p.ACK, p.FIN, p.RST = true, true, true
	p.Timestamp = now.Add(time.Second)
	tracker.Observe(p, p.Timestamp)
	f, ok := tracker.Get(KeyFor(p).ID())
	if !ok || f.PacketCount != 2 || f.ByteCount != 120 || f.SynCount != 2 || f.AckCount != 1 || f.FinCount != 1 || f.RstCount != 1 || !f.FirstSeen.Equal(now) || !f.LastSeen.Equal(p.Timestamp) {
		t.Fatalf("bad flow: %+v", f)
	}
	p2 := p
	p2.DstPort = 80
	tracker.Observe(p2, now.Add(2*time.Second))
	tracker.Observe(p, now.Add(3*time.Second)) // Touch first flow, making p2 oldest.
	p3 := p
	p3.DstPort = 8080
	tracker.Observe(p3, now.Add(4*time.Second))
	if _, ok := tracker.Get(KeyFor(p2).ID()); ok {
		t.Fatal("LRU flow not evicted")
	}
	if tracker.Len() != 2 || tracker.Evicted() != 1 {
		t.Fatal("bad capacity accounting")
	}
	tracker.Expire(now.Add(13 * time.Second))
	if tracker.Len() != 1 {
		t.Fatal("idle expiry did not remove oldest flow")
	}
	tracker.Expire(now.Add(14 * time.Second))
	if tracker.Len() != 0 {
		t.Fatal("idle expiry boundary")
	}
	p.Protocol = "ICMP"
	tracker.Observe(p, now)
	if tracker.Len() != 0 {
		t.Fatal("ICMP should not create a transport flow")
	}
}
