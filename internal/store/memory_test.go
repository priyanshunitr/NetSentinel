package store

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"netsentinel/internal/config"
	"netsentinel/internal/model"
)

func TestPacketFilters(t *testing.T) {
	p := model.PacketInfo{SrcIP: "192.0.2.1", DstIP: "198.51.100.1", SrcPort: 1000, DstPort: 443, Protocol: "TCP"}
	port443, port1000, other, zero := uint16(443), uint16(1000), uint16(80), uint16(0)
	for _, tc := range []struct {
		name   string
		filter PacketFilter
		want   bool
	}{
		{"all", PacketFilter{}, true}, {"case", PacketFilter{Protocol: "tcp"}, true},
		{"protocol", PacketFilter{Protocol: "UDP"}, false}, {"source", PacketFilter{SrcIP: p.SrcIP}, true},
		{"wrong source", PacketFilter{SrcIP: p.DstIP}, false}, {"destination port", PacketFilter{Port: &port443}, true},
		{"source port", PacketFilter{Port: &port1000}, true}, {"wrong port", PacketFilter{Port: &other}, false},
		{"and", PacketFilter{Protocol: "UDP", Port: &port443}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.filter.Match(p) != tc.want {
				t.Fatal("unexpected match")
			}
		})
	}
	p.Protocol = "ICMP"
	p.SrcPort = 0
	p.DstPort = 0
	if (PacketFilter{Port: &zero}).Match(p) {
		t.Fatal("ICMP matched fabricated port zero")
	}
}

func TestBoundedStorageStatisticsAndSnapshots(t *testing.T) {
	c := config.Default()
	c.MaxPackets = 2
	c.MaxAlerts = 2
	c.MaxFlows = 2
	s := New(c)
	now := time.Unix(1000, 0)
	for i := 0; i < 3; i++ {
		p := model.PacketInfo{Timestamp: now, SrcIP: fmt.Sprintf("192.0.2.%d", i), DstIP: "198.51.100.1", SrcPort: 1000, DstPort: 443, Protocol: "TCP", PacketSize: 60}
		s.AddPacket(p, now.Add(time.Duration(i)*time.Second))
		s.AddAlerts([]model.Alert{{Type: "test"}})
	}
	packets, alerts := s.Packets(PacketFilter{}, 10), s.Alerts(10)
	if len(packets) != 2 || packets[0].SrcIP != "192.0.2.2" || packets[1].SrcIP != "192.0.2.1" || len(alerts) != 2 || alerts[0].ID != "alert-3" || alerts[1].ID != "alert-2" {
		t.Fatal("rings did not overwrite oldest entries")
	}
	stats := s.Stats()
	if stats.TotalPackets != 3 || stats.TotalBytes != 180 || stats.TCPPackets != 3 || stats.AlertsGenerated != 3 || stats.ActiveFlows != 2 || stats.FlowsEvicted != 1 || stats.RetainedPackets != 2 || stats.TopDestinationPorts[0].Count != 2 || len(stats.TopSourceIPs) != 2 {
		t.Fatalf("bad stats: %+v", stats)
	}
	packets[0].SrcIP = "changed"
	alerts[0].Type = "changed"
	flows := s.Flows(10)
	flows[0].PacketCount = 999
	if s.Packets(PacketFilter{}, 1)[0].SrcIP == "changed" || s.Alerts(1)[0].Type == "changed" || s.Flows(1)[0].PacketCount == 999 {
		t.Fatal("API snapshots mutate storage")
	}
	s.Expire(now.Add(time.Minute + 2*time.Second))
	if s.Stats().ActiveFlows != 0 {
		t.Fatal("idle flows still active")
	}
}

func TestConcurrentReadersAndWriter(t *testing.T) {
	s := New(config.Default())
	now := time.Now()
	var wg sync.WaitGroup
	for reader := 0; reader < 4; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				s.Stats()
				s.Packets(PacketFilter{}, 20)
				s.Alerts(20)
				s.Flows(20)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			s.AddPacket(model.PacketInfo{Timestamp: now, SrcIP: "192.0.2.1", DstIP: "198.51.100.1", Protocol: "UDP", PacketSize: 60}, now)
			s.AddAlerts([]model.Alert{{Type: "test"}})
		}
	}()
	wg.Wait()
	if s.Stats().TotalPackets != 1000 {
		t.Fatal("lost updates")
	}
}
