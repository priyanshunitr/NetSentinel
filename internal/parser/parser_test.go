package parser

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"netsentinel/internal/testutil"
)

func TestTCPMetadataAndOwnership(t *testing.T) {
	data := testutil.TCP(t, "192.0.2.1", "198.51.100.2", 1234, 443, true, false)
	data[14+20+13] = 0x3f // FIN SYN RST PSH ACK URG; checksum verification is outside v1.
	now := time.Now()
	p, err := Parse(data, testutil.Info(data, now), layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	if p.Protocol != "TCP" || p.SrcIP != "192.0.2.1" || p.DstIP != "198.51.100.2" || p.SrcPort != 1234 || p.DstPort != 443 || p.SrcMAC != "00:01:02:03:04:05" || !p.SYN || !p.ACK || !p.FIN || !p.RST || !p.PSH || !p.URG || p.PacketSize != len(data) || !p.Timestamp.Equal(now) {
		t.Fatalf("bad metadata: %+v", p)
	}
	clear(data)
	if p.SrcIP != "192.0.2.1" || p.SrcMAC != "00:01:02:03:04:05" {
		t.Fatal("metadata aliases raw packet")
	}
}

func TestIPv6UDPAndExtensions(t *testing.T) {
	ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
	udp := &layers.UDP{SrcPort: 1234, DstPort: 53}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	data := testutil.Serialize(t, ip, udp, gopacket.Payload([]byte{0xff})) // Deliberately invalid DNS payload.
	for _, extended := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "destination extension"}[extended], func(t *testing.T) {
			raw := append([]byte(nil), data...)
			if extended {
				raw = append(append(append([]byte(nil), data[:40]...), []byte{17, 0, 0, 0, 0, 0, 0, 0}...), data[40:]...)
				raw[6] = byte(layers.IPProtocolIPv6Destination)
				binary.BigEndian.PutUint16(raw[4:6], uint16(len(raw)-40))
			}
			p, err := Parse(raw, testutil.Info(raw, time.Now()), layers.LinkTypeRaw)
			if err != nil || p.Protocol != "UDP" || p.SrcIP != "2001:db8::1" || p.DstPort != 53 {
				t.Fatalf("IPv6 UDP: %+v %v", p, err)
			}
		})
	}
}

func TestICMPAndVLAN(t *testing.T) {
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeDot1Q}
	tag := &layers.Dot1Q{VLANIdentifier: 42, Type: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP("192.0.2.1").To4(), DstIP: net.ParseIP("198.51.100.1").To4(), Protocol: layers.IPProtocolICMPv4}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)}
	data := testutil.Serialize(t, eth, tag, ip, icmp)
	p, err := Parse(data, testutil.Info(data, time.Now()), layers.LinkTypeEthernet)
	if err != nil || p.Protocol != "ICMP" || p.SrcPort != 0 || p.SrcMAC == "" {
		t.Fatalf("VLAN ICMP: %+v %v", p, err)
	}
	ip6 := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolICMPv6, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
	icmp6 := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)}
	if err := icmp6.SetNetworkLayerForChecksum(ip6); err != nil {
		t.Fatal(err)
	}
	data = testutil.Serialize(t, ip6, icmp6, gopacket.Payload([]byte{0, 0, 0, 0}))
	p, err = Parse(data, testutil.Info(data, time.Now()), layers.LinkTypeRaw)
	if err != nil || p.Protocol != "ICMP" {
		t.Fatalf("IPv6 ICMP: %+v %v", p, err)
	}
}

func TestIPv6HopByHopAndFragment(t *testing.T) {
	ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP, SrcIP: net.ParseIP("2001:db8::1"), DstIP: net.ParseIP("2001:db8::2")}
	udp := &layers.UDP{SrcPort: 1234, DstPort: 443}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	data := testutil.Serialize(t, ip, udp)
	for _, fragment := range []bool{false, true} {
		raw := append(append(append([]byte(nil), data[:40]...), []byte{17, 0, 0, 0, 0, 0, 0, 0}...), data[40:]...)
		raw[6] = byte(layers.IPProtocolIPv6HopByHop)
		if fragment {
			raw[6] = byte(layers.IPProtocolIPv6Fragment)
		}
		binary.BigEndian.PutUint16(raw[4:6], uint16(len(raw)-40))
		p, err := Parse(raw, testutil.Info(raw, time.Now()), layers.LinkTypeRaw)
		if err != nil || p.Truncated || p.Fragmented != fragment {
			t.Fatalf("extension metadata: %+v %v", p, err)
		}
		if fragment && (p.Protocol != "FRAGMENT" || p.SrcPort != 0) {
			t.Fatal("IPv6 fragment created a transport flow")
		}
		if !fragment && (p.Protocol != "UDP" || p.DstPort != 443) {
			t.Fatal("hop-by-hop extension hid UDP header")
		}
	}
}

func TestFragmentsTunnelsAndTruncation(t *testing.T) {
	data := testutil.TCP(t, "192.0.2.1", "198.51.100.2", 1234, 443, true, false)
	fragment := append([]byte(nil), data...)
	fragment[14+6] = 0x20 // IPv4 more-fragments bit.
	p, err := Parse(fragment, testutil.Info(fragment, time.Now()), layers.LinkTypeEthernet)
	if err != nil || p.Protocol != "FRAGMENT" || !p.Fragmented || p.SrcPort != 0 || p.SYN {
		t.Fatalf("fragment entered TCP path: %+v %v", p, err)
	}
	outer := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolIPv4, SrcIP: net.ParseIP("192.0.2.5").To4(), DstIP: net.ParseIP("198.51.100.5").To4()}
	tunnel := testutil.Serialize(t, outer, gopacket.Payload(data[14:]))
	p, err = Parse(tunnel, testutil.Info(tunnel, time.Now()), layers.LinkTypeRaw)
	if err != nil || p.Protocol != "IP/4" || p.SrcIP != "192.0.2.5" || p.SrcPort != 0 {
		t.Fatalf("inner transport confused outer flow: %+v %v", p, err)
	}
	ci := testutil.Info(data, time.Now())
	ci.Length += 100
	p, err = Parse(data, ci, layers.LinkTypeEthernet)
	if err != nil || !p.Truncated || p.PacketSize != ci.Length {
		t.Fatalf("truncation metadata: %+v %v", p, err)
	}
}

func TestMalformedAndUnsupported(t *testing.T) {
	for _, data := range [][]byte{nil, {1, 2, 3}, make([]byte, 13)} {
		if _, err := Parse(data, testutil.Info(data, time.Now()), layers.LinkTypeEthernet); !errors.Is(err, ErrMalformed) {
			t.Fatalf("want malformed, got %v", err)
		}
	}
	data := testutil.TCP(t, "192.0.2.1", "198.51.100.2", 1234, 443, true, false)
	if _, err := Parse(data[:14+20+5], testutil.Info(data[:39], time.Now()), layers.LinkTypeEthernet); !errors.Is(err, ErrMalformed) {
		t.Fatalf("short TCP: %v", err)
	}
	data[12], data[13] = 0x08, 0x06 // ARP is outside the IP analyzer.
	if _, err := Parse(data, testutil.Info(data, time.Now()), layers.LinkTypeEthernet); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ARP: %v", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(testutil.TCP(f, "192.0.2.1", "198.51.100.2", 1234, 443, true, false), byte(layers.LinkTypeEthernet))
	f.Add([]byte{0x60}, byte(layers.LinkTypeRaw))
	f.Fuzz(func(t *testing.T, data []byte, link byte) {
		if len(data) > 65535 {
			t.Skip()
		}
		p, err := Parse(data, testutil.Info(data, time.Unix(1000, 0)), layers.LinkType(link))
		if err == nil && (p.SrcIP == "" || p.DstIP == "" || p.Protocol == "") {
			t.Fatalf("incomplete successful parse: %+v", p)
		}
	})
}
