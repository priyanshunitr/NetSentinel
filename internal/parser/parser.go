package parser

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"netsentinel/internal/model"
)

var (
	ErrUnsupported = errors.New("unsupported packet")
	ErrMalformed   = errors.New("malformed packet")
)

type feedback struct{ truncated bool }

func (f *feedback) SetTruncated() { f.truncated = true }

// Parse decodes the outer IP and transport headers only. In particular, a bad
// DNS message cannot cause an otherwise valid UDP packet to be discarded.
// No returned field aliases data; raw bytes can be released after this call.
func Parse(data []byte, ci gopacket.CaptureInfo, linkType layers.LinkType) (model.PacketInfo, error) {
	p := model.PacketInfo{Timestamp: ci.Timestamp.UTC(), PacketSize: ci.Length, Truncated: ci.CaptureLength < ci.Length}
	if p.PacketSize == 0 {
		p.PacketSize = len(data)
	}
	f := &feedback{}
	payload, network, err := decodeLink(data, linkType, &p, f)
	if err != nil {
		return p, err
	}
	var protocol layers.IPProtocol
	switch network {
	case layers.LayerTypeIPv4:
		var ip layers.IPv4
		if err := ip.DecodeFromBytes(payload, f); err != nil {
			return p, malformed(err)
		}
		if ip.Version != 4 {
			return p, malformed(errors.New("invalid IPv4 version"))
		}
		p.SrcIP, p.DstIP, protocol, payload = ip.SrcIP.String(), ip.DstIP.String(), ip.Protocol, ip.Payload
		p.Fragmented = ip.FragOffset != 0 || ip.Flags&layers.IPv4MoreFragments != 0
	case layers.LayerTypeIPv6:
		networkLength := len(payload)
		var ip layers.IPv6
		if err := ip.DecodeFromBytes(payload, f); err != nil {
			return p, malformed(err)
		}
		if ip.Version != 6 {
			return p, malformed(errors.New("invalid IPv6 version"))
		}
		// The library's HopByHop path compares the full payload length after
		// removing that extension. Use the actual wire boundary for this flag.
		if ip.Length > 0 {
			f.truncated = networkLength < 40+int(ip.Length)
		}
		p.SrcIP, p.DstIP, protocol, payload = ip.SrcIP.String(), ip.DstIP.String(), ip.NextHeader, ip.Payload
		if ip.HopByHop != nil {
			protocol = ip.HopByHop.NextHeader
		}
		// Skip a bounded extension chain. Authentication/ESP remain IP metadata;
		// fragments are never assigned fabricated transport ports.
		for depth := 0; ; depth++ {
			if protocol == layers.IPProtocolIPv6Fragment {
				if len(payload) < 8 {
					return p, malformed(errors.New("short IPv6 fragment header"))
				}
				p.Fragmented = true
				break
			}
			if protocol != layers.IPProtocolIPv6HopByHop && protocol != layers.IPProtocolIPv6Routing && protocol != layers.IPProtocolIPv6Destination {
				break
			}
			if depth >= 8 {
				return p, malformed(errors.New("too many IPv6 extension headers"))
			}
			var extension layers.IPv6ExtensionSkipper
			if err := extension.DecodeFromBytes(payload, f); err != nil {
				return p, malformed(err)
			}
			protocol, payload = extension.NextHeader, extension.Payload
		}
	default:
		return p, ErrUnsupported
	}
	if p.Fragmented {
		p.Protocol = "FRAGMENT"
		p.Truncated = p.Truncated || f.truncated
		return p, nil
	}
	switch protocol {
	case layers.IPProtocolTCP:
		var tcp layers.TCP
		if err := tcp.DecodeFromBytes(payload, f); err != nil {
			return p, malformed(err)
		}
		p.Protocol, p.SrcPort, p.DstPort = "TCP", uint16(tcp.SrcPort), uint16(tcp.DstPort)
		p.SYN, p.ACK, p.FIN, p.RST, p.PSH, p.URG = tcp.SYN, tcp.ACK, tcp.FIN, tcp.RST, tcp.PSH, tcp.URG
	case layers.IPProtocolUDP:
		var udp layers.UDP
		if err := udp.DecodeFromBytes(payload, f); err != nil {
			return p, malformed(err)
		}
		p.Protocol, p.SrcPort, p.DstPort = "UDP", uint16(udp.SrcPort), uint16(udp.DstPort)
	case layers.IPProtocolICMPv4:
		var icmp layers.ICMPv4
		if err := icmp.DecodeFromBytes(payload, f); err != nil {
			return p, malformed(err)
		}
		p.Protocol = "ICMP"
	case layers.IPProtocolICMPv6:
		var icmp layers.ICMPv6
		if err := icmp.DecodeFromBytes(payload, f); err != nil {
			return p, malformed(err)
		}
		p.Protocol = "ICMP"
	default:
		p.Protocol = fmt.Sprintf("IP/%d", protocol)
	}
	p.Truncated = p.Truncated || f.truncated
	return p, nil
}

func decodeLink(data []byte, linkType layers.LinkType, p *model.PacketInfo, f *feedback) ([]byte, gopacket.LayerType, error) {
	var decoder gopacket.DecodingLayer
	switch linkType {
	case layers.LinkTypeEthernet:
		decoder = &layers.Ethernet{}
	case layers.LinkTypeLinuxSLL:
		// gopacket v1.1.19 trusts this length when slicing the fixed 8-byte
		// address field. Reject bad lengths before entering its decoder.
		if len(data) < 16 || binary.BigEndian.Uint16(data[4:6]) > 8 {
			return nil, 0, malformed(errors.New("invalid Linux cooked-capture address length"))
		}
		decoder = &layers.LinuxSLL{}
	case layers.LinkTypeNull, layers.LinkTypeLoop:
		decoder = &layers.Loopback{}
	case layers.LinkTypeRaw, layers.LinkTypeIPv4, layers.LinkTypeIPv6:
		if len(data) == 0 {
			return nil, 0, malformed(errors.New("empty IP packet"))
		}
		if data[0]>>4 == 4 {
			return data, layers.LayerTypeIPv4, nil
		}
		if data[0]>>4 == 6 {
			return data, layers.LayerTypeIPv6, nil
		}
		return nil, 0, malformed(errors.New("invalid IP version"))
	default:
		return nil, 0, ErrUnsupported
	}
	if err := decoder.DecodeFromBytes(data, f); err != nil {
		return nil, 0, malformed(err)
	}
	if eth, ok := decoder.(*layers.Ethernet); ok {
		p.SrcMAC, p.DstMAC = eth.SrcMAC.String(), eth.DstMAC.String()
	}
	payload, next := decoder.LayerPayload(), decoder.NextLayerType()
	for depth := 0; next == layers.LayerTypeDot1Q; depth++ {
		if depth >= 4 {
			return nil, 0, malformed(errors.New("too many VLAN tags"))
		}
		var tag layers.Dot1Q
		if err := tag.DecodeFromBytes(payload, f); err != nil {
			return nil, 0, malformed(err)
		}
		payload, next = tag.Payload, tag.NextLayerType()
	}
	return payload, next, nil
}

func malformed(err error) error { return fmt.Errorf("%w: %v", ErrMalformed, err) }
