// Package testutil constructs synthetic packets for tests. It never transmits.
package testutil

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TCP(t testing.TB, source, destination string, sourcePort, destinationPort uint16, syn, ack bool) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: net.ParseIP(source).To4(), DstIP: net.ParseIP(destination).To4(), Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sourcePort), DstPort: layers.TCPPort(destinationPort), SYN: syn, ACK: ack, Window: 1024}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	return Serialize(t, eth, ip, tcp)
}

func Serialize(t testing.TB, values ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, values...); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buffer.Bytes()...)
}

func Info(data []byte, timestamp time.Time) gopacket.CaptureInfo {
	return gopacket.CaptureInfo{Timestamp: timestamp, CaptureLength: len(data), Length: len(data)}
}
