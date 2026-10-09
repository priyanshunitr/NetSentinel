package model

import "time"

type Alert struct {
	ID            string    `json:"id"`
	Type          string    `json:"type"`
	Severity      string    `json:"severity"`
	SourceIP      string    `json:"source_ip"`
	DestinationIP string    `json:"destination_ip,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
	Description   string    `json:"description"`
	PortCount     int       `json:"port_count,omitempty"`
	PacketCount   uint64    `json:"packet_count,omitempty"`
	ByteCount     uint64    `json:"byte_count,omitempty"`
}
