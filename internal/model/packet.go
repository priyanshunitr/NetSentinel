package model

import "time"

// PacketInfo contains metadata only; application payloads never enter the store.
type PacketInfo struct {
	Timestamp  time.Time `json:"timestamp"`
	SrcMAC     string    `json:"src_mac,omitempty"`
	DstMAC     string    `json:"dst_mac,omitempty"`
	SrcIP      string    `json:"src_ip"`
	DstIP      string    `json:"dst_ip"`
	SrcPort    uint16    `json:"src_port"`
	DstPort    uint16    `json:"dst_port"`
	Protocol   string    `json:"protocol"`
	PacketSize int       `json:"packet_size"`
	Truncated  bool      `json:"truncated"`
	Fragmented bool      `json:"fragmented"`
	SYN        bool      `json:"syn"`
	ACK        bool      `json:"ack"`
	FIN        bool      `json:"fin"`
	RST        bool      `json:"rst"`
	PSH        bool      `json:"psh"`
	URG        bool      `json:"urg"`
}
