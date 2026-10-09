package model

import "time"

type Flow struct {
	ID          string    `json:"id"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip"`
	SrcPort     uint16    `json:"src_port"`
	DstPort     uint16    `json:"dst_port"`
	Protocol    string    `json:"protocol"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	PacketCount uint64    `json:"packet_count"`
	ByteCount   uint64    `json:"byte_count"`
	SynCount    uint64    `json:"syn_count"`
	AckCount    uint64    `json:"ack_count"`
	FinCount    uint64    `json:"fin_count"`
	RstCount    uint64    `json:"rst_count"`
}
