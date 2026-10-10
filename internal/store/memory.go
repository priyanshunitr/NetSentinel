package store

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"netsentinel/internal/config"
	"netsentinel/internal/flow"
	"netsentinel/internal/model"
)

type PacketFilter struct {
	Protocol, SrcIP string
	Port            *uint16
}

func (f PacketFilter) Match(p model.PacketInfo) bool {
	return (f.Protocol == "" || strings.EqualFold(f.Protocol, p.Protocol)) &&
		(f.SrcIP == "" || f.SrcIP == p.SrcIP) &&
		(f.Port == nil || ((p.Protocol == "TCP" || p.Protocol == "UDP") && (p.SrcPort == *f.Port || p.DstPort == *f.Port)))
}

type TopEntry struct {
	Value string `json:"value"`
	Count uint64 `json:"count"`
}

type Stats struct {
	StartedAt           time.Time  `json:"started_at"`
	TotalPackets        uint64     `json:"total_packets"`
	TotalBytes          uint64     `json:"total_bytes"`
	TCPPackets          uint64     `json:"tcp_packets"`
	UDPPackets          uint64     `json:"udp_packets"`
	ICMPPackets         uint64     `json:"icmp_packets"`
	OtherPackets        uint64     `json:"other_packets"`
	ActiveFlows         int        `json:"active_flows"`
	FlowsEvicted        uint64     `json:"flows_evicted"`
	AlertsGenerated     uint64     `json:"alerts_generated"`
	RetainedPackets     int        `json:"retained_packets"`
	RetainedAlerts      int        `json:"retained_alerts"`
	MalformedPackets    uint64     `json:"malformed_packets"`
	UnsupportedPackets  uint64     `json:"unsupported_packets"`
	DetectorEvictions   uint64     `json:"detector_evictions"`
	TopScope            string     `json:"top_scope"`
	TopSourceIPs        []TopEntry `json:"top_source_ips"`
	TopDestinationIPs   []TopEntry `json:"top_destination_ips"`
	TopDestinationPorts []TopEntry `json:"top_destination_ports"`
}

// Memory has one RWMutex for all API-visible state. The processor is the only
// writer; HTTP handlers copy bounded snapshots under RLock and encode afterward.
type Memory struct {
	mu      sync.RWMutex
	packets ring[model.PacketInfo]
	alerts  ring[model.Alert]
	flows   *flow.Tracker
	stats   Stats
}

func New(c config.Config) *Memory {
	return &Memory{packets: newRing[model.PacketInfo](c.MaxPackets), alerts: newRing[model.Alert](c.MaxAlerts), flows: flow.New(c.MaxFlows, c.FlowIdleTimeout), stats: Stats{StartedAt: time.Now().UTC()}}
}

func (s *Memory) AddPacket(p model.PacketInfo, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows.Expire(now)
	s.flows.Observe(p, now)
	s.packets.add(p)
	s.stats.TotalPackets++
	if p.PacketSize > 0 {
		s.stats.TotalBytes += uint64(p.PacketSize)
	}
	switch p.Protocol {
	case "TCP":
		s.stats.TCPPackets++
	case "UDP":
		s.stats.UDPPackets++
	case "ICMP":
		s.stats.ICMPPackets++
	default:
		s.stats.OtherPackets++
	}
}

func (s *Memory) AddAlerts(alerts []model.Alert) {
	if len(alerts) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, alert := range alerts {
		s.stats.AlertsGenerated++
		alert.ID = "alert-" + strconv.FormatUint(s.stats.AlertsGenerated, 10)
		s.alerts.add(alert)
	}
}

func (s *Memory) RecordParseError(malformed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if malformed {
		s.stats.MalformedPackets++
	} else {
		s.stats.UnsupportedPackets++
	}
}

func (s *Memory) Expire(now time.Time) { s.mu.Lock(); defer s.mu.Unlock(); s.flows.Expire(now) }

func (s *Memory) SetDetectorEvictions(count uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.DetectorEvictions = count
}

func (s *Memory) Packets(filter PacketFilter, limit int) []model.PacketInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.packets.recent(limit, filter.Match)
}

func (s *Memory) Alerts(limit int) []model.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.alerts.recent(limit, nil)
}

func (s *Memory) Flows(limit int) []model.Flow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.flows.Recent(limit)
}

func (s *Memory) Flow(id string) (model.Flow, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.flows.Get(id)
}

func (s *Memory) Stats() Stats {
	s.mu.RLock()
	stats := s.stats
	stats.ActiveFlows, stats.FlowsEvicted = s.flows.Len(), s.flows.Evicted()
	stats.RetainedPackets, stats.RetainedAlerts = s.packets.count, s.alerts.count
	packets := s.packets.recent(s.packets.count, nil)
	s.mu.RUnlock()
	sources, destinations, ports := map[string]uint64{}, map[string]uint64{}, map[string]uint64{}
	for _, p := range packets {
		sources[p.SrcIP]++
		destinations[p.DstIP]++
		if p.Protocol == "TCP" || p.Protocol == "UDP" {
			ports[strconv.Itoa(int(p.DstPort))]++
		}
	}
	stats.TopScope = "recent_packets"
	stats.TopSourceIPs, stats.TopDestinationIPs, stats.TopDestinationPorts = top(sources), top(destinations), top(ports)
	return stats
}

func top(counts map[string]uint64) []TopEntry {
	result := make([]TopEntry, 0, len(counts))
	for value, count := range counts {
		result = append(result, TopEntry{value, count})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count == result[j].Count {
			return result[i].Value < result[j].Value
		}
		return result[i].Count > result[j].Count
	})
	return result[:min(10, len(result))]
}
