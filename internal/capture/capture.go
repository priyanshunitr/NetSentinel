package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Interface struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Addresses   []string `json:"addresses"`
}

func Interfaces() ([]Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("list capture interfaces (install libpcap/Npcap): %w", err)
	}
	result := make([]Interface, 0, len(devices))
	for _, device := range devices {
		item := Interface{Name: device.Name, Description: device.Description, Addresses: []string{}}
		for _, address := range device.Addresses {
			item.Addresses = append(item.Addresses, address.IP.String())
		}
		result = append(result, item)
	}
	return result, nil
}

type Packet struct {
	Data       []byte
	Info       gopacket.CaptureInfo
	LinkType   layers.LinkType
	ObservedAt time.Time
}

type Counters struct {
	Received         atomic.Uint64
	Dropped          atomic.Uint64
	KernelDropped    atomic.Uint64
	InterfaceDropped atomic.Uint64
}

type Source struct{ handle *pcap.Handle }

type Reader interface {
	Run(context.Context, chan<- Packet, *Counters) error
	Close() error
}

func Open(name, filter string, promiscuous bool) (*Source, error) {
	handle, err := pcap.OpenLive(name, 65535, promiscuous, 250*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open interface %q (check capture permissions and libpcap/Npcap): %w", name, err)
	}
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("capture filter: %w", err)
		}
	}
	return &Source{handle: handle}, nil
}

func (s *Source) Close() error { s.handle.Close(); return nil }

// Run owns the handle until it returns. Positive pcap timeouts allow idle
// cancellation. A full queue drops the newest packet, never spawning workers.
func (s *Source) Run(ctx context.Context, output chan<- Packet, counters *Counters) error {
	defer close(output)
	lastStats := time.Now()
	for {
		if ctx.Err() != nil {
			s.updateStats(counters)
			return nil
		}
		data, info, err := s.handle.ReadPacketData()
		if time.Since(lastStats) >= time.Second {
			s.updateStats(counters)
			lastStats = time.Now()
		}
		if errors.Is(err, pcap.NextErrorTimeoutExpired) {
			continue
		}
		if errors.Is(err, io.EOF) {
			s.updateStats(counters)
			return nil
		}
		if err != nil {
			return fmt.Errorf("capture read: %w", err)
		}
		counters.Received.Add(1)
		select {
		case <-ctx.Done():
			return nil
		case output <- Packet{Data: data, Info: info, LinkType: s.handle.LinkType(), ObservedAt: time.Now()}:
		default:
			counters.Dropped.Add(1)
		}
	}
}

func (s *Source) updateStats(counters *Counters) {
	stats, err := s.handle.Stats()
	if err != nil {
		return
	} // Some capture devices do not support pcap statistics.
	counters.KernelDropped.Store(uint64(stats.PacketsDropped))
	counters.InterfaceDropped.Store(uint64(stats.PacketsIfDropped))
}
