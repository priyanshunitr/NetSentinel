package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket/pcapgo"
)

// Replay reads classic .pcap files for reproducible, permitted offline analysis.
// It waits for queue space instead of simulating live packet loss.
type Replay struct {
	file   *os.File
	reader *pcapgo.Reader
}

func OpenReplay(path string) (*Replay, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	reader, err := pcapgo.NewReader(file)
	if err != nil {
		closeErr := file.Close()
		return nil, errors.Join(fmt.Errorf("read pcap header: %w", err), closeErr)
	}
	// Keep the live per-packet allocation bound even for a file declaring a
	// much larger snapshot length. Oversized records return a reader error.
	reader.SetSnaplen(65535)
	return &Replay{file: file, reader: reader}, nil
}

func (r *Replay) Close() error { return r.file.Close() }

func (r *Replay) Run(ctx context.Context, output chan<- Packet, counters *Counters) error {
	defer close(output)
	for {
		if ctx.Err() != nil {
			return nil
		}
		data, info, err := r.reader.ReadPacketData()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read pcap packet: %w", err)
		}
		counters.Received.Add(1)
		select {
		case <-ctx.Done():
			return nil
		case output <- Packet{Data: data, Info: info, LinkType: r.reader.LinkType(), ObservedAt: info.Timestamp}:
		}
	}
}
