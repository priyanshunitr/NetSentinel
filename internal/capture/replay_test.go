package capture

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"netsentinel/internal/testutil"
)

func fixture(t *testing.T, count int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.pcap")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	data := testutil.TCP(t, "192.0.2.1", "198.51.100.1", 1234, 443, true, false)
	for i := 0; i < count; i++ {
		if err := writer.WritePacket(testutil.Info(data, time.Unix(1000+int64(i), 0)), data); err != nil {
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReplayEOFAndMetadata(t *testing.T) {
	r, err := OpenReplay(fixture(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	output := make(chan Packet, 2)
	counters := &Counters{}
	if err := r.Run(context.Background(), output, counters); err != nil {
		t.Fatal(err)
	}
	var packets []Packet
	for p := range output {
		packets = append(packets, p)
	}
	if len(packets) != 2 || counters.Received.Load() != 2 || !packets[1].ObservedAt.Equal(time.Unix(1001, 0)) || packets[0].LinkType != layers.LinkTypeEthernet {
		t.Fatal("bad replay output")
	}
}

func TestReplayCancellationWithFullQueue(t *testing.T) {
	r, err := OpenReplay(fixture(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := make(chan Packet)
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, output, &Counters{}) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("replay did not cancel")
	}
	if _, ok := <-output; ok {
		t.Fatal("output channel not closed")
	}
}

func TestReplayRejectsInvalidAndOversizedRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.pcap")
	if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReplay(path); err == nil {
		t.Fatal("invalid pcap accepted")
	}
	valid := fixture(t, 1)
	data, err := os.ReadFile(valid)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(data[24+8:24+12], 65536)
	binary.LittleEndian.PutUint32(data[24+12:24+16], 65536)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReplay(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := r.Run(context.Background(), make(chan Packet, 1), &Counters{}); err == nil {
		t.Fatal("oversized record accepted")
	}
}
