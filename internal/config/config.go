package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Host                        string
	Port                        int
	Interface                   string
	CaptureFilter               string
	Promiscuous                 bool
	ChannelSize                 int
	MaxPackets                  int
	MaxAlerts                   int
	MaxFlows                    int
	MaxDetectorEntries          int
	FlowIdleTimeout             time.Duration
	PortScanThreshold           int
	PortScanWindow              time.Duration
	SYNFloodThreshold           int
	SYNFloodWindow              time.Duration
	TrafficSpikePacketThreshold int
	TrafficSpikeByteThreshold   int
	TrafficWindow               time.Duration
}

func Default() Config {
	return Config{
		Host: "127.0.0.1", Port: 8080, ChannelSize: 512,
		MaxPackets: 1000, MaxAlerts: 500, MaxFlows: 10000,
		MaxDetectorEntries: 2048,
		FlowIdleTimeout:    60 * time.Second,
		PortScanThreshold:  20, PortScanWindow: 10 * time.Second,
		SYNFloodThreshold: 100, SYNFloodWindow: 10 * time.Second,
		TrafficSpikePacketThreshold: 1000, TrafficSpikeByteThreshold: 10_000_000,
		TrafficWindow: 10 * time.Second,
	}
}

func Load() (Config, error) {
	c := Default()
	if value, ok := os.LookupEnv("HOST"); ok {
		c.Host = value
	}
	c.Interface = os.Getenv("INTERFACE")
	c.CaptureFilter = os.Getenv("CAPTURE_FILTER")
	settings := []struct {
		name string
		dst  *int
		max  int
	}{
		{"PORT", &c.Port, 65535}, {"CHANNEL_SIZE", &c.ChannelSize, 65536},
		{"MAX_PACKETS", &c.MaxPackets, 100000}, {"MAX_ALERTS", &c.MaxAlerts, 100000},
		{"MAX_FLOWS", &c.MaxFlows, 100000}, {"MAX_DETECTOR_ENTRIES", &c.MaxDetectorEntries, 10000},
		{"PORT_SCAN_THRESHOLD", &c.PortScanThreshold, 65535},
		{"SYN_FLOOD_THRESHOLD", &c.SYNFloodThreshold, 1_000_000_000},
		{"TRAFFIC_SPIKE_PACKET_THRESHOLD", &c.TrafficSpikePacketThreshold, 1_000_000_000},
		{"TRAFFIC_SPIKE_BYTE_THRESHOLD", &c.TrafficSpikeByteThreshold, 1_000_000_000},
	}
	for _, setting := range settings {
		if raw, ok := os.LookupEnv(setting.name); ok {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > setting.max {
				return c, fmt.Errorf("%s must be an integer in [1, %d]", setting.name, setting.max)
			}
			*setting.dst = n
		}
	}
	for _, setting := range []struct {
		name string
		dst  *time.Duration
	}{
		{"FLOW_IDLE_TIMEOUT_SECONDS", &c.FlowIdleTimeout},
		{"PORT_SCAN_WINDOW_SECONDS", &c.PortScanWindow},
		{"SYN_FLOOD_WINDOW_SECONDS", &c.SYNFloodWindow},
		{"TRAFFIC_WINDOW_SECONDS", &c.TrafficWindow},
	} {
		if raw, ok := os.LookupEnv(setting.name); ok {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > 3600 {
				return c, fmt.Errorf("%s must be an integer in [1, 3600]", setting.name)
			}
			*setting.dst = time.Duration(n) * time.Second
		}
	}
	if raw, ok := os.LookupEnv("PROMISCUOUS"); ok {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return c, fmt.Errorf("PROMISCUOUS: %w", err)
		}
		c.Promiscuous = value
	}
	if net.ParseIP(c.Host) == nil {
		return c, fmt.Errorf("HOST must be an IP address")
	}
	return c, nil
}

func (c Config) Address() string { return net.JoinHostPort(c.Host, strconv.Itoa(c.Port)) }
