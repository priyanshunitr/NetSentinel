package config

import (
	"testing"
	"time"
)

func TestLoadOverrides(t *testing.T) {
	t.Setenv("HOST", "::1")
	t.Setenv("PORT", "9090")
	t.Setenv("INTERFACE", "eth0")
	t.Setenv("PROMISCUOUS", "true")
	t.Setenv("PORT_SCAN_WINDOW_SECONDS", "15")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Address() != "[::1]:9090" || c.Interface != "eth0" || !c.Promiscuous || c.PortScanWindow != 15*time.Second {
		t.Fatalf("bad config: %+v", c)
	}
}

func TestRejectInvalidEnvironment(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"PORT", "0"}, {"MAX_PACKETS", "-1"}, {"MAX_FLOWS", "100001"},
		{"SYN_FLOOD_THRESHOLD", "nope"}, {"TRAFFIC_WINDOW_SECONDS", "0"},
		{"PORT_SCAN_WINDOW_SECONDS", "3601"}, {"PROMISCUOUS", "sometimes"}, {"HOST", "localhost"},
	} {
		t.Run(tc.name+tc.value, func(t *testing.T) {
			t.Setenv(tc.name, tc.value)
			if _, err := Load(); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}
