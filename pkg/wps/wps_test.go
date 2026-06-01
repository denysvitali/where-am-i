package wps

import (
	"testing"
	"time"

	"github.com/denysvitali/where-am-i/internal/types"
)

func TestNewAppliesOptions(t *testing.T) {
	c := New(
		WithEndpoint(EndpointGrapheneOS),
		WithUserAgent("custom/1.0"),
		WithTimeout(4*time.Second),
		WithMaxRequestNetworks(7),
		WithMinRSSI(-80),
		WithModernTLS(true),
	)
	if c == nil || c.inner == nil {
		t.Fatal("New returned a client without an inner WPS client")
	}
}

func TestWithEndpointEmptyKeepsDefault(t *testing.T) {
	o := &options{cfg: types.DefaultConfig()}
	WithEndpoint("")(o)
	if o.cfg.Server.URL != types.DefaultConfig().Server.URL {
		t.Fatalf("empty endpoint should keep default, got %q", o.cfg.Server.URL)
	}
}

func TestParseObservations(t *testing.T) {
	obs, err := ParseObservations([]string{"aa:bb:cc:dd:ee:ff:-65", "11:22:33:44:55:66"})
	if err != nil {
		t.Fatalf("ParseObservations: %v", err)
	}
	if len(obs) != 2 {
		t.Fatalf("want 2 observations, got %d", len(obs))
	}
	if obs[0].RSSI == nil || *obs[0].RSSI != -65 {
		t.Fatalf("want RSSI -65, got %v", obs[0].RSSI)
	}
	if obs[1].RSSI != nil {
		t.Fatalf("want nil RSSI for BSSID without signal, got %v", *obs[1].RSSI)
	}
}

func TestToAccessPointsSkipsUnresolved(t *testing.T) {
	alt := int32(412)
	in := []types.WifiApPositioningData{
		{BSSID: "aa:bb:cc:dd:ee:ff", PositioningData: &types.PositioningData{
			Latitude: 47.37, Longitude: 8.54, Accuracy: 30, AltitudeMeters: &alt,
		}},
		{BSSID: "11:22:33:44:55:66", PositioningData: nil}, // not found → skipped
	}
	got := toAccessPoints(in)
	if len(got) != 1 {
		t.Fatalf("want 1 resolved AP, got %d", len(got))
	}
	ap := got[0]
	if ap.BSSID != "aa:bb:cc:dd:ee:ff" || ap.Latitude != 47.37 || ap.AccuracyMeters != 30 {
		t.Fatalf("unexpected mapping: %+v", ap)
	}
	if ap.AltitudeMeters == nil || *ap.AltitudeMeters != 412 {
		t.Fatalf("altitude not mapped: %v", ap.AltitudeMeters)
	}
}

func TestEndpointConstants(t *testing.T) {
	if EndpointApple == "" || EndpointGrapheneOS == "" {
		t.Fatal("endpoint constants must be set")
	}
}
