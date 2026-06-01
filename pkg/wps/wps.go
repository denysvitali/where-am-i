// Package wps is the public client for Apple's Wi-Fi Positioning System (WPS).
//
// Given a set of Wi-Fi BSSIDs (optionally with RSSI), it resolves each access
// point's known location via Apple's WPS endpoint and can triangulate a single
// position estimate. It is the importable surface over where-am-i's internals;
// the CLI in cmd/where-am-i is a thin wrapper over this same package.
//
// Example:
//
//	c := wps.New(wps.WithEndpoint(wps.EndpointGrapheneOS))
//	aps, err := c.Lookup(ctx, []string{"aa:bb:cc:dd:ee:ff"})
//
// The types exposed here are plain structs; the wire protocol (protobuf) and
// triangulation internals are intentionally hidden so they can evolve without
// breaking callers.
package wps

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/denysvitali/where-am-i/internal/applewps"
	"github.com/denysvitali/where-am-i/internal/types"
)

// Apple WPS endpoints.
const (
	// EndpointApple queries Apple's WPS servers directly.
	EndpointApple = "https://gs-loc.apple.com/clls/wloc"
	// EndpointGrapheneOS routes through the GrapheneOS privacy proxy, which
	// speaks the same protocol but prevents Apple from seeing the caller's IP.
	EndpointGrapheneOS = "https://gs-loc.apple.grapheneos.org/clls/wloc"
)

// ErrNoResults is returned when Apple resolves none of the requested BSSIDs
// (or, for Locate, when no position could be triangulated). It is distinct from
// a transport error so callers can tell "unknown access points" apart from a
// network failure.
var ErrNoResults = errors.New("wps: no access points resolved")

// AccessPoint is the resolved location of a single Wi-Fi access point.
type AccessPoint struct {
	BSSID          string
	Latitude       float64
	Longitude      float64
	AccuracyMeters int32
	AltitudeMeters *int32 // nil when Apple does not report an altitude
}

// Observation is a scanned access point with optional signal strength in dBm.
type Observation struct {
	BSSID string
	RSSI  *int32
}

// Position is a triangulated location estimate derived from multiple resolved
// access points and their RSSI.
type Position struct {
	Latitude         float64
	Longitude        float64
	AccuracyMeters   float64
	ConfidenceScore  float64 // 0..1
	UsedAccessPoints int
}

// Client queries Apple's Wi-Fi Positioning System.
type Client struct {
	inner *applewps.Client
}

type options struct {
	cfg    *types.Config
	logger *logrus.Logger
}

// Option configures a Client.
type Option func(*options)

// WithEndpoint sets the WPS endpoint URL (e.g. EndpointApple or
// EndpointGrapheneOS). An empty string is ignored.
func WithEndpoint(url string) Option {
	return func(o *options) {
		if url != "" {
			o.cfg.Server.URL = url
		}
	}
}

// WithUserAgent overrides the User-Agent sent to Apple. Empty is ignored.
func WithUserAgent(ua string) Option {
	return func(o *options) {
		if ua != "" {
			o.cfg.Request.UserAgent = ua
		}
	}
}

// WithTimeout sets the overall request timeout (split across connect and read).
// Non-positive values are ignored.
func WithTimeout(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			ms := int(d.Milliseconds())
			o.cfg.Server.ConnectTimeout = ms / 2
			o.cfg.Server.ReadTimeout = ms - ms/2
		}
	}
}

// WithModernTLS requires TLS 1.3 when enabled.
func WithModernTLS(enabled bool) Option {
	return func(o *options) { o.cfg.Server.EnforceModernTLS = enabled }
}

// WithMaxRequestNetworks caps how many BSSIDs are sent per request. Non-positive
// values are ignored.
func WithMaxRequestNetworks(n int) Option {
	return func(o *options) {
		if n > 0 {
			o.cfg.Request.MaxRequestNetworks = n
		}
	}
}

// WithMinRSSI sets the minimum RSSI (dBm) an observation must meet to be
// included by Locate.
func WithMinRSSI(dbm int32) Option {
	return func(o *options) { o.cfg.Request.MinRSSI = dbm }
}

// WithLogger attaches a logrus logger. By default logs are discarded.
func WithLogger(l *logrus.Logger) Option {
	return func(o *options) {
		if l != nil {
			o.logger = l
		}
	}
}

// New creates a Client. With no options it queries Apple directly and discards
// logs.
func New(opts ...Option) *Client {
	o := &options{
		cfg:    types.DefaultConfig(),
		logger: discardLogger(),
	}
	for _, opt := range opts {
		opt(o)
	}
	return &Client{inner: applewps.NewClient(o.cfg, o.logger)}
}

// Lookup resolves the known location of each BSSID. BSSIDs Apple does not
// recognize are omitted from the result. Returns ErrNoResults if none resolve.
func (c *Client) Lookup(ctx context.Context, bssids []string) ([]AccessPoint, error) {
	data, err := c.inner.FetchNearbyApPositioningData(ctx, bssids)
	if err != nil {
		return nil, err
	}
	aps := toAccessPoints(data)
	if len(aps) == 0 {
		return nil, ErrNoResults
	}
	return aps, nil
}

// Locate resolves the observed access points and triangulates a single
// position estimate using their RSSI. It returns the estimate, the resolved
// access points that backed it, and ErrNoResults if no position could be
// produced (e.g. too few APs resolved).
func (c *Client) Locate(ctx context.Context, obs []Observation) (Position, []AccessPoint, error) {
	inputs := make([]types.WifiInput, 0, len(obs))
	for _, o := range obs {
		inputs = append(inputs, types.WifiInput{BSSID: o.BSSID, RSSI: o.RSSI})
	}

	data, tri, err := c.inner.FetchPositioningDataWithRSSI(ctx, inputs)
	if err != nil {
		return Position{}, nil, err
	}

	aps := toAccessPoints(data)
	if tri == nil {
		return Position{}, aps, ErrNoResults
	}

	return Position{
		Latitude:         tri.Position.Lat,
		Longitude:        tri.Position.Lon,
		AccuracyMeters:   tri.EstimatedAccuracy,
		ConfidenceScore:  tri.ConfidenceScore,
		UsedAccessPoints: tri.UsedAccessPoints,
	}, aps, nil
}

// ParseObservations parses CLI-style inputs ("aa:bb:cc:dd:ee:ff" or
// "aa:bb:cc:dd:ee:ff:-65") into Observations.
func ParseObservations(inputs []string) ([]Observation, error) {
	parsed, err := applewps.ParseWifiInputs(inputs)
	if err != nil {
		return nil, err
	}
	obs := make([]Observation, 0, len(parsed))
	for _, p := range parsed {
		obs = append(obs, Observation{BSSID: p.BSSID, RSSI: p.RSSI})
	}
	return obs, nil
}

func toAccessPoints(data []types.WifiApPositioningData) []AccessPoint {
	aps := make([]AccessPoint, 0, len(data))
	for _, d := range data {
		if d.PositioningData == nil {
			continue
		}
		aps = append(aps, AccessPoint{
			BSSID:          d.BSSID,
			Latitude:       d.PositioningData.Latitude,
			Longitude:      d.PositioningData.Longitude,
			AccuracyMeters: d.PositioningData.Accuracy,
			AltitudeMeters: d.PositioningData.AltitudeMeters,
		})
	}
	return aps
}

func discardLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}
