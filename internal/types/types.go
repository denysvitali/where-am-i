package types

import "time"

// PositioningData represents the positioning information for a WiFi access point
type PositioningData struct {
	Latitude               float64 `json:"latitude"`
	Longitude              float64 `json:"longitude"`
	Accuracy               int32   `json:"accuracy"`                 // in meters
	AltitudeMeters         *int32  `json:"altitude_meters"`          // nullable
	VerticalAccuracyMeters *int32  `json:"vertical_accuracy_meters"` // nullable
}

// WifiApPositioningData represents positioning data for a specific WiFi access point
type WifiApPositioningData struct {
	BSSID           string           `json:"bssid"`
	RSSI            *int32           `json:"rssi,omitempty"`   // Signal strength in dBm (optional)
	PositioningData *PositioningData `json:"positioning_data"` // nullable if not found
}

// WifiInput represents input WiFi data with optional RSSI
type WifiInput struct {
	BSSID string `json:"bssid"`
	RSSI  *int32 `json:"rssi,omitempty"` // Signal strength in dBm (optional)
}

// Config represents the application configuration
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Throttle ThrottleConfig `mapstructure:"throttle"`
	Request  RequestConfig  `mapstructure:"request"`
}

// ServerConfig represents server configuration
type ServerConfig struct {
	URL              string `mapstructure:"url"`
	ConnectTimeout   int    `mapstructure:"connect_timeout"`
	ReadTimeout      int    `mapstructure:"read_timeout"`
	EnforceModernTLS bool   `mapstructure:"enforce_modern_tls"`
}

// ThrottleConfig represents throttling configuration
type ThrottleConfig struct {
	Cooldown                   time.Duration `mapstructure:"cooldown"`
	TriggerResultCount         int           `mapstructure:"trigger_result_count"`
	ThrottledAdditionalResults int           `mapstructure:"throttled_additional_results"`
	MaxAdditionalResults       int           `mapstructure:"max_additional_results"`
}

// RequestConfig represents request configuration
type RequestConfig struct {
	MaxRequestNetworks int    `mapstructure:"max_request_networks"`
	MinRSSI            int32  `mapstructure:"min_rssi"` // Minimum RSSI to include AP (default: -90 dBm)
	UserAgent          string `mapstructure:"user_agent"`
	Locale             string `mapstructure:"locale"`
	Identifier         string `mapstructure:"identifier"`
	Version            string `mapstructure:"version"`
	SoftwareBuild      string `mapstructure:"software_build"`
	ProductID          string `mapstructure:"product_id"`
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			URL:              "https://gs-loc.apple.com/clls/wloc",
			ConnectTimeout:   10000, // 10 seconds
			ReadTimeout:      10000, // 10 seconds
			EnforceModernTLS: false,
		},
		Throttle: ThrottleConfig{
			Cooldown:                   10 * time.Second,
			TriggerResultCount:         17,
			ThrottledAdditionalResults: 8,
			MaxAdditionalResults:       100,
		},
		Request: RequestConfig{
			MaxRequestNetworks: 40,
			MinRSSI:            -90, // -90 dBm default threshold
			UserAgent:          "locationd/2960.0.57 CFNetwork/3826.500.111.1.1 Darwin/24.4.0",
			Locale:             "en-US_US",
			Identifier:         "com.apple.locationd",
			Version:            "15.4.24E248",
			SoftwareBuild:      "macOS15.4/24E248",
			ProductID:          "arm64",
		},
	}
}
