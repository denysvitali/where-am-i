package wifi

import (
	"context"
	"fmt"
	"time"

	"github.com/mdlayher/wifi"
	"github.com/sirupsen/logrus"

	"github.com/denysvitali/where-am-i/internal/types"
)

// Scanner handles WiFi network scanning operations using the nl80211/netlink interface
type Scanner struct {
	client *wifi.Client
	log    *logrus.Logger
}

// NewScanner creates a new WiFi scanner instance
func NewScanner(logger *logrus.Logger) (*Scanner, error) {
	client, err := wifi.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create WiFi client: %w", err)
	}

	return &Scanner{
		client: client,
		log:    logger,
	}, nil
}

// Close closes the WiFi scanner and cleans up resources
func (s *Scanner) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

// ScanNetworks scans for nearby WiFi networks and returns them as WifiInput
func (s *Scanner) ScanNetworks() ([]types.WifiInput, error) {
	return s.ScanWithContext(context.Background())
}

// ScanWithContext scans for nearby WiFi networks with a context for cancellation
func (s *Scanner) ScanWithContext(ctx context.Context) ([]types.WifiInput, error) {
	s.log.Debug("Starting WiFi network scan using nl80211")

	// Get available WiFi interfaces
	interfaces, err := s.client.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get WiFi interfaces: %w", err)
	}

	if len(interfaces) == 0 {
		return nil, fmt.Errorf("no WiFi interfaces found")
	}

	s.log.WithField("interfaces", len(interfaces)).Debug("Found WiFi interfaces")

	var allWifiInputs []types.WifiInput

	// Scan on all available interfaces
	for _, ifi := range interfaces {
		s.log.WithField("interface", ifi.Name).Debug("Scanning WiFi interface")

		// Create a context with timeout for the scan operation
		scanCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		// Trigger a scan
		if err := s.client.Scan(scanCtx, ifi); err != nil {
			s.log.WithError(err).WithField("interface", ifi.Name).Warn("Failed to scan interface, skipping")
			continue
		}

		// Give the scan a moment to complete
		select {
		case <-time.After(2 * time.Second):
			// Continue to get results
		case <-scanCtx.Done():
			s.log.WithField("interface", ifi.Name).Warn("Scan timeout, trying to get partial results")
		}

		// Get access points discovered by the scan
		bssList, err := s.client.AccessPoints(ifi)
		if err != nil {
			s.log.WithError(err).WithField("interface", ifi.Name).Warn("Failed to get access points from interface")
			continue
		}

		s.log.WithFields(logrus.Fields{
			"interface":      ifi.Name,
			"access_points": len(bssList),
		}).Debug("Retrieved access points")

		// Convert WiFi BSS results to our internal types
		for _, bss := range bssList {
			// Convert hardware address to string format
			bssid := bss.BSSID.String()

			// Note: mdlayher/wifi library doesn't provide signal strength (RSSI) 
			// for scanned access points. This is a limitation of the current implementation.
			// Apple's WiFi positioning service can work with just BSSID information,
			// though RSSI values would improve accuracy.

			// Only include access points with valid BSSID
			if bssid != "" && bssid != "00:00:00:00:00:00" {
				wifiInput := types.WifiInput{
					BSSID: bssid,
					RSSI:  nil, // Signal strength not available from scan results
				}

				allWifiInputs = append(allWifiInputs, wifiInput)

				s.log.WithFields(logrus.Fields{
					"bssid": bssid,
					"ssid":  bss.SSID,
				}).Debug("Found WiFi network")
			}
		}
	}

	if len(allWifiInputs) == 0 {
		return nil, fmt.Errorf("no access points found in scan results")
	}

	s.log.WithField("networks_found", len(allWifiInputs)).Info("WiFi scan completed")
	return allWifiInputs, nil
}

// ScanAndFormat scans networks and formats them for command-line display
func (s *Scanner) ScanAndFormat() ([]string, error) {
	wifiInputs, err := s.ScanNetworks()
	if err != nil {
		return nil, err
	}

	var formattedInputs []string
	for _, input := range wifiInputs {
		if input.RSSI != nil {
			// Format as BSSID:RSSI
			formatted := fmt.Sprintf("%s:%d", input.BSSID, *input.RSSI)
			formattedInputs = append(formattedInputs, formatted)
		} else {
			// Format as BSSID only (no RSSI available from nl80211 scan)
			formattedInputs = append(formattedInputs, input.BSSID)
		}
	}

	if len(formattedInputs) == 0 {
		return nil, fmt.Errorf("no WiFi networks found to format")
	}

	return formattedInputs, nil
}

// FilterByRSSI filters WiFi networks by minimum RSSI threshold
func (s *Scanner) FilterByRSSI(wifiInputs []types.WifiInput, minRSSI int32) []types.WifiInput {
	var filtered []types.WifiInput

	for _, input := range wifiInputs {
		if input.RSSI != nil && *input.RSSI >= minRSSI {
			filtered = append(filtered, input)
		} else if input.RSSI == nil {
			// Include networks without RSSI data
			filtered = append(filtered, input)
		} else {
			s.log.WithFields(logrus.Fields{
				"bssid":    input.BSSID,
				"rssi":     *input.RSSI,
				"min_rssi": minRSSI,
			}).Debug("Filtering out weak signal")
		}
	}

	s.log.WithFields(logrus.Fields{
		"original_count": len(wifiInputs),
		"filtered_count": len(filtered),
		"min_rssi":       minRSSI,
	}).Info("Filtered WiFi networks by RSSI")

	return filtered
}

// ScanWithOptions scans WiFi networks with filtering options
func (s *Scanner) ScanWithOptions(minRSSI int32, maxNetworks int) ([]types.WifiInput, error) {
	// Scan for networks
	wifiInputs, err := s.ScanNetworks()
	if err != nil {
		return nil, err
	}

	// Filter by RSSI if specified
	if minRSSI > -100 {
		wifiInputs = s.FilterByRSSI(wifiInputs, minRSSI)
	}

	// Limit the number of networks if specified
	if maxNetworks > 0 && len(wifiInputs) > maxNetworks {
		s.log.WithFields(logrus.Fields{
			"total_networks": len(wifiInputs),
			"max_networks":   maxNetworks,
		}).Info("Limiting number of networks")
		wifiInputs = wifiInputs[:maxNetworks]
	}

	return wifiInputs, nil
}

// ValidateInterface checks if WiFi interfaces are available
func (s *Scanner) ValidateInterface() error {
	interfaces, err := s.client.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to get WiFi interfaces: %w", err)
	}

	if len(interfaces) == 0 {
		return fmt.Errorf("no WiFi interfaces available")
	}

	s.log.WithField("interfaces", len(interfaces)).Info("WiFi interfaces validated")
	for _, ifi := range interfaces {
		s.log.WithFields(logrus.Fields{
			"name": ifi.Name,
			"type": ifi.Type.String(),
		}).Debug("Available WiFi interface")
	}

	return nil
}
