package applewps

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	pb "github.com/denysvitali/where-am-i/internal/proto"
	"github.com/denysvitali/where-am-i/internal/triangulation"
	"github.com/denysvitali/where-am-i/internal/types"
)

// Client represents an Apple WPS client
type Client struct {
	config                *types.Config
	httpClient            *http.Client
	throttleTriggeredTime time.Time
	log                   *logrus.Logger
}

// NewClient creates a new Apple WPS client
func NewClient(config *types.Config, logger *logrus.Logger) *Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	if config.Server.EnforceModernTLS {
		transport.TLSClientConfig.MinVersion = tls.VersionTLS13
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Server.ConnectTimeout+config.Server.ReadTimeout) * time.Millisecond,
	}

	return &Client{
		config:     config,
		httpClient: client,
		log:        logger,
	}
}

// FetchNearbyApPositioningData fetches positioning data for nearby access points
func (c *Client) FetchNearbyApPositioningData(bssids []string) ([]types.WifiApPositioningData, error) {
	// Limit request BSSIDs to max allowed
	requestBssids := bssids
	if len(bssids) > c.config.Request.MaxRequestNetworks {
		requestBssids = bssids[:c.config.Request.MaxRequestNetworks]
	}

	// Determine max additional results based on throttling
	maxAdditionalResults := c.config.Throttle.MaxAdditionalResults
	if time.Since(c.throttleTriggeredTime) < c.config.Throttle.Cooldown {
		maxAdditionalResults = c.config.Throttle.ThrottledAdditionalResults
	}

	c.log.WithFields(logrus.Fields{
		"request_bssids": requestBssids,
		"max_additional": maxAdditionalResults,
	}).Debug("Fetching positioning data")

	response, err := c.fetchInner(requestBssids, maxAdditionalResults)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch positioning data: %w", err)
	}

	// Check if throttling should be triggered
	if len(response.WirelessAps) >= c.config.Throttle.TriggerResultCount {
		c.log.WithField("ap_count", len(response.WirelessAps)).Debug("Response AP count triggered throttle")
		c.throttleTriggeredTime = time.Now()
	}

	// Process results
	result := make(map[string]*types.PositioningData)

	for _, ap := range response.WirelessAps {
		normalizedBssid := normalizeBssid(ap.MacId)
		if normalizedBssid == "" {
			c.log.WithField("bssid", ap.MacId).Warn("Invalid BSSID")
			continue
		}

		if _, exists := result[normalizedBssid]; !exists {
			result[normalizedBssid] = convertPositioningData(ap.Location)
		}
	}

	// Ensure all requested BSSIDs are in the result (with nil if not found)
	for _, bssid := range requestBssids {
		if _, exists := result[bssid]; !exists {
			result[bssid] = nil
		}
	}

	// Convert to slice
	var results []types.WifiApPositioningData
	for bssid, data := range result {
		results = append(results, types.WifiApPositioningData{
			BSSID:           bssid,
			PositioningData: data,
		})
	}

	return results, nil
}

func ref[T any](v T) *T {
	return &v
}

// fetchInner performs the actual HTTP request to Apple WPS
func (c *Client) fetchInner(bssids []string, maxAdditionalResults int) (*pb.ALSLocationResponse, error) {
	// Create protobuf request
	wirelessAPs := make([]*pb.WirelessAP, len(bssids))
	for i, bssid := range bssids {
		wirelessAPs[i] = &pb.WirelessAP{
			MacId: bssid,
		}
	}

	request := &pb.ALSLocationRequest{
		WirelessAps:              wirelessAPs,
		NumberOfSurroundingWifis: ref(int32(maxAdditionalResults)),
		SurroundingWifiBands: []pb.ALSLocationRequest_WifiBand{
			pb.ALSLocationRequest_K2DOT4GHZ,
			pb.ALSLocationRequest_K5GHZ,
		},
		WifiAltitudeScale: ref(pb.ALSLocationRequest_KWIFI_ALTITUDE_SCALE_10_TO_THE_2),
		Meta: &pb.ALSLocationRequest_ALSMeta{
			SoftwareBuild: ref(c.config.Request.SoftwareBuild),
			ProductId:     ref(c.config.Request.ProductID),
		},
	}

	protobufData, err := proto.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal protobuf: %w", err)
	}

	// Create HTTP request body
	var buf bytes.Buffer

	// Write header
	if err := binary.Write(&buf, binary.BigEndian, uint16(1)); err != nil {
		return nil, fmt.Errorf("failed to write header: %w", err)
	}

	locale := []byte(c.config.Request.Locale)
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(locale))); err != nil {
		return nil, fmt.Errorf("failed to write locale length: %w", err)
	}
	buf.Write(locale)

	identifier := []byte(c.config.Request.Identifier)
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(identifier))); err != nil {
		return nil, fmt.Errorf("failed to write identifier length: %w", err)
	}
	buf.Write(identifier)

	version := []byte(c.config.Request.Version)
	if err := binary.Write(&buf, binary.BigEndian, uint16(len(version))); err != nil {
		return nil, fmt.Errorf("failed to write version length: %w", err)
	}
	buf.Write(version)

	if err := binary.Write(&buf, binary.BigEndian, uint32(1)); err != nil {
		return nil, fmt.Errorf("failed to write request code: %w", err)
	}
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(protobufData))); err != nil {
		return nil, fmt.Errorf("failed to write protobuf data length: %w", err)
	}
	buf.Write(protobufData)

	// Create HTTP request
	req, err := http.NewRequest("POST", c.config.Server.URL, &buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", c.config.Request.UserAgent)

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			c.log.WithError(closeErr).Warn("Failed to close response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non-200 response code: %d", resp.StatusCode)
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Skip header (10 bytes)
	const ignoredHeaderSize = 10
	if len(body) < ignoredHeaderSize {
		return nil, fmt.Errorf("response too short: %d bytes", len(body))
	}

	protoBytes := body[ignoredHeaderSize:]

	// Parse response
	response := &pb.ALSLocationResponse{}
	if err := proto.Unmarshal(protoBytes, response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	c.log.WithFields(logrus.Fields{
		"ap_count":  len(response.WirelessAps),
		"byte_size": len(body),
	}).Debug("Received response")

	return response, nil
}

// normalizeBssid normalizes a BSSID by adding leading zeros to octets
func normalizeBssid(bssid string) string {
	// Validate BSSID format
	re := regexp.MustCompile(`^([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}$`)
	if !re.MatchString(bssid) {
		return ""
	}

	octets := strings.Split(bssid, ":")
	if len(octets) != 6 {
		return ""
	}

	var normalized strings.Builder
	for i, octet := range octets {
		if i > 0 {
			normalized.WriteByte(':')
		}

		if len(octet) == 1 {
			normalized.WriteByte('0')
		} else if len(octet) != 2 {
			return ""
		}

		normalized.WriteString(strings.ToLower(octet))
	}

	return normalized.String()
}

// convertPositioningData converts protobuf location data to PositioningData
func convertPositioningData(location *pb.ALSLocation) *types.PositioningData {
	if location == nil || location.Latitude == -18000000000 {
		return nil
	}

	latitude := float64(location.Latitude) * 0.00000001
	longitude := float64(location.Longitude) * 0.00000001

	var altitudeMeters *int32
	if location.Altitude != nil && *location.Altitude != -100 && *location.Altitude != -50000 {
		alt := *location.Altitude / 100
		altitudeMeters = &alt
	}

	var verticalAccuracyMeters *int32
	if location.VerticalAccuracy != nil && *location.VerticalAccuracy != -100 && altitudeMeters != nil {
		vertAcc := *location.VerticalAccuracy / 100
		verticalAccuracyMeters = &vertAcc
	}

	return &types.PositioningData{
		Latitude:               latitude,
		Longitude:              longitude,
		Accuracy:               location.Accuracy,
		AltitudeMeters:         altitudeMeters,
		VerticalAccuracyMeters: verticalAccuracyMeters,
	}
}

// FetchPositioningDataWithRSSI fetches positioning data for WiFi access points with RSSI values
// and performs triangulation to estimate location
func (c *Client) FetchPositioningDataWithRSSI(wifiInputs []types.WifiInput) ([]types.WifiApPositioningData, *triangulation.TriangulationResult, error) {
	// Filter out weak signals if RSSI filtering is enabled
	var filteredInputs []types.WifiInput
	for _, input := range wifiInputs {
		if input.RSSI != nil && *input.RSSI < c.config.Request.MinRSSI {
			c.log.WithFields(logrus.Fields{
				"bssid":    input.BSSID,
				"rssi":     *input.RSSI,
				"min_rssi": c.config.Request.MinRSSI,
			}).Debug("Filtering out weak signal")
			continue
		}
		filteredInputs = append(filteredInputs, input)
	}

	if len(filteredInputs) == 0 {
		return nil, nil, fmt.Errorf("no WiFi access points remaining after RSSI filtering")
	}

	// Extract BSSIDs for the existing fetch method
	bssids := make([]string, len(filteredInputs))
	for i, input := range filteredInputs {
		bssids[i] = input.BSSID
	}

	// Fetch positioning data using existing method
	apData, err := c.FetchNearbyApPositioningData(bssids)
	if err != nil {
		return nil, nil, err
	}

	// Merge RSSI information with positioning data
	rssiMap := make(map[string]*int32)
	for _, input := range filteredInputs {
		rssiMap[input.BSSID] = input.RSSI
	}

	for i := range apData {
		if rssi, exists := rssiMap[apData[i].BSSID]; exists {
			apData[i].RSSI = rssi
		}
	}

	// Perform triangulation if we have multiple APs with positioning data
	triangulationResult, err := triangulation.TriangulatePosition(apData)
	if err != nil {
		c.log.WithError(err).Debug("Triangulation failed, returning individual AP data")
		return apData, nil, nil
	}

	c.log.WithFields(logrus.Fields{
		"triangulated_lat": triangulationResult.Position.Lat,
		"triangulated_lon": triangulationResult.Position.Lon,
		"accuracy":         triangulationResult.EstimatedAccuracy,
		"confidence":       triangulationResult.ConfidenceScore,
		"used_aps":         triangulationResult.UsedAccessPoints,
	}).Info("Triangulation successful")

	return apData, triangulationResult, nil
}

// ParseWifiInputs parses WiFi input strings in format "BSSID" or "BSSID:RSSI"
func ParseWifiInputs(inputs []string) ([]types.WifiInput, error) {
	var wifiInputs []types.WifiInput

	for _, input := range inputs {
		parts := strings.Split(input, ":")
		if len(parts) < 6 {
			return nil, fmt.Errorf("invalid BSSID format: %s (expected format: aa:bb:cc:dd:ee:ff or aa:bb:cc:dd:ee:ff:-65)", input)
		}

		// Check if last part is RSSI (numeric)
		var bssid string
		var rssi *int32

		if len(parts) == 7 {
			// Format: aa:bb:cc:dd:ee:ff:-65 (BSSID with RSSI)
			bssid = strings.Join(parts[:6], ":")
			rssiValue := parts[6]

			// Parse RSSI value
			var rssiInt int32
			if _, err := fmt.Sscanf(rssiValue, "%d", &rssiInt); err != nil {
				return nil, fmt.Errorf("invalid RSSI value in %s: %s", input, rssiValue)
			}

			// Validate RSSI range (typical WiFi RSSI is -10 to -100 dBm)
			if rssiInt > -10 || rssiInt < -100 {
				return nil, fmt.Errorf("RSSI value %d is out of typical range (-10 to -100 dBm)", rssiInt)
			}

			rssi = &rssiInt
		} else if len(parts) == 6 {
			// Format: aa:bb:cc:dd:ee:ff (BSSID only)
			bssid = input
		} else {
			return nil, fmt.Errorf("invalid input format: %s", input)
		}

		// Validate BSSID format
		if !isValidBSSID(bssid) {
			return nil, fmt.Errorf("invalid BSSID format: %s", bssid)
		}

		wifiInputs = append(wifiInputs, types.WifiInput{
			BSSID: normalizeBssid(bssid),
			RSSI:  rssi,
		})
	}

	return wifiInputs, nil
}

func isValidBSSID(bssid string) bool {
	// Regex for MAC address validation
	macRegex := regexp.MustCompile(`^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$`)
	return macRegex.MatchString(bssid)
}
