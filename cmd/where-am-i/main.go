package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/adrg/xdg"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/denysvitali/where-am-i/internal/applewps"
	"github.com/denysvitali/where-am-i/internal/triangulation"
	"github.com/denysvitali/where-am-i/internal/types"
	"github.com/denysvitali/where-am-i/internal/wifi"
)

var (
	version = "dev"
	cfgFile string
	verbose bool
	debug   bool
	format  string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "where-am-i",
	Short: "Find location using WiFi networks via Apple WPS",
	Long: `where-am-i is a CLI tool that queries Apple's Wireless Positioning System (WPS)
to determine location based on nearby WiFi networks.

You can provide WiFi BSSID (MAC addresses) as arguments, and the tool will
query Apple's servers to get positioning data for those access points.`,
	Version: version,
	Example: `  # Query location for specific WiFi networks
  where-am-i locate aa:bb:cc:dd:ee:ff 11:22:33:44:55:66

  # Output as JSON
  where-am-i locate --format json aa:bb:cc:dd:ee:ff

  # Use custom configuration
  where-am-i locate --config config.yaml aa:bb:cc:dd:ee:ff`,
}

// locateCmd represents the locate command
var locateCmd = &cobra.Command{
	Use:   "locate [BSSID...] or [BSSID:RSSI...]",
	Short: "Locate WiFi access points using Apple WPS with optional triangulation",
	Long: `Query Apple's Wireless Positioning System to get location data for 
the specified WiFi access points (BSSIDs). 

You can provide BSSIDs in two formats:
- Simple BSSID: aa:bb:cc:dd:ee:ff
- BSSID with RSSI: aa:bb:cc:dd:ee:ff:-65

When RSSI values are provided, the tool will:
1. Filter out weak signals (below min_rssi threshold)
2. Perform triangulation using multiple access points
3. Provide estimated location with confidence scores

RSSI values should be in dBm (typically -10 to -100).

Alternatively, use --auto-scan to automatically discover nearby WiFi networks.`,
	RunE: locateRun,
	Example: `  # Locate single WiFi network
  where-am-i locate aa:bb:cc:dd:ee:ff

  # Locate with RSSI for improved accuracy
  where-am-i locate aa:bb:cc:dd:ee:ff:-45 11:22:33:44:55:66:-60

  # Multiple networks with triangulation
  where-am-i locate aa:bb:cc:dd:ee:ff:-45 11:22:33:44:55:66:-60 22:33:44:55:66:77:-70

  # Auto-scan nearby networks and locate
  where-am-i locate --auto-scan

  # Output as JSON
  where-am-i locate --format json aa:bb:cc:dd:ee:ff:-45`,
}

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan for nearby WiFi networks and display their BSSIDs",
	Long: `Scan for nearby WiFi networks using the system's WiFi interface.
This uses Linux's nl80211/netlink interface to discover access points
without requiring root privileges on most systems.

Note: Signal strength (RSSI) values are not available from scan results
due to limitations in the WiFi library. The scan will only return BSSID
(MAC address) information.`,
	RunE: scanRun,
	Example: `  # Scan for WiFi networks
  where-am-i scan

  # Scan and format for use with locate command
  where-am-i scan --format args

  # Limit number of results
  where-am-i scan --max-networks 10`,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $XDG_CONFIG_HOME/where-am-i/config.yaml or ~/.config/where-am-i/config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "debug output")

	// Locate command flags
	locateCmd.Flags().StringVarP(&format, "format", "f", "table", "output format (table, json, yaml)")
	locateCmd.Flags().String("server-url", "", "Apple WPS server URL")
	locateCmd.Flags().Int("connect-timeout", 10000, "connection timeout in milliseconds")
	locateCmd.Flags().Int("read-timeout", 10000, "read timeout in milliseconds")
	locateCmd.Flags().Bool("enforce-modern-tls", false, "enforce modern TLS (TLS 1.3)")
	locateCmd.Flags().Int("max-networks", 40, "maximum number of networks to request")
	locateCmd.Flags().Int32("min-rssi", -90, "minimum RSSI to include access point (dBm)")
	locateCmd.Flags().Bool("show-aps", false, "show individual access points in output")
	locateCmd.Flags().Bool("auto-scan", false, "automatically scan for nearby WiFi networks")

	// Scan command flags
	scanCmd.Flags().StringVarP(&format, "format", "f", "table", "output format (table, json, args)")
	scanCmd.Flags().Int("max-networks", 0, "maximum number of networks to scan (0 = no limit)")

	// Bind flags to viper
	if err := viper.BindPFlag("server.url", locateCmd.Flags().Lookup("server-url")); err != nil {
		panic(fmt.Sprintf("failed to bind server.url flag: %v", err))
	}
	if err := viper.BindPFlag("server.connect_timeout", locateCmd.Flags().Lookup("connect-timeout")); err != nil {
		panic(fmt.Sprintf("failed to bind server.connect_timeout flag: %v", err))
	}
	if err := viper.BindPFlag("server.read_timeout", locateCmd.Flags().Lookup("read-timeout")); err != nil {
		panic(fmt.Sprintf("failed to bind server.read_timeout flag: %v", err))
	}
	if err := viper.BindPFlag("server.enforce_modern_tls", locateCmd.Flags().Lookup("enforce-modern-tls")); err != nil {
		panic(fmt.Sprintf("failed to bind server.enforce_modern_tls flag: %v", err))
	}
	if err := viper.BindPFlag("request.max_request_networks", locateCmd.Flags().Lookup("max-networks")); err != nil {
		panic(fmt.Sprintf("failed to bind request.max_request_networks flag: %v", err))
	}
	if err := viper.BindPFlag("request.min_rssi", locateCmd.Flags().Lookup("min-rssi")); err != nil {
		panic(fmt.Sprintf("failed to bind request.min_rssi flag: %v", err))
	}

	rootCmd.AddCommand(locateCmd)
	rootCmd.AddCommand(scanCmd)
}

// initConfig reads in config file and ENV variables
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(cfgFile)
	} else {
		// Use XDG Base Directory specification
		configDir := xdg.ConfigHome + "/where-am-i"

		// Search config in XDG config directory and current directory
		viper.AddConfigPath(configDir)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName("config")
	}

	// Environment variables
	viper.SetEnvPrefix("WHERE_AM_I")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Set defaults from types.DefaultConfig()
	defaultConfig := types.DefaultConfig()
	viper.SetDefault("server.url", defaultConfig.Server.URL)
	viper.SetDefault("server.connect_timeout", defaultConfig.Server.ConnectTimeout)
	viper.SetDefault("server.read_timeout", defaultConfig.Server.ReadTimeout)
	viper.SetDefault("server.enforce_modern_tls", defaultConfig.Server.EnforceModernTLS)
	viper.SetDefault("throttle.cooldown", defaultConfig.Throttle.Cooldown)
	viper.SetDefault("throttle.trigger_result_count", defaultConfig.Throttle.TriggerResultCount)
	viper.SetDefault("throttle.throttled_additional_results", defaultConfig.Throttle.ThrottledAdditionalResults)
	viper.SetDefault("throttle.max_additional_results", defaultConfig.Throttle.MaxAdditionalResults)
	viper.SetDefault("request.max_request_networks", defaultConfig.Request.MaxRequestNetworks)
	viper.SetDefault("request.min_rssi", defaultConfig.Request.MinRSSI)
	viper.SetDefault("request.user_agent", defaultConfig.Request.UserAgent)
	viper.SetDefault("request.locale", defaultConfig.Request.Locale)
	viper.SetDefault("request.identifier", defaultConfig.Request.Identifier)
	viper.SetDefault("request.version", defaultConfig.Request.Version)
	viper.SetDefault("request.software_build", defaultConfig.Request.SoftwareBuild)
	viper.SetDefault("request.product_id", defaultConfig.Request.ProductID)

	// If a config file is found, read it in
	if err := viper.ReadInConfig(); err == nil {
		if verbose {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
	}
}

func setupLogger() *logrus.Logger {
	logger := logrus.New()

	if debug {
		logger.SetLevel(logrus.DebugLevel)
	} else if verbose {
		logger.SetLevel(logrus.InfoLevel)
	} else {
		logger.SetLevel(logrus.WarnLevel)
	}

	// Use structured logging for JSON output
	if format == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			DisableTimestamp: true,
		})
	}

	return logger
}

func locateRun(cmd *cobra.Command, args []string) error {
	logger := setupLogger()

	// Load configuration
	var config types.Config
	if err := viper.Unmarshal(&config); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	if debug {
		logger.WithField("config", config).Debug("Loaded configuration")
	}

	var wifiInputs []types.WifiInput
	var err error

	// Check if auto-scan is enabled
	autoScan, _ := cmd.Flags().GetBool("auto-scan")

	if autoScan && len(args) == 0 {
		// Auto-scan for WiFi networks
		logger.Info("Auto-scanning for nearby WiFi networks...")

		scanner, err := wifi.NewScanner(logger)
		if err != nil {
			return fmt.Errorf("failed to create WiFi scanner: %w", err)
		}
		defer func() {
			if closeErr := scanner.Close(); closeErr != nil {
				logger.WithError(closeErr).Warn("Failed to close WiFi scanner")
			}
		}()

		// Get max networks and min RSSI from configuration
		maxNetworks, _ := cmd.Flags().GetInt("max-networks")
		minRSSI, _ := cmd.Flags().GetInt32("min-rssi")

		wifiInputs, err = scanner.ScanWithOptions(minRSSI, maxNetworks)
		if err != nil {
			return fmt.Errorf("failed to scan WiFi networks: %w", err)
		}

		if len(wifiInputs) == 0 {
			return fmt.Errorf("no WiFi networks found during scan")
		}

		logger.WithField("scanned_networks", len(wifiInputs)).Info("Found WiFi networks")
	} else {
		// Parse WiFi inputs from command line arguments (supports both "BSSID" and "BSSID:RSSI" formats)
		if len(args) == 0 {
			return fmt.Errorf("no WiFi inputs provided (use --auto-scan to scan automatically)")
		}

		wifiInputs, err = applewps.ParseWifiInputs(args)
		if err != nil {
			return fmt.Errorf("failed to parse WiFi inputs: %w", err)
		}

		if len(wifiInputs) == 0 {
			return fmt.Errorf("no valid WiFi inputs provided")
		}
	}

	client := applewps.NewClient(&config, logger)
	logger.WithField("wifi_inputs", len(wifiInputs)).Info("Querying Apple WPS for positioning data")

	// Always use the RSSI-aware method and attempt triangulation
	// This ensures we always get a Google Maps link, even without RSSI values
	results, tri, err := client.FetchPositioningDataWithRSSI(wifiInputs)
	if err != nil {
		return fmt.Errorf("failed to fetch positioning data: %w", err)
	}

	showAPs, _ := cmd.Flags().GetBool("show-aps")
	return outputResultsWithTriangulation(results, tri, format, showAPs)
}

func outputResults(results []types.WifiApPositioningData, format string) error {
	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(results)

	case "yaml":
		// For simplicity, we'll use JSON format for YAML too
		// In a production app, you might want to use a proper YAML library
		return outputResults(results, "json")

	case "table":
		fallthrough
	default:
		return outputTable(results)
	}
}

func outputTable(results []types.WifiApPositioningData) error {
	fmt.Printf("%-17s %-12s %-12s %-8s %-10s %-15s\n",
		"BSSID", "Latitude", "Longitude", "Accuracy", "Altitude", "Vert. Accuracy")
	fmt.Println(strings.Repeat("-", 80))

	for _, result := range results {
		if result.PositioningData == nil {
			fmt.Printf("%-17s %-12s %-12s %-8s %-10s %-15s\n",
				result.BSSID, "N/A", "N/A", "N/A", "N/A", "N/A")
			continue
		}

		data := result.PositioningData
		altitude := "N/A"
		if data.AltitudeMeters != nil {
			altitude = fmt.Sprintf("%dm", *data.AltitudeMeters)
		}

		vertAccuracy := "N/A"
		if data.VerticalAccuracyMeters != nil {
			vertAccuracy = fmt.Sprintf("%dm", *data.VerticalAccuracyMeters)
		}

		fmt.Printf("%-17s %-12.6f %-12.6f %-8dm %-10s %-15s\n",
			result.BSSID,
			data.Latitude,
			data.Longitude,
			data.Accuracy,
			altitude,
			vertAccuracy)
	}

	return nil
}

// TriangulationOutput represents the combined output with triangulation results
type TriangulationOutput struct {
	AccessPoints  []types.WifiApPositioningData `json:"access_points,omitempty"`
	Triangulation *TriangulationResultWithLink  `json:"triangulation,omitempty"`
}

// TriangulationResultWithLink wraps the triangulation result with a Google Maps link
type TriangulationResultWithLink struct {
	*triangulation.TriangulationResult
	GoogleMapsLink string `json:"google_maps_link"`
}

func outputResultsWithTriangulation(results []types.WifiApPositioningData, triangulationResult *triangulation.TriangulationResult, format string, showAPs bool) error {
	var triangulationWithLink *TriangulationResultWithLink
	if triangulationResult != nil {
		triangulationWithLink = &TriangulationResultWithLink{
			TriangulationResult: triangulationResult,
			GoogleMapsLink:      triangulationResult.GoogleMapsLink(),
		}
	}

	output := TriangulationOutput{
		Triangulation: triangulationWithLink,
	}

	// Only include access points if showAPs is true
	if showAPs {
		output.AccessPoints = results
	}

	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(output)

	case "yaml":
		// For simplicity, we'll use JSON format for YAML too
		return outputResultsWithTriangulation(results, triangulationResult, "json", showAPs)

	default: // table
		return outputTriangulationTable(results, triangulationResult, showAPs)
	}
}

func outputTriangulationTable(results []types.WifiApPositioningData, triangulationResult *triangulation.TriangulationResult, showAPs bool) error {
	// First show triangulation result if available
	if triangulationResult != nil {
		fmt.Printf("Triangulated Location:\n")
		fmt.Printf("  Latitude:     %.6f\n", triangulationResult.Position.Lat)
		fmt.Printf("  Longitude:    %.6f\n", triangulationResult.Position.Lon)
		fmt.Printf("  Accuracy:     %.1f meters\n", triangulationResult.EstimatedAccuracy)
		fmt.Printf("  Confidence:   %.1f%%\n", triangulationResult.ConfidenceScore*100)
		fmt.Printf("  Used APs:     %d\n", triangulationResult.UsedAccessPoints)
		fmt.Printf("  Google Maps:  %s\n", triangulationResult.GoogleMapsLink())

		// Only add extra newline if we're going to show APs
		if showAPs {
			fmt.Printf("\n")
		}
	}

	// Only show individual AP results if flag is set
	if showAPs {
		fmt.Printf("Individual Access Points:\n")
		fmt.Printf("%-18s %-12s %-12s %-10s %-10s %-15s %-18s\n",
			"BSSID", "Latitude", "Longitude", "Accuracy", "RSSI", "Altitude", "Vert. Accuracy")
		fmt.Printf("%-18s %-12s %-12s %-10s %-10s %-15s %-18s\n",
			strings.Repeat("-", 18), strings.Repeat("-", 12), strings.Repeat("-", 12),
			strings.Repeat("-", 10), strings.Repeat("-", 10), strings.Repeat("-", 15), strings.Repeat("-", 18))

		for _, result := range results {
			rssiStr := "N/A"
			if result.RSSI != nil {
				rssiStr = fmt.Sprintf("%d dBm", *result.RSSI)
			}

			if result.PositioningData != nil {
				altStr := "N/A"
				if result.PositioningData.AltitudeMeters != nil {
					altStr = fmt.Sprintf("%d m", *result.PositioningData.AltitudeMeters)
				}

				vertAccStr := "N/A"
				if result.PositioningData.VerticalAccuracyMeters != nil {
					vertAccStr = fmt.Sprintf("%d m", *result.PositioningData.VerticalAccuracyMeters)
				}

				fmt.Printf("%-18s %-12.6f %-12.6f %-10d %-10s %-15s %-18s\n",
					result.BSSID,
					result.PositioningData.Latitude,
					result.PositioningData.Longitude,
					result.PositioningData.Accuracy,
					rssiStr,
					altStr,
					vertAccStr)
			} else {
				fmt.Printf("%-18s %-12s %-12s %-10s %-10s %-15s %-18s\n",
					result.BSSID, "Not found", "Not found", "N/A", rssiStr, "N/A", "N/A")
			}
		}
	}

	return nil
}

func outputResultsWithSimpleLocation(results []types.WifiApPositioningData, format string, showAPs bool) error {
	// Filter out results without positioning data
	var validResults []types.WifiApPositioningData
	for _, result := range results {
		if result.PositioningData != nil {
			validResults = append(validResults, result)
		}
	}

	if len(validResults) == 0 {
		return fmt.Errorf("no access points with location data found")
	}

	// Calculate simple centroid (average) of all access points
	var latSum, lonSum float64
	var accuracySum int32
	for _, result := range validResults {
		latSum += result.PositioningData.Latitude
		lonSum += result.PositioningData.Longitude
		accuracySum += result.PositioningData.Accuracy
	}

	avgLat := latSum / float64(len(validResults))
	avgLon := lonSum / float64(len(validResults))
	avgAccuracy := int(accuracySum) / len(validResults)

	// Create a simple location result
	simpleLocation := struct {
		EstimatedLocation struct {
			Latitude         float64 `json:"latitude"`
			Longitude        float64 `json:"longitude"`
			Accuracy         int     `json:"accuracy_meters"`
			GoogleMapsLink   string  `json:"google_maps_link"`
			AccessPointsUsed int     `json:"access_points_used"`
			Note             string  `json:"note"`
		} `json:"estimated_location"`
		AccessPoints []types.WifiApPositioningData `json:"access_points,omitempty"`
	}{}

	simpleLocation.EstimatedLocation.Latitude = avgLat
	simpleLocation.EstimatedLocation.Longitude = avgLon
	simpleLocation.EstimatedLocation.Accuracy = avgAccuracy
	simpleLocation.EstimatedLocation.AccessPointsUsed = len(validResults)
	simpleLocation.EstimatedLocation.Note = "Simple centroid calculation (RSSI not available)"
	simpleLocation.EstimatedLocation.GoogleMapsLink = fmt.Sprintf("https://maps.google.com/maps?q=%.6f,%.6f", avgLat, avgLon)

	// Only include individual access points if showAPs is true
	if showAPs {
		simpleLocation.AccessPoints = validResults
	}

	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(simpleLocation)

	case "yaml":
		return outputResultsWithSimpleLocation(results, "json", showAPs)

	default: // table
		fmt.Printf("Estimated Location (centroid of %d access points):\n", len(validResults))
		fmt.Printf("  Latitude:     %.6f\n", avgLat)
		fmt.Printf("  Longitude:    %.6f\n", avgLon)
		fmt.Printf("  Accuracy:     ~%d meters (average)\n", avgAccuracy)
		fmt.Printf("  Google Maps:  %s\n", simpleLocation.EstimatedLocation.GoogleMapsLink)
		fmt.Printf("  Note:         %s\n", simpleLocation.EstimatedLocation.Note)

		// Only show individual access points if showAPs flag is set
		if showAPs {
			fmt.Printf("\nIndividual Access Points:\n")
			return outputTable(validResults)
		}

		return nil
	}
}

func scanRun(cmd *cobra.Command, args []string) error {
	logger := setupLogger()

	// Create WiFi scanner
	scanner, err := wifi.NewScanner(logger)
	if err != nil {
		return fmt.Errorf("failed to create WiFi scanner: %w", err)
	}
	defer func() {
		if closeErr := scanner.Close(); closeErr != nil {
			logger.WithError(closeErr).Warn("Failed to close WiFi scanner")
		}
	}()

	// Validate WiFi interface availability
	if err := scanner.ValidateInterface(); err != nil {
		return fmt.Errorf("WiFi interface validation failed: %w", err)
	}

	logger.Info("Scanning for nearby WiFi networks...")

	// Get max networks limit from flags
	maxNetworks, _ := cmd.Flags().GetInt("max-networks")

	// Scan for networks
	var wifiInputs []types.WifiInput
	if maxNetworks > 0 {
		wifiInputs, err = scanner.ScanWithOptions(-100, maxNetworks) // Use -100 as "no RSSI filter"
	} else {
		wifiInputs, err = scanner.ScanNetworks()
	}

	if err != nil {
		return fmt.Errorf("failed to scan WiFi networks: %w", err)
	}

	if len(wifiInputs) == 0 {
		logger.Warn("No WiFi networks found")
		return nil
	}

	logger.WithField("networks_found", len(wifiInputs)).Info("WiFi scan completed")

	// Output results based on format
	format, _ := cmd.Flags().GetString("format")
	return outputScanResults(wifiInputs, format)
}

func outputScanResults(wifiInputs []types.WifiInput, format string) error {
	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(wifiInputs)

	case "args":
		// Format suitable for use as arguments to the locate command
		for _, input := range wifiInputs {
			if input.RSSI != nil {
				fmt.Printf("%s:%d ", input.BSSID, *input.RSSI)
			} else {
				fmt.Printf("%s ", input.BSSID)
			}
		}
		fmt.Println() // Add newline at the end
		return nil

	case "table":
		fallthrough
	default:
		return outputScanTable(wifiInputs)
	}
}

func outputScanTable(wifiInputs []types.WifiInput) error {
	fmt.Printf("%-18s %-10s\n", "BSSID", "RSSI")
	fmt.Printf("%-18s %-10s\n", strings.Repeat("-", 18), strings.Repeat("-", 10))

	for _, input := range wifiInputs {
		rssiStr := "N/A"
		if input.RSSI != nil {
			rssiStr = fmt.Sprintf("%d dBm", *input.RSSI)
		}
		fmt.Printf("%-18s %-10s\n", input.BSSID, rssiStr)
	}

	fmt.Printf("\nFound %d WiFi networks\n", len(wifiInputs))
	return nil
}
