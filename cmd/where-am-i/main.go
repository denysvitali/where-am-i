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

RSSI values should be in dBm (typically -10 to -100).`,
	Args: cobra.MinimumNArgs(1),
	RunE: locateRun,
	Example: `  # Locate single WiFi network
  where-am-i locate aa:bb:cc:dd:ee:ff

  # Locate with RSSI for improved accuracy
  where-am-i locate aa:bb:cc:dd:ee:ff:-45 11:22:33:44:55:66:-60

  # Multiple networks with triangulation
  where-am-i locate aa:bb:cc:dd:ee:ff:-45 11:22:33:44:55:66:-60 22:33:44:55:66:77:-70

  # Output as JSON
  where-am-i locate --format json aa:bb:cc:dd:ee:ff:-45`,
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

	// Bind flags to viper
	viper.BindPFlag("server.url", locateCmd.Flags().Lookup("server-url"))
	viper.BindPFlag("server.connect_timeout", locateCmd.Flags().Lookup("connect-timeout"))
	viper.BindPFlag("server.read_timeout", locateCmd.Flags().Lookup("read-timeout"))
	viper.BindPFlag("server.enforce_modern_tls", locateCmd.Flags().Lookup("enforce-modern-tls"))
	viper.BindPFlag("request.max_request_networks", locateCmd.Flags().Lookup("max-networks"))
	viper.BindPFlag("request.min_rssi", locateCmd.Flags().Lookup("min-rssi"))

	rootCmd.AddCommand(locateCmd)
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

	// Parse WiFi inputs (supports both "BSSID" and "BSSID:RSSI" formats)
	client := applewps.NewClient(&config, logger)
	wifiInputs, err := applewps.ParseWifiInputs(args)
	if err != nil {
		return fmt.Errorf("failed to parse WiFi inputs: %w", err)
	}

	if len(wifiInputs) == 0 {
		return fmt.Errorf("no valid WiFi inputs provided")
	}

	logger.WithField("wifi_inputs", len(wifiInputs)).Info("Querying Apple WPS for positioning data")

	// Check if any inputs have RSSI values
	hasRSSI := false
	for _, input := range wifiInputs {
		if input.RSSI != nil {
			hasRSSI = true
			break
		}
	}

	if hasRSSI {
		// Use new method with RSSI support and triangulation
		results, tri, err := client.FetchPositioningDataWithRSSI(wifiInputs)
		if err != nil {
			return fmt.Errorf("failed to fetch positioning data with RSSI: %w", err)
		}
		showAPs, _ := cmd.Flags().GetBool("show-aps")
		return outputResultsWithTriangulation(results, tri, format, showAPs)
	} else {
		// Fall back to original method for backward compatibility
		var bssids []string
		for _, input := range wifiInputs {
			bssids = append(bssids, input.BSSID)
		}

		results, err := client.FetchNearbyApPositioningData(bssids)
		if err != nil {
			return fmt.Errorf("failed to fetch positioning data: %w", err)
		}
		return outputResults(results, format)
	}
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
