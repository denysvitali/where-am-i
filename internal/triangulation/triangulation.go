package triangulation

import (
	"errors"
	"fmt"
	"math"
	"math/rand"

	"github.com/denysvitali/where-am-i/internal/types"
)

// Point represents a 2D coordinate with variance
type Point struct {
	Lat      float64
	Lon      float64
	Variance float64 // Position uncertainty
}

// Measurement represents a measurement from a WiFi access point
type Measurement struct {
	Position    Point   // Known position of the AP
	Distance    float64 // Estimated distance to the AP
	DistanceVar float64 // Variance in distance estimate
	Probability float64 // Probability weight for EM algorithm
	RSSI        *int32  // Original RSSI value
	IsReal      bool    // Whether this is a real measurement or estimated
}

// TriangulationResult represents the result of triangulation
type TriangulationResult struct {
	Position          Point
	EstimatedAccuracy float64 // estimated accuracy in meters
	UsedAccessPoints  int     // number of APs used in calculation
	ConfidenceScore   float64 // confidence score (0-1)
}

// GoogleMapsLink generates a Google Maps link for the triangulated position
func (tr *TriangulationResult) GoogleMapsLink() string {
	return fmt.Sprintf("https://maps.google.com/?q=%.6f,%.6f", tr.Position.Lat, tr.Position.Lon)
}

// EstimateDistanceFromRSSI estimates distance from RSSI using proper path loss model
// Uses the log-distance path loss model which properly accounts for square law propagation:
// RSSI = TxPower - 10*n*log10(d/d0) - X_sigma
// This inherently includes the square law since power ~ 1/d^2 for free space (n=2)
func EstimateDistanceFromRSSI(rssi int32) (distance, variance float64) {
	const (
		txPower           = 20.0 // Typical WiFi transmission power in dBm
		pathLossExponent  = 2.0  // Free space path loss exponent (square law)
		referenceDistance = 1.0  // Reference distance in meters
		shadowingStdDev   = 8.0  // Shadowing standard deviation in dB
		referenceLoss     = 40.0 // Path loss at reference distance (dB)
	)

	if rssi >= txPower {
		return 1.0, 1.0 // Very close, minimum distance with low variance
	}

	// Calculate distance using inverse path loss formula
	// The formula automatically accounts for square law propagation when n=2
	// d = d0 * 10^((TxPower - RSSI - referenceLoss) / (10 * n))
	pathLoss := txPower - float64(rssi) - referenceLoss
	exponent := pathLoss / (10.0 * pathLossExponent)
	distance = referenceDistance * math.Pow(10, exponent)

	// Calculate variance based on shadowing effects and measurement uncertainty
	// The uncertainty increases quadratically with distance due to propagation model
	shadowingVar := math.Pow(shadowingStdDev, 2)

	// Distance uncertainty scales with distance due to logarithmic relationship
	// and the quadratic nature of signal propagation
	distanceUncertainty := distance * math.Sqrt(shadowingVar) / 10.0
	variance = math.Max(1.0, distanceUncertainty)

	// Clamp to reasonable values
	if distance < 1.0 {
		distance = 1.0
		variance = 1.0
	}
	if distance > 1000.0 {
		distance = 1000.0
		variance = 100.0 // High uncertainty for very distant APs
	}

	return distance, variance
}

// ConvertToMeasurements converts WiFi AP data to measurements for multilateration
func ConvertToMeasurements(wifiAPs []types.WifiApPositioningData) ([]Measurement, error) {
	var measurements []Measurement

	for _, wifiAP := range wifiAPs {
		if wifiAP.PositioningData == nil {
			continue // Skip APs without positioning data
		}

		// Convert positioning accuracy to variance (assume Gaussian distribution)
		positionVar := math.Pow(float64(wifiAP.PositioningData.Accuracy), 2)

		measurement := Measurement{
			Position: Point{
				Lat:      wifiAP.PositioningData.Latitude,
				Lon:      wifiAP.PositioningData.Longitude,
				Variance: positionVar,
			},
			RSSI:   wifiAP.RSSI,
			IsReal: true,
		}

		// Estimate distance from RSSI if available
		if wifiAP.RSSI != nil {
			distance, distanceVar := EstimateDistanceFromRSSI(*wifiAP.RSSI)
			measurement.Distance = distance
			measurement.DistanceVar = distanceVar
		} else {
			// Use positioning accuracy as rough distance estimate with high uncertainty
			measurement.Distance = float64(wifiAP.PositioningData.Accuracy) * 2
			measurement.DistanceVar = measurement.Distance * 0.5 // 50% uncertainty
		}

		measurements = append(measurements, measurement)
	}

	if len(measurements) == 0 {
		return nil, errors.New("no usable measurements for triangulation")
	}

	return measurements, nil
}

// EMMultilateration performs multilateration using Expectation-Maximization algorithm
// This implementation is based on the Rust code and properly handles the geometric
// constraints of multilateration
func EMMultilateration(measurements []Measurement, initialGuess *Point, iterations int) (*TriangulationResult, error) {
	if len(measurements) == 0 {
		return nil, errors.New("no measurements provided")
	}

	if len(measurements) == 1 {
		// Single measurement - return its position with high uncertainty
		m := measurements[0]
		return &TriangulationResult{
			Position: Point{
				Lat:      m.Position.Lat,
				Lon:      m.Position.Lon,
				Variance: m.Position.Variance + m.DistanceVar,
			},
			EstimatedAccuracy: math.Sqrt(m.Position.Variance + m.DistanceVar),
			UsedAccessPoints:  1,
			ConfidenceScore:   0.3,
		}, nil
	}

	// Initialize estimated position
	var estimatedPosition Point
	if initialGuess != nil {
		estimatedPosition = *initialGuess
	} else {
		// Use centroid of measurements as initial guess
		estimatedPosition = calculateCentroid(measurements)
		estimatedPosition.Variance = 100.0 // Initial uncertainty
	}

	// Make a copy of measurements for algorithm
	workingMeasurements := make([]Measurement, len(measurements))
	copy(workingMeasurements, measurements)

	// EM Algorithm iterations - following the pattern from the Rust code
	for iter := 0; iter < iterations; iter++ {
		// Randomly select a measurement to update (as in the Rust version)
		selectedIdx := rand.Intn(len(workingMeasurements))
		measurement := &workingMeasurements[selectedIdx]

		// E-step: Calculate probability based on distance discrepancy
		// This properly accounts for the geometric constraints
		xDelta := estimatedPosition.Lat - measurement.Position.Lat
		yDelta := estimatedPosition.Lon - measurement.Position.Lon

		// Convert lat/lon differences to meters using haversine distance
		estimatedDistance := haversineDistance(
			estimatedPosition.Lat, estimatedPosition.Lon,
			measurement.Position.Lat, measurement.Position.Lon,
		)

		// Calculate expected variance (combining position and distance uncertainty)
		expectedVariance := math.Sqrt(measurement.Position.Variance +
			measurement.DistanceVar +
			estimatedPosition.Variance)

		// Calculate probability based on distance discrepancy
		// This follows the same logic as the Rust implementation
		distanceError := math.Abs(measurement.Distance - estimatedDistance)
		if distanceError > expectedVariance && estimatedDistance > 0.0 {
			measurement.Probability = measurement.Distance/estimatedDistance - 1.0
		} else {
			measurement.Probability = 0.0
		}

		// M-step: Adjust estimated position based on probability
		// The weights are applied to the coordinate differences
		weightLat := measurement.Probability
		weightLon := measurement.Probability

		deltaLat := xDelta * weightLat
		deltaLon := yDelta * weightLon

		// Update measurement position if it's not real (latent variable)
		// This allows the algorithm to adjust uncertain AP positions
		if !measurement.IsReal {
			measurement.Position.Lat -= deltaLat
			measurement.Position.Lon -= deltaLon
		}

		// Update estimated position
		estimatedPosition.Lat += deltaLat
		estimatedPosition.Lon += deltaLon
	}

	// Calculate final variance based on weighted measurements
	// This follows the variance calculation from the Rust code
	sumWeight := 0.0
	weightedVariance := 0.0

	for _, measurement := range workingMeasurements {
		weight := measurement.Probability + 1.0
		weightedVariance += weight * (measurement.Position.Variance + measurement.DistanceVar)
		sumWeight += weight
	}

	if sumWeight > 0.0 {
		estimatedPosition.Variance = weightedVariance / sumWeight
	} else {
		estimatedPosition.Variance = 100.0 // Default high uncertainty
	}

	// Calculate confidence score based on convergence quality
	usedAPs := 0
	totalProbability := 0.0
	for _, measurement := range workingMeasurements {
		if measurement.Probability > 0.1 {
			usedAPs++
		}
		totalProbability += math.Abs(measurement.Probability)
	}

	confidence := calculateConfidenceScore(usedAPs, totalProbability, len(measurements))

	return &TriangulationResult{
		Position:          estimatedPosition,
		EstimatedAccuracy: math.Sqrt(estimatedPosition.Variance),
		UsedAccessPoints:  usedAPs,
		ConfidenceScore:   confidence,
	}, nil
}

// TriangulatePosition performs triangulation using the EM multilateration algorithm
func TriangulatePosition(wifiAPs []types.WifiApPositioningData) (*TriangulationResult, error) {
	measurements, err := ConvertToMeasurements(wifiAPs)
	if err != nil {
		return nil, err
	}

	// Use EM multilateration with a reasonable number of iterations
	// More iterations = better convergence but longer computation time
	const iterations = 100
	return EMMultilateration(measurements, nil, iterations)
}

// Helper functions

func calculateCentroid(measurements []Measurement) Point {
	var sumLat, sumLon, sumWeight float64

	for _, m := range measurements {
		// Weight by inverse of variance (more certain measurements have higher weight)
		weight := 1.0 / (1.0 + m.Position.Variance)
		sumLat += m.Position.Lat * weight
		sumLon += m.Position.Lon * weight
		sumWeight += weight
	}

	if sumWeight > 0 {
		return Point{
			Lat: sumLat / sumWeight,
			Lon: sumLon / sumWeight,
		}
	}

	// Fallback to simple average
	return Point{
		Lat: sumLat / float64(len(measurements)),
		Lon: sumLon / float64(len(measurements)),
	}
}

func calculateConfidenceScore(usedAPs int, totalProbability float64, totalMeasurements int) float64 {
	if usedAPs == 0 {
		return 0.0
	}

	baseScore := 0.3 // Base confidence

	// More APs = higher confidence (geometric dilution of precision improvement)
	apBonus := math.Min(0.4, float64(usedAPs-1)*0.1)

	// Higher total probability = better convergence
	probabilityBonus := math.Min(0.3, totalProbability/float64(totalMeasurements)*0.3)

	return math.Min(1.0, baseScore+apBonus+probabilityBonus)
}

// haversineDistance calculates the great circle distance between two points
// This is essential for proper distance calculations in geographic coordinates
func haversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371000 // Earth radius in meters

	dLat := (lat2 - lat1) * math.Pi / 180
	dLon := (lon2 - lon1) * math.Pi / 180

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*math.Pi/180)*math.Cos(lat2*math.Pi/180)*
			math.Sin(dLon/2)*math.Sin(dLon/2)

	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return R * c
}
