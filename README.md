# Where Am I

Find your location using WiFi networks via Apple's Wireless Positioning System.

## Quick Start

```bash
# Clone and build
git clone https://github.com/denysvitali/where-am-i
cd where-am-i
make build

# Find location using WiFi MAC addresses
./bin/where-am-i locate aa:bb:cc:dd:ee:ff 11:22:33:44:55:66

# Output as JSON
./bin/where-am-i locate --format json aa:bb:cc:dd:ee:ff
```

## Installation

**Option 1: With Nix (recommended)**
```bash
nix develop
make build
```

**Option 2: Manual**
```bash
# Requires Go 1.22+, buf, protoc
make build
```

## Usage

```bash
# Basic location lookup
where-am-i locate <MAC_ADDRESS> [MAC_ADDRESS...]

# With signal strength for better accuracy
where-am-i locate aa:bb:cc:dd:ee:ff:-45 11:22:33:44:55:66:-60

# Different output formats
where-am-i locate --format json aa:bb:cc:dd:ee:ff
where-am-i locate --format yaml aa:bb:cc:dd:ee:ff
```

## Configuration

Create `~/.config/where-am-i/config.yaml`:
```yaml
server:
  url: "https://gs-loc.apple.com/clls/wloc"
  # Or use GrapheneOS proxy for privacy:
  # url: "https://gs-loc.apple.grapheneos.org/clls/wloc"

request:
  max_request_networks: 40
```

Or use environment variables:
```bash
export WHERE_AM_I_SERVER_URL="https://gs-loc.apple.grapheneos.org/clls/wloc"
```

## Development

```bash
nix develop             # Enter dev environment
make generate           # Generate protobuf files
make build              # Build application
make test               # Run tests
make run ARGS="--help"  # Run with arguments
```

## How It Works

1. Takes WiFi MAC addresses (BSSIDs) as input
2. Queries Apple's positioning servers using their WPS protocol
3. Returns location data with accuracy estimates
4. Supports triangulation when multiple networks with signal strength are provided

## Privacy

This tool queries Apple's servers. For enhanced privacy, use the GrapheneOS proxy endpoint in your configuration.

## Thanks

Thanks to the GrapheneOS team for providing the [original Java / Rust implementation](https://github.com/GrapheneOS/platform_packages_apps_NetworkLocation/) and the proxy endpoint.
