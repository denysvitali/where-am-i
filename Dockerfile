# Build stage
FROM golang:1.24-alpine AS builder

# Install required packages
RUN apk add --no-cache git

# Install buf for protobuf generation
RUN go install github.com/bufbuild/buf/cmd/buf@latest

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Generate protobuf files
RUN buf generate

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static" -s -w' -o where-am-i ./cmd/where-am-i

# Final stage
FROM scratch

# Add ca-certificates for HTTPS requests
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the binary
COPY --from=builder /app/where-am-i /where-am-i

# Set the entrypoint
ENTRYPOINT ["/where-am-i"]
