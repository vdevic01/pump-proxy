# ----- Build stage -----
FROM golang:1.22 AS builder

# Set working dir inside build container
WORKDIR /app

# Copy go files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build binary
RUN go build -o pump-proxy .

# ----- Runtime stage -----
FROM ubuntu:22.04

# Create non-root user
RUN useradd -m appuser

# Copy binary from build stage
COPY --from=builder /app/pump-proxy /usr/local/bin/pump-proxy

# Use non-root user
USER appuser

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/pump-proxy"]
