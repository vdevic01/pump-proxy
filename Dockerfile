# ----- Build stage -----
FROM golang:1.24.5 AS builder

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

# Install CA certificates
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m appuser

# Copy binary from build stage
COPY --from=builder /app/pump-proxy /app/pump-proxy
COPY --from=builder /app/templates /app/templates
COPY --from=builder /app/static /app/static

WORKDIR /app

# Use non-root user
USER appuser

# Set entrypoint
ENTRYPOINT ["/app/pump-proxy"]
