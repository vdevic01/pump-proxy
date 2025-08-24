# ----- Build stage -----
FROM golang:1.25.0 AS builder

# Set working dir inside build container
WORKDIR /app

# Copy go files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o pump-proxy .

# ----- Runtime stage -----
FROM alpine:3.22.1

# Install CA certificates
RUN apk add --no-cache ca-certificates

# Create non-root user
RUN adduser -D appuser

# Copy binary from build stage
COPY --from=builder /app/pump-proxy /app/pump-proxy
COPY --from=builder /app/templates /app/templates
COPY --from=builder /app/static /app/static

WORKDIR /app

# Use non-root user
USER appuser

# Set entrypoint
ENTRYPOINT ["/app/pump-proxy"]
