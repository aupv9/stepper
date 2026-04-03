# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Download dependencies first (layer cache)
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build service binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/iam-service ./cmd/iam-service
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/iam-cli ./cmd/iam-cli

# --- Runtime stage ---
FROM gcr.io/distroless/static-debian12

WORKDIR /app

# Copy binaries
COPY --from=builder /bin/iam-service /app/iam-service
COPY --from=builder /bin/iam-cli     /app/iam-cli

# Copy default policy config
COPY config/policy.example.yaml /app/config/policy.yaml

# Expose HTTP port
EXPOSE 8080

# Default environment
ENV IAM_ADDR=:8080
ENV IAM_POLICY_FILE=/app/config/policy.yaml
ENV IAM_REALM=IAM

ENTRYPOINT ["/app/iam-service"]
