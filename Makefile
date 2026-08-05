.PHONY: build test lint tidy docker-build cli service fmt loadtest quickstart

build:
	go build ./...

test:
	go test ./... -v -race

lint:
	golangci-lint run ./...

tidy:
	go mod tidy

docker-build:
	docker build -f deployments/Dockerfile -t common-iam:latest .

cli:
	go run ./cmd/iam-cli

service:
	go run ./cmd/iam-service

fmt:
	gofmt -w .

# Requires k6 (https://k6.io) and a running gateway (make service) with
# IAM_TOKEN exported from the dev-mode logs.
loadtest:
	k6 run -e BASE_URL=$${BASE_URL:-http://localhost:8080} -e IAM_TOKEN=$${IAM_TOKEN} loadtest/k6.js

quickstart:
	cd deployments/quickstart && docker compose up --build
