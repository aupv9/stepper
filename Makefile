.PHONY: build test lint tidy docker-build cli service fmt

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
