.PHONY: build test lint tidy docker-build cli service binaries fmt

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

binaries:
	go build -o bin/iam-service ./cmd/iam-service
	go build -o bin/iam-cli     ./cmd/iam-cli

fmt:
	gofmt -w .
