.PHONY: build test lint tidy docker-build cli

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
	go run cmd/iam-cli/main.go

service:
	go run cmd/iam-service/main.go

fmt:
	gofmt -w .
