COMMIT := $(shell git rev-parse HEAD)

all:
	go build -ldflags "-X main.revision=$(COMMIT)" -o bin/packetbridge cmd/packetbridge/main.go
	go build -ldflags "-X main.revision=$(COMMIT)" -o bin/balancer cmd/balancer/main.go

clean:
	rm -rf bin

test:
	go test ./...
