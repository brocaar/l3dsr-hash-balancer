all: clean
	go build -o bin/packetbridge cmd/packetbridge/main.go
	go build -o bin/balancer cmd/balancer/main.go
	go build -o bin/testsyn cmd/testsyn/main.go

clean:
	rm -rf bin

test:
	go test ./...
