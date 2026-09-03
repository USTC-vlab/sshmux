.PHONY: all test test-race

all:
	go build -ldflags='-s -w' -trimpath

test:
	go test ./...
	cd crypto && go test ./ssh

test-race:
	go test -race ./...
	cd crypto && go test -race ./ssh
