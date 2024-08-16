.PHONY: all test

all:
	go build -ldflags='-s -w' -trimpath

test:
	go test .
