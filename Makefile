.PHONY: all test

all:
	go build -ldflags='-s -w'

test:
	go test .
