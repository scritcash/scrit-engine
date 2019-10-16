.PHONY: all test

all:
	env GO111MODULE=on go build -mod vendor -v ./...

test:
	go test -v ./...
