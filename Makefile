APP ?= trustpin
CMD := ./cmd/trustpin
GOCACHE ?= /tmp/go-build

.PHONY: build run serve test fmt clean

build:
	GOCACHE=$(GOCACHE) go build -o $(APP) $(CMD)

run:
	GOCACHE=$(GOCACHE) go run $(CMD)

serve:
	GOCACHE=$(GOCACHE) go run $(CMD) serve

test:
	GOCACHE=$(GOCACHE) go test ./...

fmt:
	gofmt -w cmd/trustpin/main.go internal/cli/*.go internal/trustpin/*.go internal/webui/server.go

clean:
	rm -f $(APP) trustPIN
