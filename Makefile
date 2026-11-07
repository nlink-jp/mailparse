# mailparse is a library: there is no binary. `build` only compiles the
# packages, which leaves nothing behind, so it is safe to run anywhere.

.PHONY: build test vet lint fuzz check clean

build:
	go build ./...

## test: unit tests, the fixture tests and every fuzz seed (offline)
test:
	go test -race -cover ./...

vet:
	go vet ./...

## lint: golangci-lint — run before every commit
lint:
	golangci-lint run ./...

## fuzz: explore beyond the seeds for a while (FUZZTIME, default 60s)
FUZZTIME ?= 60s
fuzz:
	go test -run '^$$' -fuzz '^FuzzParseBytes$$' -fuzztime $(FUZZTIME) .

check: lint test

clean:
	rm -rf dist
