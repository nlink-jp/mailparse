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

## fuzz: explore beyond the seeds for a while (FUZZTIME per target, default 60s).
## Minimizing is capped at one try: with seeds of tens of KB, minimizing each new
## input stalls the run for seconds and counts no executions.
FUZZTIME ?= 60s
FUZZFLAGS = -run '^$$' -fuzztime $(FUZZTIME) -fuzzminimizetime 1x
fuzz:
	go test $(FUZZFLAGS) -fuzz '^FuzzParseBytes$$' .
	go test $(FUZZFLAGS) -fuzz '^FuzzOpen$$' ./cfb

check: lint test

clean:
	rm -rf dist
