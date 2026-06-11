BINARY   := ot-dspm
CARGO    := cargo
TARGET   := target/release/$(BINARY)

.PHONY: all build release debug test bench check fmt lint clean docker help

all: build

## Build (debug)
build:
	$(CARGO) build

## Build (release, optimised)
release:
	$(CARGO) build --release

## Run debug binary (pass ARGS="..." to forward arguments)
run:
	$(CARGO) run -- $(ARGS)

## Run tests
test:
	$(CARGO) test

## Run benchmarks
bench:
	$(CARGO) bench

## Type-check without producing an artifact
check:
	$(CARGO) check

## Format source code
fmt:
	$(CARGO) fmt

## Lint (clippy)
lint:
	$(CARGO) clippy -- -D warnings

## Format + lint
ci: fmt lint test

## Statically linked Linux release (requires musl toolchain)
linux-static:
	$(CARGO) build --release --target x86_64-unknown-linux-musl

## ARM64 Linux release (requires cross)
linux-arm64:
	cross build --release --target aarch64-unknown-linux-musl

## Build Docker image
docker:
	docker build -t $(BINARY):latest .

## Remove build artifacts
clean:
	$(CARGO) clean

help:
	@grep -E '^##' Makefile | sed 's/## //'
