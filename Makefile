CONFIG ?= config.toml
NEXT_API_DIR := next-api
.DEFAULT_GOAL := build

.PHONY: help build check fmt clippy test run run-debug clean

help:
	@echo "available commands: build check fmt clippy test run run-debug clean"

build:
	cargo build --release

check:
	cargo check

fmt:
	cargo fmt

clippy:
	cargo clippy --all-targets -- -D warnings

test:
	cargo test

run:
	cargo run --release -- --config $(CONFIG)

run-debug:
	cargo run -- --config $(CONFIG)

clean:
	cargo clean
