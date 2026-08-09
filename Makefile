.PHONY: all build build-verifier-wasm build-wasm-release test vet clean

all: build

build:
	go build -buildvcs=false ./...

build-verifier-wasm:
	./scripts/build-verifier-wasm.sh dist/verifier

build-wasm-release:
	@test -n "$(VERSION)" || { echo "set VERSION=vX.Y.Z" >&2; exit 1; }
	./scripts/build-wasm-release.sh "$(VERSION)" dist/wasm-release

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf dist/
