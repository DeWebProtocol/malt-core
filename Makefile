.PHONY: all build build-verifier-wasm build-wasm-release generate-kzg-setup test vet clean

all: build

build:
	go build -buildvcs=false ./...

build-verifier-wasm:
	./scripts/build-verifier-wasm.sh dist/verifier

build-wasm-release:
	@test -n "$(VERSION)" || { echo "set VERSION=vX.Y.Z" >&2; exit 1; }
	./scripts/build-wasm-release.sh "$(VERSION)" dist/wasm-release

generate-kzg-setup:
	go generate ./auth/commitment/kzg

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf dist/
