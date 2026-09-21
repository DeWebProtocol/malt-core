.PHONY: all build generate-kzg-setup test vet clean

all: build

build:
	go build -p=6 -buildvcs=false ./...

generate-kzg-setup:
	go generate ./auth/commitment/kzg

test:
	go test -p=6 -parallel=6 ./...

vet:
	go vet -p=6 ./...

clean:
	rm -rf dist/
