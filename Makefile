.PHONY: build ipxe components check verify smoke smoke-injected smoke-server smoke-control-plane smoke-pxe

build:
	./scripts/build.sh

ipxe:
	./scripts/build-ipxe.sh

check:
	./scripts/check.sh
	python3 -m py_compile scripts/verify-image.py scripts/smoke-test.py scripts/test-injection.py scripts/test-server.py scripts/test-control-plane.py scripts/test-pxe.py
	go test -race ./...
	go vet ./...

verify:
	python3 scripts/verify-image.py dist/hcos-base.efi

smoke:
	python3 scripts/smoke-test.py dist/hcos-base.efi

smoke-injected:
	python3 scripts/test-injection.py dist/hcos-base.efi

components:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/hcos-server ./cmd/hcos-server
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/hcos-controller ./cmd/hcos-controller
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/hcos-agent ./cmd/hcos-agent

smoke-server:
	python3 scripts/test-server.py dist/hcos-base.efi

smoke-control-plane: components
	python3 scripts/test-control-plane.py

smoke-pxe: components
	python3 scripts/test-pxe.py
