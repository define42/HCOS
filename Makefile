.PHONY: build check verify smoke

build:
	./scripts/build.sh

check:
	./scripts/check.sh
	python3 -m py_compile scripts/verify-image.py scripts/smoke-test.py

verify:
	python3 scripts/verify-image.py dist/hcos.efi

smoke:
	python3 scripts/smoke-test.py dist/hcos.efi
