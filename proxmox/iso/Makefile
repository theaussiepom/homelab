.DEFAULT_GOAL := help
.NOTPARALLEL:
.PHONY: help tools init fetch prepare unit fixture test-boot test build password-hash test-profile qualify usb-list usb-inspect usb-check usb-write
help:
	@echo "Start here: README.md"
	@echo "Practice: make tools init fetch unit fixture test-boot"
	@echo "Your machine: edit .local/ settings; make password-hash build test-profile qualify"
	@echo "USB (macOS): make usb-list; then usb-inspect, usb-check, usb-write with USB=/dev/diskN"
tools init fetch prepare unit fixture test-boot password-hash test-profile qualify:
	@./scripts/run.sh $@
test: unit test-boot
build:
	@./scripts/run.sh build-production
usb-list:
	diskutil list external physical
usb-inspect:
	@test -n "$(USB)" || { echo "Choose the USB explicitly: make usb-inspect USB=/dev/diskN"; exit 2; }
	/usr/bin/python3 scripts/write-usb.py --inspect "$(USB)" --save .local/usb.json
usb-check:
	@test -n "$(USB)" || { echo "Choose the USB explicitly: make usb-check USB=/dev/diskN"; exit 2; }
	/usr/bin/python3 scripts/write-usb.py --device "$(USB)"
usb-write:
	@test -n "$(USB)" || { echo "Choose the USB explicitly: make usb-write USB=/dev/diskN"; exit 2; }
	sudo /usr/bin/python3 scripts/write-usb.py --device "$(USB)" --write
