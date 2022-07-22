PWD = $(shell pwd)

build-docker-bin:
	docker run --rm -it -v $(PWD):/Documents/bhcli -w /Documents/bhcli bhcli sh -c \
		'CARGO_TARGET_DIR=./target/linux cargo build --release'

build-darwin:
	cargo build --release
	cp target/release/bhcli dist/bhcli.darwin.amd64
	tar -czvf dist/bhcli.darwin.amd64.tar.gz dist/bhcli.darwin.amd64
	openssl dgst -sha256 dist/bhcli.darwin.amd64.tar.gz | cut -d ' ' -f 2 > dist/bhcli.darwin.amd64.tar.gz.checksum
	rm dist/bhcli.darwin.amd64

build-linux: build-docker-bin
	cp target/linux/release/bhcli dist/bhcli.linux.amd64
	tar -czvf dist/bhcli.linux.amd64.tar.gz dist/bhcli.linux.amd64
	openssl dgst -sha256 dist/bhcli.linux.amd64.tar.gz | cut -d ' ' -f 2 > dist/bhcli.linux.amd64.tar.gz.checksum
	rm dist/bhcli.linux.amd64

cross-compile-windows:
	cargo build --release --target x86_64-pc-windows-gnu
	cp target/x86_64-pc-windows-gnu/release/bhcli.exe dist/bhcli.windows.amd64.exe
	zip       dist/bhcli.windows.amd64.zip   dist/bhcli.windows.amd64.exe
	openssl dgst -sha256 dist/bhcli.windows.amd64.zip   | cut -d ' ' -f 2 > dist/bhcli.windows.amd64.zip.checksum
	rm dist/bhcli.windows.amd64.exe

process-windows:
	zip       dist/bhcli.windows.amd64.zip   dist/bhcli.exe
	openssl dgst -sha256 dist/bhcli.windows.amd64.zip   | cut -d ' ' -f 2 > dist/bhcli.windows.amd64.zip.checksum
	rm dist/bhcli.exe

rsync:
	rsync --recursive --times --compress --progress dist/ torsv:/root/dist/downloads-bhcli

deploy: build-darwin cross-compile-windows build-linux rsync

.PHONY: build-darwin process-windows cross-compile-windows rsync
