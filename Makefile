IFACE       ?= eth0
BPF_SRC     := bpf/xdp_sentryx.c
BPF_OBJ     := bpf/xdp_sentryx.o
DAEMON_BIN  := bin/sentryxd
CLI_BIN     := bin/sxctl
SETUP_BIN   := bin/sentryx-setup
DASH_BIN    := bin/sentryx-dashboard
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
DIST        := dist

.PHONY: all bpf daemon cli setup dashboard run clean deps install dist

all: bpf daemon cli setup dashboard

## Compile the XDP program to BPF bytecode (Linux only — Windows/macOS
## builds never touch this, see internal/firewall's package docs)
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c $< -o $@

## Build the control daemon
daemon:
	go build -o $(DAEMON_BIN) ./cmd/sentryxd

## Build the CLI
cli:
	go build -o $(CLI_BIN) ./cmd/sxctl

## Build the Phase 28 GUI installer (double-click → wizard → running)
setup:
	go build -ldflags "-X main.version=$(VERSION)" -o $(SETUP_BIN) ./cmd/sentryx-setup

## Build the dashboard launcher — the Start Menu/Applications/Dock icon
## the operator double-clicks *after* setup, opening the dashboard as its
## own app-style window instead of a localhost browser tab (see
## cmd/sentryx-dashboard's package docs)
dashboard:
	go build -ldflags "-X main.version=$(VERSION)" -o $(DASH_BIN) ./cmd/sentryx-dashboard

## Run the daemon against $(IFACE) in insecure (local dev) mode
run: all
	sudo ./$(DAEMON_BIN) -iface $(IFACE) -obj $(BPF_OBJ) -insecure

## Install build dependencies (Debian/Ubuntu)
deps:
	sudo apt-get update && sudo apt-get install -y clang llvm libbpf-dev linux-headers-$$(uname -r) bpftool
	go mod download

## Build everything and install it system-wide as a systemd service
## (binaries -> /usr/local/bin, config -> /etc/sentryx, data -> /var/lib/sentryx)
install:
	sudo ./scripts/install.sh -i $(IFACE)

## Phase 27.3 — cross-compiled release binaries for every OS/arch sxctl
## itself claims to support. Filenames match what cmd/sentryx-setup's
## fetch.go and scripts/install.sh both look for
## (sentryxd-<os>-<arch>[.exe], sxctl-<os>-<arch>[.exe]) — keep this list
## and those two files' naming convention in sync if either changes.
## Note: the bpf/*.o object is Linux-only and isn't part of this matrix —
## Windows/macOS binaries fall back to their OS-native firewall backend
## and never load it (see internal/firewall/firewall_{windows,darwin}.go).
dist:
	mkdir -p $(DIST)
	GOOS=linux   GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/sentryxd-linux-amd64        ./cmd/sentryxd
	GOOS=linux   GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/sentryxd-linux-arm64        ./cmd/sentryxd
	GOOS=windows GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/sentryxd-windows-amd64.exe  ./cmd/sentryxd
	GOOS=darwin  GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/sentryxd-darwin-amd64      ./cmd/sentryxd
	GOOS=darwin  GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/sentryxd-darwin-arm64      ./cmd/sentryxd
	GOOS=linux   GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/sxctl-linux-amd64          ./cmd/sxctl
	GOOS=linux   GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/sxctl-linux-arm64          ./cmd/sxctl
	GOOS=windows GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/sxctl-windows-amd64.exe    ./cmd/sxctl
	GOOS=darwin  GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/sxctl-darwin-amd64        ./cmd/sxctl
	GOOS=darwin  GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/sxctl-darwin-arm64        ./cmd/sxctl
	GOOS=linux   GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/sentryx-setup-linux-amd64       ./cmd/sentryx-setup
	GOOS=windows GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/sentryx-setup-windows-amd64.exe ./cmd/sentryx-setup
	# ^ picks up cmd/sentryx-setup/rsrc_windows_amd64.syso automatically (no
	#   extra flag needed), embedding the requireAdministrator manifest so
	#   this always UAC-prompts instead of failing later with "sc.exe
	#   create failed ... Access is denied". Regenerate that .syso with
	#   `rsrc -manifest cmd/sentryx-setup/sentryx-setup.manifest -o cmd/sentryx-setup/rsrc_windows_amd64.syso`
	#   if sentryx-setup.manifest ever changes.
	GOOS=darwin  GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/sentryx-setup-darwin-arm64     ./cmd/sentryx-setup
	GOOS=linux   GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/sentryx-dashboard-linux-amd64       ./cmd/sentryx-dashboard
	GOOS=windows GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/sentryx-dashboard-windows-amd64.exe ./cmd/sentryx-dashboard
	GOOS=darwin  GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o $(DIST)/sentryx-dashboard-darwin-arm64     ./cmd/sentryx-dashboard

clean:
	rm -f $(BPF_OBJ) $(DAEMON_BIN) $(CLI_BIN) $(SETUP_BIN) $(DASH_BIN)
	rm -rf $(DIST)
