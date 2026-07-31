//go:build !windows

package main

import "context"

// runAsWindowsService always reports false here — the Windows Service
// Control Manager handshake only exists on Windows; see
// service_windows.go for the real implementation. On Linux/macOS,
// main.go's normal os/signal-driven path (systemd/launchd send a real
// SIGTERM, which os/signal already handles) is all that's ever needed.
func runAsWindowsService(run func(ctx context.Context)) bool { return false }
