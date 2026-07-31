//go:build windows

// This file is what makes `sc.exe create SENTRYXD ... start=auto` (see
// cmd/sentryx-setup/install_windows.go) actually work. Without it,
// sentryxd is a perfectly good console program that Windows' Service
// Control Manager can launch — but SCM then waits for it to perform a
// specific handshake (register a control handler, report StartPending
// then Running) before it considers the service "started," and a plain
// console app never sends that handshake at all. SCM eventually gives up
// and Windows reports error 1053: "the service did not respond to the
// start or control request in a timely fashion" — exactly the symptom
// this file exists to fix.
package main

import (
	"context"
	"sync"

	"golang.org/x/sys/windows/svc"
)

// winSvcHandler implements svc.Handler by running sentryxd's normal
// startup/shutdown lifecycle (run, from main.go) inside the goroutine SCM
// expects, and translating SCM's Stop/Shutdown control requests into a
// context cancellation — the same signal run() already knows how to react
// to when launched normally via os/signal.
type winSvcHandler struct {
	run func(ctx context.Context)
}

func (h *winSvcHandler) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var once sync.Once
	go func() {
		h.run(ctx)
		close(done)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		req := <-r
		switch req.Cmd {
		case svc.Interrogate:
			changes <- req.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			once.Do(cancel)
			<-done // wait for run()'s own graceful-shutdown path to finish
			return false, 0
		}
	}
}

// runAsWindowsService reports whether this process was actually launched
// by the Service Control Manager (as opposed to a terminal, a double
// click, or `go run`). If so, it performs the full SCM handshake and
// blocks here — driving run via ctx cancellation on Stop/Shutdown — until
// the service is told to stop, then returns true so main.go's normal
// os/signal-driven path is skipped entirely. If this process wasn't
// launched by SCM, it returns false immediately and changes nothing.
func runAsWindowsService(run func(ctx context.Context)) bool {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false
	}
	_ = svc.Run("SENTRYXD", &winSvcHandler{run: run})
	return true
}
