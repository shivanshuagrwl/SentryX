//go:build windows

package main

import (
	"os"
	"path/filepath"
)

// browserPaths returns the well-known install locations Edge/Chrome use on
// Windows. Edge ships on every Windows 10/11 box by default, so this is
// what makes "app-style window, no extra install" actually true out of the
// box rather than only working if the operator happens to have Chrome.
func browserPaths() []string {
	pf := os.Getenv("ProgramFiles")
	pf86 := os.Getenv("ProgramFiles(x86)")
	localAppData := os.Getenv("LocalAppData")

	var paths []string
	add := func(base, rel string) {
		if base == "" {
			return
		}
		paths = append(paths, filepath.Join(base, rel))
	}

	// Edge (built into Windows 10/11 — the most reliable candidate)
	add(pf86, `Microsoft\Edge\Application\msedge.exe`)
	add(pf, `Microsoft\Edge\Application\msedge.exe`)

	// Chrome, if installed
	add(pf, `Google\Chrome\Application\chrome.exe`)
	add(pf86, `Google\Chrome\Application\chrome.exe`)
	add(localAppData, `Google\Chrome\Application\chrome.exe`)

	return paths
}
