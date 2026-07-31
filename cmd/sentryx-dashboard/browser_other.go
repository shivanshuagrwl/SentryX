//go:build !windows && !darwin

package main

// browserPaths is a no-op on Linux and other Unix-likes: distro package
// managers put browser binaries on PATH (google-chrome, chromium-browser,
// etc.), which appModeCandidates already tries by name, so there's no
// well-known absolute path worth guessing here the way Windows/macOS need.
func browserPaths() []string {
	return nil
}
