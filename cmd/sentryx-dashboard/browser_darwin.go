//go:build darwin

package main

// browserPaths returns the well-known /Applications locations for
// Chromium-family browsers on macOS. Safari has no --app= equivalent, so
// it's deliberately not in this list — if none of these exist,
// openInDefaultBrowser's `open` fallback lands the operator on Safari (or
// whatever their default is) as a normal tab, which is still fine, just
// not chromeless.
func browserPaths() []string {
	return []string{
		"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
		"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
	}
}
