package main

import (
	"fmt"
	"os"
	"time"
)

// Minimal, dependency-free ANSI helpers. sxctl only colors output when
// stdout looks like a real terminal and NO_COLOR isn't set — scripts piping
// `sxctl list --json` (or any output through `| cat`) never see escape
// codes, so it stays safe for automation.
var colorEnabled = isTTY(os.Stdout) && os.Getenv("NO_COLOR") == ""

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

const (
	ansiReset = "\033[0m"
	ansiBold  = "\033[1m"
	ansiDim   = "\033[2m"
	ansiRed   = "\033[38;5;174m" // muted red, matches dashboard palette
	ansiGreen = "\033[38;5;108m" // muted green
	ansiAmber = "\033[38;5;179m" // muted amber
	ansiCyan  = "\033[38;5;73m"
	ansiGray  = "\033[38;5;244m"
)

func colorize(code, s string) string {
	if !colorEnabled {
		return s
	}
	return code + s + ansiReset
}

func bold(s string) string  { return colorize(ansiBold, s) }
func dim(s string) string   { return colorize(ansiDim, s) }
func red(s string) string   { return colorize(ansiRed, s) }
func green(s string) string { return colorize(ansiGreen, s) }
func amber(s string) string { return colorize(ansiAmber, s) }
func cyan(s string) string  { return colorize(ansiCyan, s) }
func gray(s string) string  { return colorize(ansiGray, s) }

// reasonColor maps a firewall reason string to the color the dashboard
// uses for it, so `sxctl list`/`sxctl why` visually match the web UI.
func reasonColor(reason string) string {
	switch reason {
	case "manual":
		return ansiCyan
	case "rate-limit":
		return ansiAmber
	case "anomaly":
		return ansiRed
	case "threat-intel":
		return ansiRed
	case "syn-flood":
		return ansiRed
	case "port-knock":
		return ansiAmber
	case "dns-block":
		return ansiCyan
	case "geoip":
		return ansiCyan
	default:
		return ansiGray
	}
}

func colorReason(reason string) string {
	if reason == "" {
		reason = "none"
	}
	return colorize(reasonColor(reason), reason)
}

// spinner is a tiny, dependency-free progress spinner for commands that do
// real work (benchmark, policy apply, controller push) so the CLI never
// looks like it's hung. Call stop() when the work is done; it clears the
// line and, if msg != "", prints a final status line.
func spinner(label string) (stop func(finalMsg string, ok bool)) {
	if !colorEnabled {
		fmt.Println(label + "...")
		return func(finalMsg string, ok bool) {
			if finalMsg != "" {
				fmt.Println(finalMsg)
			}
		}
	}

	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	done := make(chan struct{})
	go func() {
		i := 0
		for {
			select {
			case <-done:
				return
			default:
				fmt.Printf("\r%s %s", cyan(frames[i%len(frames)]), label)
				i++
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()

	return func(finalMsg string, ok bool) {
		close(done)
		fmt.Print("\r\033[K") // clear the spinner line
		if finalMsg == "" {
			return
		}
		mark := green("✓")
		if !ok {
			mark = red("✗")
		}
		fmt.Printf("%s %s\n", mark, finalMsg)
	}
}
