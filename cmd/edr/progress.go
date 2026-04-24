package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/mattn/go-isatty"
)

type terminalProgress struct {
	mu           sync.Mutex
	out          io.Writer
	label        string
	lastLen      int
	lastLine     string
	logLines     int
	pinned       bool
	closed       bool
	cursorHidden bool
}

var terminalSupportsCursorMotion = func(fd uintptr) bool {
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

func newTerminalProgress(out io.Writer, label string) *terminalProgress {
	return newTerminalProgressWithPin(out, label, shouldPinProgress(out))
}

func newTerminalProgressWithPin(out io.Writer, label string, pinned bool) *terminalProgress {
	return &terminalProgress{
		out:    out,
		label:  strings.TrimSpace(label),
		pinned: pinned,
	}
}

func shouldPinProgress(out io.Writer) bool {
	if !isPinnedProgressEnabled() {
		return false
	}
	return shouldPinProgressByCapability(out)
}

func shouldPinProgressByCapability(out io.Writer) bool {
	if out == nil {
		return false
	}
	fdWriter, ok := out.(interface{ Fd() uintptr })
	if !ok {
		return false
	}
	fd := fdWriter.Fd()
	if !terminalSupportsCursorMotion(fd) {
		return false
	}
	return enableProgressANSIMode(fd)
}

func shouldPinFilescanProgress(out io.Writer) bool {
	if shouldPinProgress(out) {
		return true
	}
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("CEYES_PROGRESS_PINNED")))
	switch raw {
	case "0", "false", "no", "off":
		return false
	}
	return shouldPinProgressByCapability(out)
}

func isPinnedProgressEnabled() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("CEYES_PROGRESS_PINNED")))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	// Top-pinned redraw relies on frequent cursor up/down moves, which visibly
	// jitters in Windows terminals. Keep it off by default on Windows.
	return runtime.GOOS != "windows"
}

func (p *terminalProgress) Update(done, total int, stage string) {
	if p == nil || p.out == nil || p.closed || total <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if done < 0 {
		done = 0
	}
	if done > total {
		done = total
	}
	percent := int(float64(done) / float64(total) * 100)
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	barWidth := 26
	filled := int(float64(percent) / 100 * float64(barWidth))
	if filled < 0 {
		filled = 0
	}
	if filled > barWidth {
		filled = barWidth
	}
	bar := strings.Repeat("=", filled) + strings.Repeat("-", barWidth-filled)

	stage = strings.TrimSpace(stage)
	if stage != "" {
		stage = " | " + stage
	}
	line := fmt.Sprintf("%s [%s] %3d%% (%d/%d)%s", p.label, bar, percent, done, total, stage)
	if p.pinned {
		p.hideCursor()
		p.renderPinnedLine(line)
		return
	}

	padding := ""
	if p.lastLen > len(line) {
		padding = strings.Repeat(" ", p.lastLen-len(line))
	}
	fmt.Fprint(p.out, "\r"+line+padding)
	p.lastLen = len(line)
	p.lastLine = line
}

func (p *terminalProgress) PrintLine(line string) {
	if p == nil || p.out == nil {
		return
	}
	line = strings.TrimRight(line, "\r\n")

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.pinned {
		if p.logLines == 0 {
			// Reserve the first row for progress, even if logs arrive before the first Update.
			fmt.Fprint(p.out, "\n")
		}
		if line == "" {
			fmt.Fprint(p.out, "\n")
		} else {
			fmt.Fprintln(p.out, line)
		}
		p.logLines++
		if p.lastLen > 0 {
			p.renderPinnedLine(p.lastLine)
		}
		return
	}

	if p.lastLen > 0 {
		// Clear the in-place progress row before emitting a standalone line.
		fmt.Fprint(p.out, "\r"+strings.Repeat(" ", p.lastLen)+"\r")
		p.lastLen = 0
		p.lastLine = ""
	}
	if line == "" {
		fmt.Fprint(p.out, "\n")
		return
	}
	fmt.Fprintln(p.out, line)
}

func (p *terminalProgress) Done() {
	if p == nil || p.out == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	if p.lastLen > 0 {
		if p.pinned {
			if p.logLines == 0 {
				fmt.Fprint(p.out, "\n")
			}
		} else {
			fmt.Fprint(p.out, "\n")
		}
	}
	if p.cursorHidden {
		fmt.Fprint(p.out, "\x1b[?25h")
		p.cursorHidden = false
	}
}

func (p *terminalProgress) renderPinnedLine(line string) {
	offset := 0
	if p.logLines > 0 {
		offset = p.logLines + 1
	}
	if offset > 0 {
		fmt.Fprintf(p.out, "\x1b[%dA", offset)
	}

	padding := ""
	if p.lastLen > len(line) {
		padding = strings.Repeat(" ", p.lastLen-len(line))
	}
	fmt.Fprint(p.out, "\r"+line+padding)
	p.lastLen = len(line)
	p.lastLine = line

	if offset > 0 {
		fmt.Fprintf(p.out, "\x1b[%dB\r", offset)
	}
}

func (p *terminalProgress) hideCursor() {
	if !p.pinned || p.cursorHidden {
		return
	}
	fmt.Fprint(p.out, "\x1b[?25l")
	p.cursorHidden = true
}
