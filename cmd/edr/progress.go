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
	lastRows     int
	pinned       bool
	pinBottom    bool
	closed       bool
	cursorHidden bool
	termWidth    int
}

var terminalSupportsCursorMotion = func(fd uintptr) bool {
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

func newTerminalProgress(out io.Writer, label string) *terminalProgress {
	return newTerminalProgressWithBottomPin(out, label, shouldPinProgress(out))
}

func newTerminalProgressWithPin(out io.Writer, label string, pinned bool) *terminalProgress {
	p := &terminalProgress{
		out:    out,
		label:  strings.TrimSpace(label),
		pinned: pinned,
	}
	if p.pinned {
		p.termWidth = detectTerminalWidth(out)
	}
	return p
}

func newTerminalProgressWithBottomPin(out io.Writer, label string, pinned bool) *terminalProgress {
	p := &terminalProgress{
		out:       out,
		label:     strings.TrimSpace(label),
		pinBottom: pinned,
	}
	return p
}

func shouldPinProgress(out io.Writer) bool {
	if !isPinnedProgressEnabled() {
		return false
	}
	if shouldPinProgressByCapability(out) {
		return true
	}
	return shouldPinProgressByFallback(out)
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

func detectTerminalWidth(out io.Writer) int {
	if out == nil {
		return 0
	}
	fdWriter, ok := out.(interface{ Fd() uintptr })
	if !ok {
		return 0
	}
	fd := fdWriter.Fd()
	if !terminalSupportsCursorMotion(fd) {
		return 0
	}
	if cols, ok := terminalWidth(fd); ok && cols > 0 {
		return cols
	}
	return 0
}

func shouldPinProgressByFallback(out io.Writer) bool {
	if out == nil || runtime.GOOS == "windows" {
		return false
	}
	file, ok := out.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return progressPinnedFallbackEnabled(os.Getenv("TERM"), runtime.GOOS, info.Mode()&os.ModeCharDevice != 0)
}

func shouldPinFilescanProgress(out io.Writer) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("CEYES_PROGRESS_PINNED")))
	switch raw {
	case "0", "false", "no", "off":
		return false
	case "1", "true", "yes", "on":
		if shouldPinProgressByCapability(out) {
			return true
		}
		return shouldPinFilescanProgressByFallback(out)
	}
	if shouldPinProgress(out) {
		return true
	}
	return shouldPinProgressByCapability(out)
}

func shouldPinFilescanProgressByFallback(out io.Writer) bool {
	if out == nil || runtime.GOOS == "windows" {
		return false
	}
	file, ok := out.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return progressPinnedFallbackEnabled(os.Getenv("TERM"), runtime.GOOS, info.Mode()&os.ModeCharDevice != 0)
}

func progressPinnedFallbackEnabled(term, goos string, charDevice bool) bool {
	if goos == "windows" || !charDevice {
		return false
	}
	trimmed := strings.ToLower(strings.TrimSpace(term))
	return trimmed != "" && trimmed != "dumb"
}

func isPinnedProgressEnabled() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("CEYES_PROGRESS_PINNED")))
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	// Default to top-pinned progress when not explicitly disabled.
	return true
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
	if p.pinBottom {
		p.hideCursor()
		p.renderBottomPinnedLine(line)
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
			p.logLines++
		} else {
			fmt.Fprintln(p.out, line)
			p.logLines += p.visualRows(line)
		}
		if p.lastLen > 0 {
			p.renderPinnedLine(p.lastLine)
		}
		return
	}
	if p.pinBottom {
		hadProgress := p.lastLen > 0
		if hadProgress {
			p.clearBottomPinnedLine()
		}
		if line == "" {
			fmt.Fprint(p.out, "\n")
		} else {
			fmt.Fprintln(p.out, line)
		}
		if hadProgress && p.lastLine != "" {
			p.renderBottomPinnedLine(p.lastLine)
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
		} else if p.pinBottom {
			fmt.Fprint(p.out, "\n")
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
	p.lastRows = p.visualRows(line)

	if offset > 0 {
		fmt.Fprintf(p.out, "\x1b[%dB\r", offset)
	}
}

func (p *terminalProgress) hideCursor() {
	if (!p.pinned && !p.pinBottom) || p.cursorHidden {
		return
	}
	fmt.Fprint(p.out, "\x1b[?25l")
	p.cursorHidden = true
}

func (p *terminalProgress) clearBottomPinnedLine() {
	padding := ""
	if p.lastLen > 0 {
		padding = strings.Repeat(" ", p.lastLen)
	}
	fmt.Fprint(p.out, "\r"+padding+"\r")
	p.lastLen = 0
	p.lastLine = ""
	p.lastRows = 0
}

func (p *terminalProgress) renderBottomPinnedLine(line string) {
	padding := ""
	if p.lastLen > len(line) {
		padding = strings.Repeat(" ", p.lastLen-len(line))
	}
	fmt.Fprint(p.out, "\r"+line+padding)
	p.lastLen = len(line)
	p.lastLine = line
	p.lastRows = 1
}

func (p *terminalProgress) visualRows(line string) int {
	if line == "" {
		return 1
	}
	width := p.termWidth
	if width <= 0 {
		return 1
	}
	rows := 1
	col := 0
	for _, r := range line {
		if r == '\n' {
			rows++
			col = 0
			continue
		}
		col++
		if col > width {
			rows++
			col = 1
		}
	}
	return rows
}
