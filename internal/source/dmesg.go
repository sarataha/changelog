package source

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// DmesgLogSource implements LogSource for kernel dmesg logs
type DmesgLogSource struct {
	scanner *bufio.Scanner
}

// NewDmesgLogSource creates a new dmesg log source
func NewDmesgLogSource(reader io.Reader) (*DmesgLogSource, error) {
	return &DmesgLogSource{
		scanner: bufio.NewScanner(reader),
	}, nil
}

// Name returns the source name
func (d *DmesgLogSource) Name() string {
	return "dmesg"
}

var dmesgPattern = regexp.MustCompile(`^\[(\w+ ?\d+ ?\d+:\d+:\d+)\] (.+)$`)
var oomPattern = regexp.MustCompile(`Out of memory: Kill process (\d+) \(([^)]+)\)`)
var killedPattern = regexp.MustCompile(`Killed process (\d+) \(([^)]+)\)`)

// ReadEvents reads and converts dmesg events within the time range
func (d *DmesgLogSource) ReadEvents(timeRange TimeRange) ([]*SystemEvent, error) {
	var systemEvents []*SystemEvent

	for d.scanner.Scan() {
		line := d.scanner.Text()
		if line == "" {
			continue
		}

		event := d.parseLine(line)
		if event == nil {
			continue
		}

		// Filter by time range
		if !timeRange.Contains(event.Timestamp) {
			continue
		}

		systemEvents = append(systemEvents, event)
	}

	if err := d.scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	return systemEvents, nil
}

func (d *DmesgLogSource) parseLine(line string) *SystemEvent {
	matches := dmesgPattern.FindStringSubmatch(line)
	if len(matches) != 3 {
		return nil
	}

	timestampStr := matches[1]
	message := matches[2]

	// Parse timestamp (Aug29 14:27:15 or Aug 29 14:27:15)
	timestamp, err := d.parseTimestamp(timestampStr)
	if err != nil {
		return nil
	}

	// Categorize the kernel message
	eventType, action, target := d.categorizeMessage(message)

	return &SystemEvent{
		Timestamp: timestamp,
		Source:    "dmesg",
		Type:      eventType,
		User:      "kernel",
		Action:    action,
		Target:    target,
		Process:   "kernel",
		Raw:       line,
	}
}

func (d *DmesgLogSource) parseTimestamp(timestampStr string) (time.Time, error) {
	// Try different dmesg timestamp formats
	formats := []string{
		"Jan2 15:04:05",   // Aug29 14:27:15
		"Jan 2 15:04:05",  // Aug 29 14:27:15
	}

	for _, format := range formats {
		if timestamp, err := time.Parse(format, timestampStr); err == nil {
			// Set current year since dmesg doesn't include year
			return timestamp.AddDate(time.Now().Year(), 0, 0), nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse timestamp: %s", timestampStr)
}

func (d *DmesgLogSource) categorizeMessage(message string) (eventType, action, target string) {
	msg := strings.ToLower(message)

	// OOM killer events
	if oomMatches := oomPattern.FindStringSubmatch(message); len(oomMatches) == 3 {
		pid := oomMatches[1]
		process := oomMatches[2]
		return "kernel_oom", "oom_kill", fmt.Sprintf("%s (pid %s)", process, pid)
	}

	if killedMatches := killedPattern.FindStringSubmatch(message); len(killedMatches) == 3 {
		pid := killedMatches[1]
		process := killedMatches[2]
		return "kernel_oom", "killed", fmt.Sprintf("%s (pid %s)", process, pid)
	}

	// Filesystem events
	if strings.Contains(msg, "mounted filesystem") {
		return "filesystem", "mounted", d.extractFilesystem(message)
	}

	// Hardware events
	if strings.Contains(msg, "usb disconnect") || strings.Contains(msg, "usb connect") {
		action := "disconnect"
		if strings.Contains(msg, "connect") {
			action = "connect"
		}
		return "hardware", action, "usb_device"
	}

	// Generic kernel message
	return "kernel_message", "logged", "system"
}

func (d *DmesgLogSource) extractFilesystem(message string) string {
	// Extract filesystem from "EXT4-fs (sda1): mounted..."
	if idx := strings.Index(message, "):"); idx != -1 {
		start := strings.Index(message, "(")
		if start != -1 {
			return message[start+1 : idx]
		}
	}
	return "filesystem"
}

// Close is a no-op for DmesgLogSource
func (d *DmesgLogSource) Close() error {
	return nil
}