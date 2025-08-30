package source

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// JournalctlLogSource implements LogSource for systemd journal logs
type JournalctlLogSource struct {
	scanner *bufio.Scanner
}

// NewJournalctlLogSource creates a new journalctl log source
func NewJournalctlLogSource(reader io.Reader) (*JournalctlLogSource, error) {
	return &JournalctlLogSource{
		scanner: bufio.NewScanner(reader),
	}, nil
}

// Name returns the source name
func (j *JournalctlLogSource) Name() string {
	return "journalctl"
}

var journalPattern = regexp.MustCompile(`^(\w+ \d+ \d+:\d+:\d+) (\S+) ([^:]+): (.+)$`)

// ReadEvents reads and converts journalctl events within the time range
func (j *JournalctlLogSource) ReadEvents(timeRange TimeRange) ([]*SystemEvent, error) {
	var systemEvents []*SystemEvent

	for j.scanner.Scan() {
		line := j.scanner.Text()
		if line == "" {
			continue
		}

		event := j.parseLine(line)
		if event == nil {
			continue
		}

		// Filter by time range
		if !timeRange.Contains(event.Timestamp) {
			continue
		}

		systemEvents = append(systemEvents, event)
	}

	if err := j.scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	return systemEvents, nil
}

func (j *JournalctlLogSource) parseLine(line string) *SystemEvent {
	matches := journalPattern.FindStringSubmatch(line)
	if len(matches) != 5 {
		return nil
	}

	timestampStr := matches[1]
	hostname := matches[2]
	process := matches[3]
	message := matches[4]

	// Parse timestamp (Aug 29 14:27:16)
	timestamp, err := time.Parse("Jan 2 15:04:05", timestampStr)
	if err != nil {
		return nil
	}
	// Set current year since syslog format doesn't include year
	timestamp = timestamp.AddDate(time.Now().Year(), 0, 0)

	// Determine event type and action from message
	eventType, action, target := j.categorizeMessage(process, message)

	return &SystemEvent{
		Timestamp: timestamp,
		Source:    "journalctl",
		Type:      eventType,
		User:      hostname, // Use hostname as user context for system events
		Action:    action,
		Target:    target,
		Process:   process,
		Raw:       line,
	}
}

func (j *JournalctlLogSource) categorizeMessage(process, message string) (eventType, action, target string) {
	msg := strings.ToLower(message)

	// Service lifecycle events
	if strings.Contains(process, "systemd[") {
		if strings.Contains(msg, "failed with result") {
			return "service_status", "failed", j.extractServiceName(process, message)
		}
		if strings.Contains(msg, "starting") {
			return "service_status", "starting", j.extractServiceName(process, message)
		}
		if strings.Contains(msg, "started") {
			return "service_status", "started", j.extractServiceName(process, message)
		}
		if strings.Contains(msg, "stopped") {
			return "service_status", "stopped", j.extractServiceName(process, message)
		}
	}

	// Application errors
	if strings.Contains(msg, "error") || strings.Contains(msg, "failed") {
		return "application_error", "error", process
	}

	// Configuration reloads
	if strings.Contains(msg, "reload") || strings.Contains(msg, "configuration") {
		return "config_change", "reload", process
	}

	// Default: generic message
	return "message", "logged", process
}

func (j *JournalctlLogSource) extractServiceName(process, message string) string {
	// Look for service name in message like "nginx.service: Starting..."
	if idx := strings.Index(message, ".service"); idx != -1 {
		start := strings.LastIndex(message[:idx], " ") + 1
		return message[start : idx+8] // Include ".service"
	}
	return process
}

// Close is a no-op for JournalctlLogSource
func (j *JournalctlLogSource) Close() error {
	return nil
}