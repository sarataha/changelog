package source

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// FileLogSource implements LogSource for generic application log files
type FileLogSource struct {
	scanner *bufio.Scanner
	name    string
}

// NewFileLogSource creates a new file log source
func NewFileLogSource(reader io.Reader, name string) (*FileLogSource, error) {
	return &FileLogSource{
		scanner: bufio.NewScanner(reader),
		name:    name,
	}, nil
}

// Name returns the source name
func (f *FileLogSource) Name() string {
	return f.name
}

var timestampPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})`),        // 2025/08/29 14:27:15
	regexp.MustCompile(`^(\w+ \d+ \d{2}:\d{2}:\d{2})`),                  // Aug 29 14:27:15
	regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d]*Z?)`), // 2025-08-29T14:28:01.123Z
}

// ReadEvents reads and converts application log events within the time range
func (f *FileLogSource) ReadEvents(timeRange TimeRange) ([]*SystemEvent, error) {
	var systemEvents []*SystemEvent

	for f.scanner.Scan() {
		line := f.scanner.Text()
		if line == "" {
			continue
		}

		event := f.parseLine(line)
		if event == nil {
			continue
		}

		// Filter by time range
		if !timeRange.Contains(event.Timestamp) {
			continue
		}

		systemEvents = append(systemEvents, event)
	}

	if err := f.scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanner error: %w", err)
	}

	return systemEvents, nil
}

func (f *FileLogSource) parseLine(line string) *SystemEvent {
	timestamp, remaining := f.extractTimestamp(line)
	if timestamp.IsZero() {
		return nil
	}

	// Categorize the log message
	eventType, action, target := f.categorizeMessage(remaining)

	return &SystemEvent{
		Timestamp: timestamp,
		Source:    f.name,
		Type:      eventType,
		User:      f.name, // Use app name as user context
		Action:    action,
		Target:    target,
		Process:   f.name,
		Raw:       line,
	}
}

func (f *FileLogSource) extractTimestamp(line string) (time.Time, string) {
	for _, pattern := range timestampPatterns {
		matches := pattern.FindStringSubmatch(line)
		if len(matches) >= 2 {
			timestampStr := matches[1]
			remaining := line[len(matches[0]):]
			
			timestamp, err := f.parseTimestamp(timestampStr)
			if err == nil {
				return timestamp, strings.TrimSpace(remaining)
			}
		}
	}
	return time.Time{}, line
}

func (f *FileLogSource) parseTimestamp(timestampStr string) (time.Time, error) {
	formats := []string{
		"2006/01/02 15:04:05",
		"Jan 2 15:04:05",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
	}

	for _, format := range formats {
		if timestamp, err := time.Parse(format, timestampStr); err == nil {
			// Set current year for formats without year
			if timestamp.Year() == 0 {
				timestamp = timestamp.AddDate(time.Now().Year(), 0, 0)
			}
			return timestamp, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse timestamp: %s", timestampStr)
}

func (f *FileLogSource) categorizeMessage(message string) (eventType, action, target string) {
	msg := strings.ToLower(message)

	// Error levels
	if strings.Contains(msg, "[error]") || strings.Contains(msg, "error") {
		if strings.Contains(msg, "connection refused") || strings.Contains(msg, "connect() failed") {
			return "application_error", "connection_failed", "upstream"
		}
		return "application_error", "error", f.extractTarget(message)
	}

	// Warning levels
	if strings.Contains(msg, "[warn]") || strings.Contains(msg, "warning") {
		if strings.Contains(msg, "exited on signal") {
			return "application_lifecycle", "process_killed", f.extractTarget(message)
		}
		return "application_warning", "warning", f.extractTarget(message)
	}

	// Lifecycle events
	if strings.Contains(msg, "starting") || strings.Contains(msg, "started") {
		return "application_lifecycle", "started", f.name
	}

	if strings.Contains(msg, "shutting down") || strings.Contains(msg, "shutdown") {
		return "application_lifecycle", "shutdown", f.name
	}

	if strings.Contains(msg, "configuration") && (strings.Contains(msg, "test") || strings.Contains(msg, "reload")) {
		return "application_config", "config_test", f.name
	}

	// Generic info
	return "application_info", "logged", f.extractTarget(message)
}

func (f *FileLogSource) extractTarget(message string) string {
	// Try to extract meaningful target from message
	words := strings.Fields(message)
	if len(words) > 5 {
		return strings.Join(words[:5], " ") + "..."
	}
	return strings.Join(words, " ")
}

// Close is a no-op for FileLogSource
func (f *FileLogSource) Close() error {
	return nil
}