package rawcollector

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// RawLogEntry represents a single log line with metadata
type RawLogEntry struct {
	Timestamp time.Time
	Source    string
	Raw       string
}

// RawLogCollector gathers raw log lines without parsing
type RawLogCollector struct {
	logs []RawLogEntry
}

// NewRawLogCollector creates a new raw log collector
func NewRawLogCollector() *RawLogCollector {
	return &RawLogCollector{
		logs: make([]RawLogEntry, 0),
	}
}

// CollectAuditd collects raw auditd log lines
func (r *RawLogCollector) CollectAuditd(auditLogPath string, timeRange TimeRange) error {
	file, err := os.Open(auditLogPath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		
		// Extract timestamp from auditd format
		timestamp := extractAuditdTimestamp(line)
		if !timeRange.Contains(timestamp) {
			continue
		}
		
		r.logs = append(r.logs, RawLogEntry{
			Timestamp: timestamp,
			Source:    "auditd",
			Raw:       line,
		})
	}
	
	return scanner.Err()
}

// CollectJournalctl collects raw journalctl log lines
func (r *RawLogCollector) CollectJournalctl(timeRange TimeRange) error {
	since := timeRange.Start.Format("2006-01-02 15:04:05")
	until := timeRange.End.Format("2006-01-02 15:04:05")
	
	cmd := exec.Command("journalctl", "--since", since, "--until", until, "--output", "short", "--no-pager")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		
		timestamp := extractJournalctlTimestamp(line)
		if !timeRange.Contains(timestamp) {
			continue
		}
		
		r.logs = append(r.logs, RawLogEntry{
			Timestamp: timestamp,
			Source:    "journalctl", 
			Raw:       line,
		})
	}
	
	return scanner.Err()
}

// GetRawLogs returns all collected raw logs sorted by timestamp
func (r *RawLogCollector) GetRawLogs() []RawLogEntry {
	// Sort by timestamp
	for i := 0; i < len(r.logs)-1; i++ {
		for j := i + 1; j < len(r.logs); j++ {
			if r.logs[i].Timestamp.After(r.logs[j].Timestamp) {
				r.logs[i], r.logs[j] = r.logs[j], r.logs[i]
			}
		}
	}
	return r.logs
}

// TimeRange defines a time window
type TimeRange struct {
	Start time.Time
	End   time.Time
}

// Contains checks if timestamp falls within the range
func (tr *TimeRange) Contains(timestamp time.Time) bool {
	return !timestamp.Before(tr.Start) && !timestamp.After(tr.End)
}

func extractAuditdTimestamp(line string) time.Time {
	// Extract from format: type=SYSCALL msg=audit(1640995200.000:123):
	if strings.Contains(line, "msg=audit(") {
		start := strings.Index(line, "msg=audit(") + 10
		end := strings.Index(line[start:], ":")
		if end > 0 {
			timestampStr := line[start : start+end]
			if timestamp, err := strconv.ParseFloat(timestampStr, 64); err == nil {
				return time.Unix(int64(timestamp), 0)
			}
		}
	}
	return time.Now() // fallback
}

func extractJournalctlTimestamp(line string) time.Time {
	// Extract from format: Aug 31 14:04:01 hostname ...
	parts := strings.Split(line, " ")
	if len(parts) >= 3 {
		timeStr := fmt.Sprintf("%s %s %s", parts[0], parts[1], parts[2])
		if timestamp, err := time.Parse("Jan 2 15:04:05", timeStr); err == nil {
			// Set current year
			now := time.Now()
			return time.Date(now.Year(), timestamp.Month(), timestamp.Day(),
				timestamp.Hour(), timestamp.Minute(), timestamp.Second(), 0, now.Location())
		}
	}
	return time.Now() // fallback
}