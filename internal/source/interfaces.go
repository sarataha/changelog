package source

import (
	"fmt"
	"time"
)

// SystemEvent represents a unified event from any log source
type SystemEvent struct {
	Timestamp time.Time
	Source    string // "auditd", "journalctl", "dmesg", etc.
	Type      string // event type specific to source
	User      string
	Action    string
	Target    string // file, command, service, etc.
	Process   string
	Raw       string // original log line
}

// GetKey returns a unique identifier for correlation
func (e *SystemEvent) GetKey() string {
	return fmt.Sprintf("%s-%s-%s-%s", e.Source, e.Type, e.User, e.Action)
}

// TimeRange defines a time window for event filtering
type TimeRange struct {
	Start time.Time
	End   time.Time
}

// Contains checks if timestamp falls within the range
func (tr *TimeRange) Contains(timestamp time.Time) bool {
	return !timestamp.Before(tr.Start) && !timestamp.After(tr.End)
}

// LogSource interface for reading events from different log sources
type LogSource interface {
	Name() string
	ReadEvents(timeRange TimeRange) ([]*SystemEvent, error)
	Close() error
}