package audit

import "time"

// AuditEvent represents a parsed auditd log entry
type AuditEvent struct {
	Timestamp time.Time
	Type      string
	Fields    map[string]string
	Raw       string
}

// LogReader defines the interface for reading audit events
type LogReader interface {
	ReadEvent() (*AuditEvent, error)
	Close() error
}