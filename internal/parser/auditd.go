package parser

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sarataha/changelog/internal/audit"
)

// AuditdParser handles parsing raw auditd log lines
type AuditdParser struct {
	headerRegex *regexp.Regexp
	fieldRegex  *regexp.Regexp
}

// NewAuditdParser creates a new auditd parser
func NewAuditdParser() *AuditdParser {
	return &AuditdParser{
		// Parse: type=SYSCALL msg=audit(1640995200.000:123):
		headerRegex: regexp.MustCompile(`type=(\w+)\s+msg=audit\(([0-9.]+):([0-9]+)\):`),
		// Parse: key=value pairs including quoted values
		fieldRegex: regexp.MustCompile(`(\w+)=("([^"]*)"|([^\s]+))`),
	}
}

// ParseLine parses a single auditd log line into an AuditEvent
func (p *AuditdParser) ParseLine(line string) (*audit.AuditEvent, error) {
	if strings.TrimSpace(line) == "" {
		return nil, fmt.Errorf("empty line")
	}

	event := &audit.AuditEvent{
		Fields: make(map[string]string),
		Raw:    line,
	}

	// Parse header (type and timestamp)
	headerMatch := p.headerRegex.FindStringSubmatch(line)
	if len(headerMatch) < 4 {
		return nil, fmt.Errorf("invalid auditd header format")
	}

	event.Type = headerMatch[1]

	// Parse timestamp from epoch with milliseconds
	timestampStr := headerMatch[2]
	timestamp, err := strconv.ParseFloat(timestampStr, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp: %w", err)
	}
	
	// Convert to time.Time with proper nanosecond precision
	seconds := int64(timestamp)
	nanoseconds := int64((timestamp - float64(seconds)) * 1e9)
	event.Timestamp = time.Unix(seconds, nanoseconds)

	// Parse all key=value fields (both quoted and unquoted)
	fieldMatches := p.fieldRegex.FindAllStringSubmatch(line, -1)
	for _, match := range fieldMatches {
		if len(match) >= 5 {
			key := match[1]
			var value string
			
			// Check if value was quoted (group 3) or unquoted (group 4)
			if match[3] != "" {
				value = match[3] // quoted value
			} else {
				value = match[4] // unquoted value
			}
			
			event.Fields[key] = value
		}
	}

	return event, nil
}