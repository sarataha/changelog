package parser

import (
	"testing"
	"time"

	"github.com/sarataha/changelog/internal/audit"
)

func TestAuditdParser_ParseLine(t *testing.T) {
	parser := NewAuditdParser()

	tests := []struct {
		name     string
		input    string
		expected *audit.AuditEvent
		wantErr  bool
	}{
		{
			name:  "basic SYSCALL event",
			input: `type=SYSCALL msg=audit(1640995200.000:123): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff1234 comm="vim" uid=1000`,
			expected: &audit.AuditEvent{
				Timestamp: time.Unix(1640995200, 0),
				Type:      "SYSCALL",
				Fields: map[string]string{
					"arch":    "c000003e",
					"syscall": "257",
					"success": "yes",
					"exit":    "3",
					"a0":      "ffffff9c",
					"a1":      "7fff1234",
					"comm":    "vim",
					"uid":     "1000",
				},
				Raw: `type=SYSCALL msg=audit(1640995200.000:123): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff1234 comm="vim" uid=1000`,
			},
			wantErr: false,
		},
		{
			name:  "PATH event with file path",
			input: `type=PATH msg=audit(1640995200.123:124): item=0 name="/etc/nginx/nginx.conf" inode=12345 mode=0100644`,
			expected: &audit.AuditEvent{
				Timestamp: time.Unix(1640995200, 123000000), // 0.123 seconds = 123 million nanoseconds
				Type:      "PATH",
				Fields: map[string]string{
					"item":  "0",
					"name":  "/etc/nginx/nginx.conf",
					"inode": "12345",
					"mode":  "0100644",
				},
				Raw: `type=PATH msg=audit(1640995200.123:124): item=0 name="/etc/nginx/nginx.conf" inode=12345 mode=0100644`,
			},
			wantErr: false,
		},
		{
			name:    "empty line",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid format - no type",
			input:   "invalid line without proper format",
			wantErr: true,
		},
		{
			name:    "invalid timestamp",
			input:   `type=SYSCALL msg=audit(invalid:123): syscall=257`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := parser.ParseLine(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Check timestamp (allow small floating point precision differences)
			timeDiff := event.Timestamp.Sub(tt.expected.Timestamp)
			if timeDiff < -time.Microsecond || timeDiff > time.Microsecond {
				t.Errorf("timestamp mismatch: got %v, want %v (diff: %v)", event.Timestamp, tt.expected.Timestamp, timeDiff)
			}

			// Check type
			if event.Type != tt.expected.Type {
				t.Errorf("type mismatch: got %v, want %v", event.Type, tt.expected.Type)
			}

			// Check fields
			for key, expectedValue := range tt.expected.Fields {
				if actualValue, exists := event.Fields[key]; !exists {
					t.Errorf("missing field %s", key)
				} else if actualValue != expectedValue {
					t.Errorf("field %s mismatch: got %v, want %v", key, actualValue, expectedValue)
				}
			}

			// Check raw
			if event.Raw != tt.expected.Raw {
				t.Errorf("raw mismatch: got %v, want %v", event.Raw, tt.expected.Raw)
			}
		})
	}
}

func TestAuditdParser_ParseLine_EdgeCases(t *testing.T) {
	parser := NewAuditdParser()

	t.Run("quoted values with spaces", func(t *testing.T) {
		input := `type=EXECVE msg=audit(1640995200.000:125): argc=3 a0="ls" a1="-la" a2="/var/log/audit"`
		event, err := parser.ParseLine(input)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expectedFields := map[string]string{
			"argc": "3",
			"a0":   "ls",
			"a1":   "-la", 
			"a2":   "/var/log/audit",
		}

		for key, expected := range expectedFields {
			if actual, exists := event.Fields[key]; !exists {
				t.Errorf("missing field %s", key)
			} else if actual != expected {
				t.Errorf("field %s: got %v, want %v", key, actual, expected)
			}
		}
	})
}