package parser

import (
	"testing"
	"time"

	"github.com/sarataha/changelog/internal/audit"
)

func TestSyscallInterpreter_Interpret(t *testing.T) {
	interpreter := NewSyscallInterpreter()

	tests := []struct {
		name     string
		event    *audit.AuditEvent
		expected *audit.SystemAction
		wantErr  bool
	}{
		{
			name: "openat syscall with file path",
			event: &audit.AuditEvent{
				Timestamp: time.Unix(1640995200, 0),
				Type:      "SYSCALL",
				Fields: map[string]string{
					"syscall": "257",
					"comm":    "vim",
					"uid":     "1000",
					"success": "yes",
				},
			},
			expected: &audit.SystemAction{
				Action:    "openat",
				Process:   "vim",
				User:      "1000",
				Timestamp: "2022-01-01 02:00:00",
			},
			wantErr: false,
		},
		{
			name: "write syscall",
			event: &audit.AuditEvent{
				Timestamp: time.Unix(1640995201, 0),
				Type:      "SYSCALL",
				Fields: map[string]string{
					"syscall": "1",
					"comm":    "vim",
					"uid":     "1000",
					"success": "yes",
				},
			},
			expected: &audit.SystemAction{
				Action:    "write",
				Process:   "vim",
				User:      "1000",
				Timestamp: "2022-01-01 02:00:01",
			},
			wantErr: false,
		},
		{
			name: "unlink syscall (delete)",
			event: &audit.AuditEvent{
				Timestamp: time.Unix(1640995202, 0),
				Type:      "SYSCALL",
				Fields: map[string]string{
					"syscall": "87",
					"comm":    "rm",
					"uid":     "0",
					"success": "yes",
				},
			},
			expected: &audit.SystemAction{
				Action:    "unlink",
				Process:   "rm",
				User:      "0",
				Timestamp: "2022-01-01 02:00:02",
			},
			wantErr: false,
		},
		{
			name: "unknown syscall number",
			event: &audit.AuditEvent{
				Timestamp: time.Unix(1640995203, 0),
				Type:      "SYSCALL",
				Fields: map[string]string{
					"syscall": "9999",
					"comm":    "unknown",
					"uid":     "1000",
					"success": "yes",
				},
			},
			expected: &audit.SystemAction{
				Action:    "syscall_9999",
				Process:   "unknown",
				User:      "1000",
				Timestamp: "2022-01-01 02:00:03",
			},
			wantErr: false,
		},
		{
			name: "non-SYSCALL event type",
			event: &audit.AuditEvent{
				Type: "PATH",
				Fields: map[string]string{
					"name": "/etc/passwd",
				},
			},
			expected: nil,
			wantErr:  true,
		},
		{
			name: "missing syscall field",
			event: &audit.AuditEvent{
				Type: "SYSCALL",
				Fields: map[string]string{
					"comm": "vim",
					"uid":  "1000",
				},
			},
			expected: nil,
			wantErr:  true,
		},
		{
			name: "invalid syscall number",
			event: &audit.AuditEvent{
				Type: "SYSCALL",
				Fields: map[string]string{
					"syscall": "invalid",
					"comm":    "vim",
					"uid":     "1000",
				},
			},
			expected: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action, err := interpreter.Interpret(tt.event)

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

			if action.Action != tt.expected.Action {
				t.Errorf("action mismatch: got %v, want %v", action.Action, tt.expected.Action)
			}

			if action.Process != tt.expected.Process {
				t.Errorf("process mismatch: got %v, want %v", action.Process, tt.expected.Process)
			}

			if action.User != tt.expected.User {
				t.Errorf("user mismatch: got %v, want %v", action.User, tt.expected.User)
			}

			if action.Timestamp != tt.expected.Timestamp {
				t.Errorf("timestamp mismatch: got %v, want %v", action.Timestamp, tt.expected.Timestamp)
			}
		})
	}
}

func TestSyscallInterpreter_GetSyscallName(t *testing.T) {
	interpreter := NewSyscallInterpreter()

	tests := []struct {
		syscallNum int
		expected   string
	}{
		{1, "write"},
		{2, "open"},
		{87, "unlink"},
		{257, "openat"},
		{9999, "syscall_9999"}, // unknown syscall
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := interpreter.GetSyscallName(tt.syscallNum)
			if result != tt.expected {
				t.Errorf("getSyscallName(%d) = %v, want %v", tt.syscallNum, result, tt.expected)
			}
		})
	}
}