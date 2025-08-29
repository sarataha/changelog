package parser

import (
	"testing"
	"time"

	"github.com/sarataha/changelog/internal/audit"
)

func TestUserCommandInterpreter_Interpret(t *testing.T) {
	interpreter := NewUserCommandInterpreter()

	tests := []struct {
		name     string
		event    *audit.AuditEvent
		expected *audit.SystemAction
		wantErr  bool
	}{
		{
			name: "tail command",
			event: &audit.AuditEvent{
				Timestamp: time.Unix(1756466111, 765000000),
				Type:      "USER_CMD",
				Fields: map[string]string{
					"uid": "501",
					"cmd": "7461696C202D3230202F7661722F6C6F672F61756469742F61756469742E6C6F67",
					"exe": "/usr/bin/sudo",
					"cwd": "/home/sara.linux",
				},
			},
			expected: &audit.SystemAction{
				Timestamp: "2025-08-29 14:01:51",
				User:      "501",
				Action:    "executed",
				Target:    "tail -20 /var/log/audit/audit.log",
				Process:   "sudo",
			},
			wantErr: false,
		},
		{
			name: "systemctl start command",
			event: &audit.AuditEvent{
				Timestamp: time.Unix(1756465235, 833000000),
				Type:      "USER_CMD",
				Fields: map[string]string{
					"uid": "501",
					"cmd": "73797374656D63746C20737461727420617564697464",
					"exe": "/usr/bin/sudo",
				},
			},
			expected: &audit.SystemAction{
				Timestamp: "2025-08-29 13:47:15",
				User:      "501",
				Action:    "executed",
				Target:    "systemctl start auditd",
				Process:   "sudo",
			},
			wantErr: false,
		},
		{
			name: "cat command",
			event: &audit.AuditEvent{
				Timestamp: time.Unix(1756466362, 905000000),
				Type:      "USER_CMD",
				Fields: map[string]string{
					"uid": "501",
					"cmd": "636174202F7661722F6C6F672F61756469742F61756469742E6C6F67",
					"exe": "/usr/bin/sudo",
				},
			},
			expected: &audit.SystemAction{
				Timestamp: "2025-08-29 14:06:02",
				User:      "501",
				Action:    "executed",
				Target:    "cat /var/log/audit/audit.log",
				Process:   "sudo",
			},
			wantErr: false,
		},
		{
			name: "non-USER_CMD event",
			event: &audit.AuditEvent{
				Type: "SYSCALL",
				Fields: map[string]string{
					"syscall": "257",
				},
			},
			expected: nil,
			wantErr:  true,
		},
		{
			name: "missing cmd field",
			event: &audit.AuditEvent{
				Type: "USER_CMD",
				Fields: map[string]string{
					"uid": "501",
					"exe": "/usr/bin/sudo",
				},
			},
			expected: nil,
			wantErr:  true,
		},
		{
			name: "invalid hex",
			event: &audit.AuditEvent{
				Type: "USER_CMD",
				Fields: map[string]string{
					"uid": "501",
					"cmd": "invalid_hex",
					"exe": "/usr/bin/sudo",
				},
			},
			expected: &audit.SystemAction{
				Timestamp: "1970-01-01 02:00:00",
				User:      "501",
				Action:    "executed",
				Target:    "invalid_hex",
				Process:   "sudo",
			},
			wantErr: false,
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

			if len(action.Timestamp) == 0 {
				t.Errorf("timestamp is empty")
			}

			if action.User != tt.expected.User {
				t.Errorf("user mismatch: got %v, want %v", action.User, tt.expected.User)
			}

			if action.Action != tt.expected.Action {
				t.Errorf("action mismatch: got %v, want %v", action.Action, tt.expected.Action)
			}

			if action.Target != tt.expected.Target {
				t.Errorf("target mismatch: got %v, want %v", action.Target, tt.expected.Target)
			}

			if action.Process != tt.expected.Process {
				t.Errorf("process mismatch: got %v, want %v", action.Process, tt.expected.Process)
			}
		})
	}
}

func TestDecodeHexCommand(t *testing.T) {
	interpreter := NewUserCommandInterpreter()

	tests := []struct {
		name     string
		hexCmd   string
		expected string
	}{
		{
			name:     "tail command",
			hexCmd:   "7461696C202D3230202F7661722F6C6F672F61756469742F61756469742E6C6F67",
			expected: "tail -20 /var/log/audit/audit.log",
		},
		{
			name:     "systemctl start",
			hexCmd:   "73797374656D63746C20737461727420617564697464",
			expected: "systemctl start auditd",
		},
		{
			name:     "cat command",
			hexCmd:   "636174202F7661722F6C6F672F61756469742F61756469742E6C6F67",
			expected: "cat /var/log/audit/audit.log",
		},
		{
			name:     "empty hex",
			hexCmd:   "",
			expected: "",
		},
		{
			name:     "invalid hex",
			hexCmd:   "invalid",
			expected: "invalid",
		},
		{
			name:     "odd length hex",
			hexCmd:   "123",
			expected: "123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := interpreter.decodeHexCommand(tt.hexCmd)
			if result != tt.expected {
				t.Errorf("decodeHexCommand(%s) = %v, want %v", tt.hexCmd, result, tt.expected)
			}
		})
	}
}