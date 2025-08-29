package output

import (
	"testing"

	"github.com/sarataha/changelog/internal/audit"
)

func TestSimpleFormatter_Format(t *testing.T) {
	formatter := NewSimpleFormatter()

	tests := []struct {
		name     string
		action   *audit.SystemAction
		expected string
	}{
		{
			name: "basic action formatting",
			action: &audit.SystemAction{
				Timestamp: "2022-01-01 15:30:45",
				User:      "john",
				Action:    "openat",
				Process:   "vim",
				Target:    "/etc/nginx/nginx.conf",
			},
			expected: "2022-01-01 15:30:45 john opened /etc/nginx/nginx.conf using vim",
		},
		{
			name: "write action",
			action: &audit.SystemAction{
				Timestamp: "2022-01-01 15:30:46",
				User:      "john",
				Action:    "write",
				Process:   "vim",
				Target:    "/etc/nginx/nginx.conf",
			},
			expected: "2022-01-01 15:30:46 john wrote to /etc/nginx/nginx.conf using vim",
		},
		{
			name: "unlink action",
			action: &audit.SystemAction{
				Timestamp: "2022-01-01 15:30:47",
				User:      "root",
				Action:    "unlink",
				Process:   "rm",
				Target:    "/tmp/oldfile.txt",
			},
			expected: "2022-01-01 15:30:47 root deleted /tmp/oldfile.txt using rm",
		},
		{
			name: "systemctl command",
			action: &audit.SystemAction{
				Timestamp: "2022-01-01 15:30:48",
				User:      "root",
				Action:    "execve",
				Process:   "systemctl",
				Target:    "restart nginx",
			},
			expected: "2022-01-01 15:30:48 root executed: systemctl restart nginx",
		},
		{
			name: "unknown action",
			action: &audit.SystemAction{
				Timestamp: "2022-01-01 15:30:49",
				User:      "john",
				Action:    "syscall_999",
				Process:   "unknown",
				Target:    "/some/file",
			},
			expected: "2022-01-01 15:30:49 john performed syscall_999 on /some/file using unknown",
		},
		{
			name: "action without target",
			action: &audit.SystemAction{
				Timestamp: "2022-01-01 15:30:50",
				User:      "john",
				Action:    "write",
				Process:   "vim",
				Target:    "",
			},
			expected: "2022-01-01 15:30:50 john performed write using vim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatter.Format(tt.action)
			if result != tt.expected {
				t.Errorf("Format() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestHumanFormatter_Format(t *testing.T) {
	formatter := NewHumanFormatter()

	action := &audit.SystemAction{
		Timestamp: "2022-01-01 15:30:45",
		User:      "john",
		Action:    "openat",
		Process:   "vim",
		Target:    "/etc/nginx/nginx.conf",
	}

	result := formatter.Format(action)
	expected := "2022-01-01 15:30:45 john opened /etc/nginx/nginx.conf using vim"

	if result != expected {
		t.Errorf("Format() = %v, want %v", result, expected)
	}
}