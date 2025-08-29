package source

import (
	"testing"
	"time"
)

func TestSystemEvent_Creation(t *testing.T) {
	timestamp := time.Unix(1756466111, 0)
	
	event := &SystemEvent{
		Timestamp: timestamp,
		Source:    "auditd",
		Type:      "USER_CMD",
		User:      "sara",
		Action:    "executed",
		Target:    "systemctl restart nginx",
		Process:   "sudo",
		Raw:       "type=USER_CMD msg=audit(1756466111.765:123): ...",
	}

	if event.Timestamp != timestamp {
		t.Errorf("expected timestamp %v, got %v", timestamp, event.Timestamp)
	}

	if event.Source != "auditd" {
		t.Errorf("expected source 'auditd', got %v", event.Source)
	}

	if event.GetKey() != "auditd-USER_CMD-sara-executed" {
		t.Errorf("unexpected event key: %s", event.GetKey())
	}
}

func TestTimeRange_Contains(t *testing.T) {
	start := time.Unix(1000, 0)
	end := time.Unix(2000, 0)
	timeRange := TimeRange{Start: start, End: end}

	tests := []struct {
		name      string
		timestamp time.Time
		expected  bool
	}{
		{
			name:      "before range",
			timestamp: time.Unix(500, 0),
			expected:  false,
		},
		{
			name:      "at start",
			timestamp: time.Unix(1000, 0),
			expected:  true,
		},
		{
			name:      "within range",
			timestamp: time.Unix(1500, 0),
			expected:  true,
		},
		{
			name:      "at end",
			timestamp: time.Unix(2000, 0),
			expected:  true,
		},
		{
			name:      "after range",
			timestamp: time.Unix(2500, 0),
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := timeRange.Contains(tt.timestamp)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}