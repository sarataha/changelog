package source

import (
	"strings"
	"testing"
	"time"
)

func TestJournalctlLogSource_ReadEvents(t *testing.T) {
	mockData := `Aug 29 14:27:16 server nginx[1234]: nginx: configuration reload completed
Aug 29 14:27:17 server systemd[1]: nginx.service: Failed with result 'exit-code'
Aug 29 14:27:20 server systemd[1]: nginx.service: Starting A high performance web server and a reverse proxy server...
Aug 29 14:27:22 server systemd[1]: nginx.service: Started A high performance web server and a reverse proxy server.`

	reader := strings.NewReader(mockData)
	source, err := NewJournalctlLogSource(reader)
	if err != nil {
		t.Fatalf("failed to create journalctl log source: %v", err)
	}
	defer source.Close()

	timeRange := TimeRange{
		Start: time.Date(2025, 8, 29, 14, 25, 0, 0, time.UTC),
		End:   time.Date(2025, 8, 29, 14, 30, 0, 0, time.UTC),
	}

	events, err := source.ReadEvents(timeRange)
	if err != nil {
		t.Fatalf("failed to read events: %v", err)
	}

	if len(events) < 2 {
		t.Fatalf("expected at least 2 events, got %d", len(events))
	}

	// Check service failure event
	failEvent := events[1]
	if failEvent.Source != "journalctl" {
		t.Errorf("expected source 'journalctl', got %v", failEvent.Source)
	}

	if failEvent.Type != "service_status" {
		t.Errorf("expected type 'service_status', got %v", failEvent.Type)
	}

	if failEvent.Action != "failed" {
		t.Errorf("expected action 'failed', got %v", failEvent.Action)
	}

	if failEvent.Target != "nginx.service" {
		t.Errorf("expected target 'nginx.service', got %v", failEvent.Target)
	}
}

func TestJournalctlLogSource_Name(t *testing.T) {
	reader := strings.NewReader("")
	source, _ := NewJournalctlLogSource(reader)
	
	if source.Name() != "journalctl" {
		t.Errorf("expected name 'journalctl', got %v", source.Name())
	}
}