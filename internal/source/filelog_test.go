package source

import (
	"strings"
	"testing"
	"time"
)

func TestFileLogSource_ReadEvents(t *testing.T) {
	mockData := `2025/08/29 14:27:15 [error] 1234#0: *567 connect() failed (111: Connection refused) while connecting to upstream
2025/08/29 14:27:16 [warn] 1234#0: worker process 5678 exited on signal 9
2025/08/29 14:27:17 [info] 1234#0: signal 15 (SIGTERM) received, shutting down
Aug 29 14:28:00 server nginx: configuration test successful
2025-08-29T14:28:01.123Z INFO Starting HTTP server on port 8080`

	reader := strings.NewReader(mockData)
	source, err := NewFileLogSource(reader, "nginx")
	if err != nil {
		t.Fatalf("failed to create file log source: %v", err)
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

	if len(events) < 3 {
		t.Fatalf("expected at least 3 events, got %d", len(events))
	}

	// Check error event
	errorEvent := events[0]
	if errorEvent.Source != "nginx" {
		t.Errorf("expected source 'nginx', got %v", errorEvent.Source)
	}

	if errorEvent.Type != "application_error" {
		t.Errorf("expected type 'application_error', got %v", errorEvent.Type)
	}

	if errorEvent.Action != "connection_failed" {
		t.Errorf("expected action 'connection_failed', got %v", errorEvent.Action)
	}

	// Check shutdown event
	shutdownEvent := events[2]
	if shutdownEvent.Type != "application_lifecycle" {
		t.Errorf("expected type 'application_lifecycle', got %v", shutdownEvent.Type)
	}

	if shutdownEvent.Action != "shutdown" {
		t.Errorf("expected action 'shutdown', got %v", shutdownEvent.Action)
	}
}

func TestFileLogSource_Name(t *testing.T) {
	reader := strings.NewReader("")
	source, _ := NewFileLogSource(reader, "testapp")
	
	if source.Name() != "testapp" {
		t.Errorf("expected name 'testapp', got %v", source.Name())
	}
}