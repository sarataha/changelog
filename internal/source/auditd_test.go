package source

import (
	"strings"
	"testing"
	"time"
)

func TestAuditdLogSource_ReadEvents(t *testing.T) {
	mockData := `type=USER_CMD msg=audit(1756466111.765:123): uid=501 cmd=7461696C202D3230202F7661722F6C6F672F61756469742F61756469742E6C6F67 exe=/usr/bin/sudo`

	reader := strings.NewReader(mockData)
	source, err := NewAuditdLogSource(reader)
	if err != nil {
		t.Fatalf("failed to create auditd log source: %v", err)
	}
	defer source.Close()

	timeRange := TimeRange{
		Start: time.Unix(1756466000, 0),
		End:   time.Unix(1756466200, 0),
	}

	events, err := source.ReadEvents(timeRange)
	if err != nil {
		t.Fatalf("failed to read events: %v", err)
	}

	if len(events) == 0 {
		t.Fatal("expected at least one event")
	}

	event := events[0]
	if event.Source != "auditd" {
		t.Errorf("expected source 'auditd', got %v", event.Source)
	}

	if event.Type != "USER_CMD" {
		t.Errorf("expected type 'USER_CMD', got %v", event.Type)
	}

	if event.User != "501" {
		t.Errorf("expected user '501', got %v", event.User)
	}

	if event.Action != "executed" {
		t.Errorf("expected action 'executed', got %v", event.Action)
	}
}

func TestAuditdLogSource_Name(t *testing.T) {
	reader := strings.NewReader("")
	source, _ := NewAuditdLogSource(reader)
	
	if source.Name() != "auditd" {
		t.Errorf("expected name 'auditd', got %v", source.Name())
	}
}