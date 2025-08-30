package source

import (
	"strings"
	"testing"
	"time"
)

func TestDmesgLogSource_ReadEvents(t *testing.T) {
	mockData := `[Aug29 14:27:15] Out of memory: Kill process 1234 (nginx) score 900 or sacrifice child
[Aug29 14:27:16] Killed process 1234 (nginx) total-vm:524288kB, anon-rss:262144kB, file-rss:0kB, shmem-rss:0kB
[Aug29 14:28:00] EXT4-fs (sda1): mounted filesystem with ordered data mode
[Aug29 14:29:12] ACPI: \_SB_.PCI0.GP17.XHC0.RHUB.HS03: USB disconnect, address 1`

	reader := strings.NewReader(mockData)
	source, err := NewDmesgLogSource(reader)
	if err != nil {
		t.Fatalf("failed to create dmesg log source: %v", err)
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

	// Check OOM kill event
	oomEvent := events[0]
	if oomEvent.Source != "dmesg" {
		t.Errorf("expected source 'dmesg', got %v", oomEvent.Source)
	}

	if oomEvent.Type != "kernel_oom" {
		t.Errorf("expected type 'kernel_oom', got %v", oomEvent.Type)
	}

	if oomEvent.Action != "oom_kill" {
		t.Errorf("expected action 'oom_kill', got %v", oomEvent.Action)
	}

	if oomEvent.Target != "nginx (pid 1234)" {
		t.Errorf("expected target 'nginx (pid 1234)', got %v", oomEvent.Target)
	}
}

func TestDmesgLogSource_Name(t *testing.T) {
	reader := strings.NewReader("")
	source, _ := NewDmesgLogSource(reader)
	
	if source.Name() != "dmesg" {
		t.Errorf("expected name 'dmesg', got %v", source.Name())
	}
}