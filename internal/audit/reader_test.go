package audit

import (
	"os"
	"strings"
	"testing"
)

func TestFileLogReader_ReadEvent(t *testing.T) {
	testData := `type=SYSCALL msg=audit(1640995200.000:123): arch=c000003e syscall=257 success=yes comm="vim" uid=1000
type=PATH msg=audit(1640995200.123:124): item=0 name="/etc/nginx/nginx.conf" inode=12345
type=SYSCALL msg=audit(1640995201.000:125): arch=c000003e syscall=1 success=yes comm="vim" uid=1000
`

	tmpFile, err := os.CreateTemp("", "audit_test_*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(testData); err != nil {
		t.Fatalf("failed to write test data: %v", err)
	}
	tmpFile.Close()

	reader, err := NewFileLogReader(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to create reader: %v", err)
	}
	defer reader.Close()

	expectedEvents := 3
	eventCount := 0

	for {
		event, err := reader.ReadEvent()
		if err != nil {
			if strings.Contains(err.Error(), "EOF") {
				break
			}
			t.Fatalf("unexpected error reading event: %v", err)
		}

		eventCount++

		if event.Raw == "" {
			t.Errorf("event %d has empty raw content", eventCount)
		}
	}

	if eventCount != expectedEvents {
		t.Errorf("expected %d events, got %d", expectedEvents, eventCount)
	}
}

func TestFileLogReader_NonExistentFile(t *testing.T) {
	_, err := NewFileLogReader("/non/existent/file.log")
	if err == nil {
		t.Errorf("expected error for non-existent file")
	}
}

func TestFileLogReader_EmptyFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "empty_audit_*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	reader, err := NewFileLogReader(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to create reader: %v", err)
	}
	defer reader.Close()

	_, err = reader.ReadEvent()
	if err == nil {
		t.Errorf("expected EOF error for empty file")
	}
}