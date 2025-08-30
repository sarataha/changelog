package main

import (
	"strings"
	"testing"
	"time"

	"github.com/sarataha/changelog/internal/source"
)

func TestCollectEventsFromSources(t *testing.T) {
	// Mock data for different sources
	auditData := `type=USER_CMD msg=audit(1756466111.765:123): uid=501 cmd=7461696C202D3230202F7661722F6C6F672F61756469742F61756469742E6C6F67 exe=/usr/bin/sudo`
	
	journalData := `Aug 29 14:27:16 server nginx[1234]: nginx: configuration reload completed
Aug 29 14:27:17 server systemd[1]: nginx.service: Failed with result 'exit-code'`

	dmesgData := `[Aug29 14:27:15] Out of memory: Kill process 1234 (nginx) score 900 or sacrifice child`

	// Create log sources
	auditSource, _ := source.NewAuditdLogSource(strings.NewReader(auditData))
	journalSource, _ := source.NewJournalctlLogSource(strings.NewReader(journalData))
	dmesgSource, _ := source.NewDmesgLogSource(strings.NewReader(dmesgData))

	sources := []source.LogSource{auditSource, journalSource, dmesgSource}

	timeRange := source.TimeRange{
		Start: time.Date(2025, 8, 29, 14, 0, 0, 0, time.UTC),
		End:   time.Date(2025, 8, 29, 15, 0, 0, 0, time.UTC),
	}

	allEvents, err := collectEventsFromSources(sources, timeRange)
	if err != nil {
		t.Fatalf("failed to collect events: %v", err)
	}

	if len(allEvents) < 2 {
		t.Fatalf("expected at least 2 events from different sources, got %d", len(allEvents))
	}

	// Verify we have events from different sources
	sourceCount := make(map[string]int)
	for _, event := range allEvents {
		sourceCount[event.Source]++
	}

	if len(sourceCount) < 2 {
		t.Error("expected events from multiple sources")
	}
}

func TestEventsSortedByTimestamp(t *testing.T) {
	events := []*source.SystemEvent{
		{Timestamp: time.Unix(1000, 0), Source: "test"},
		{Timestamp: time.Unix(500, 0), Source: "test"},
		{Timestamp: time.Unix(1500, 0), Source: "test"},
	}

	sortEventsByTimestamp(events)

	if !events[0].Timestamp.Before(events[1].Timestamp) {
		t.Error("events not sorted by timestamp")
	}
	if !events[1].Timestamp.Before(events[2].Timestamp) {
		t.Error("events not sorted by timestamp")
	}
}