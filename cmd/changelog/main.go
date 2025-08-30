package main

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sarataha/changelog/internal/source"
)

func main() {
	auditLogPath := "/var/log/audit/audit.log"
	if len(os.Args) > 1 {
		auditLogPath = os.Args[1]
	}

	fmt.Printf("=== Multi-Source Event Collection ===\n")

	// Create all log sources
	sources, err := createLogSources(auditLogPath)
	if err != nil {
		log.Fatalf("Failed to create log sources: %v", err)
	}
	defer closeLogSources(sources)

	// Set time range (last 1 hour for demo)
	now := time.Now()
	timeRange := source.TimeRange{
		Start: now.Add(-1 * time.Hour),
		End:   now,
	}

	// Collect events from all sources
	allEvents, err := collectEventsFromSources(sources, timeRange)
	if err != nil {
		log.Fatalf("Failed to collect events: %v", err)
	}

	// Sort by timestamp
	sortEventsByTimestamp(allEvents)

	// Display timeline
	fmt.Printf("=== Timeline (%d events) ===\n", len(allEvents))
	for _, event := range allEvents {
		fmt.Printf("%s [%s] %s %s: %s\n",
			event.Timestamp.Format("15:04:05"),
			event.Source,
			event.User,
			event.Action,
			event.Target)
	}
}

func createLogSources(auditLogPath string) ([]source.LogSource, error) {
	var sources []source.LogSource

	// Try to create auditd source
	if auditFile, err := os.Open(auditLogPath); err == nil {
		if auditSource, err := source.NewAuditdLogSource(auditFile); err == nil {
			sources = append(sources, auditSource)
		}
	}

	// For now, use empty readers for other sources (will add real commands later)
	journalSource, _ := source.NewJournalctlLogSource(strings.NewReader(""))
	dmesgSource, _ := source.NewDmesgLogSource(strings.NewReader(""))

	sources = append(sources, journalSource, dmesgSource)
	return sources, nil
}

func closeLogSources(sources []source.LogSource) {
	for _, src := range sources {
		src.Close()
	}
}

func collectEventsFromSources(sources []source.LogSource, timeRange source.TimeRange) ([]*source.SystemEvent, error) {
	var allEvents []*source.SystemEvent

	for _, src := range sources {
		events, err := src.ReadEvents(timeRange)
		if err != nil {
			log.Printf("Error reading from %s: %v", src.Name(), err)
			continue
		}
		allEvents = append(allEvents, events...)
	}

	return allEvents, nil
}

func sortEventsByTimestamp(events []*source.SystemEvent) {
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
}