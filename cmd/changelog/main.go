package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sarataha/changelog/internal/source"
)

func main() {
	var (
		auditLogPath  = flag.String("audit-log", "/var/log/audit/audit.log", "Path to audit log file")
		incidentTime  = flag.String("incident-time", "", "Incident time (RFC3339 or HH:MM:SS)")
		window        = flag.String("window", "1h", "Time window around incident (e.g., 10m, 2h)")
		sources       = flag.String("sources", "auditd,journalctl,dmesg", "Comma-separated list of sources")
	)
	flag.Parse()

	fmt.Printf("=== Multi-Source Event Collection ===\n")

	// Parse time range
	timeRange, err := parseTimeRange(*incidentTime, *window)
	if err != nil {
		log.Fatalf("Failed to parse time range: %v", err)
	}

	// Create log sources based on --sources flag
	logSources, err := createLogSources(*auditLogPath, *sources)
	if err != nil {
		log.Fatalf("Failed to create log sources: %v", err)
	}
	defer closeLogSources(logSources)

	// Collect events from all sources
	allEvents, err := collectEventsFromSources(logSources, timeRange)
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

func parseTimeRange(incidentTimeStr, windowStr string) (source.TimeRange, error) {
	window, err := parseWindow(windowStr)
	if err != nil {
		return source.TimeRange{}, err
	}

	var incidentTime time.Time
	if incidentTimeStr == "" {
		incidentTime = time.Now()
	} else {
		incidentTime, err = parseIncidentTime(incidentTimeStr)
		if err != nil {
			return source.TimeRange{}, err
		}
	}

	halfWindow := window / 2
	return source.TimeRange{
		Start: incidentTime.Add(-halfWindow),
		End:   incidentTime.Add(halfWindow),
	}, nil
}

func parseIncidentTime(timeStr string) (time.Time, error) {
	// Try RFC3339 format first
	if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
		return t, nil
	}

	// Try time-only format (HH:MM:SS)
	if t, err := time.Parse("15:04:05", timeStr); err == nil {
		now := time.Now()
		return time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), t.Second(), 0, now.Location()), nil
	}

	return time.Time{}, fmt.Errorf("invalid time format: %s (use RFC3339 or HH:MM:SS)", timeStr)
}

func parseWindow(windowStr string) (time.Duration, error) {
	return time.ParseDuration(windowStr)
}

func createLogSources(auditLogPath, sourcesStr string) ([]source.LogSource, error) {
	var logSources []source.LogSource
	requestedSources := strings.Split(sourcesStr, ",")

	for _, srcName := range requestedSources {
		srcName = strings.TrimSpace(srcName)
		
		switch srcName {
		case "auditd":
			if auditFile, err := os.Open(auditLogPath); err == nil {
				if auditSource, err := source.NewAuditdLogSource(auditFile); err == nil {
					logSources = append(logSources, auditSource)
				}
			}
		case "journalctl":
			// For now, use empty reader (will add real journalctl command later)
			journalSource, _ := source.NewJournalctlLogSource(strings.NewReader(""))
			logSources = append(logSources, journalSource)
		case "dmesg":
			// For now, use empty reader (will add real dmesg command later)
			dmesgSource, _ := source.NewDmesgLogSource(strings.NewReader(""))
			logSources = append(logSources, dmesgSource)
		}
	}

	return logSources, nil
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