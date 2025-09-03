package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/sarataha/changelog/internal/rawcollector"
)

func main() {
	var (
		auditLogPath = flag.String("audit-log", "/var/log/audit/audit.log", "Path to audit log file")
		incidentTime = flag.String("incident-time", "", "Incident time (RFC3339 or HH:MM:SS)")
		window       = flag.String("window", "1h", "Time window around incident (e.g., 10m, 2h)")
		sources      = flag.String("sources", "auditd,journalctl", "Comma-separated list of sources")
	)
	flag.Parse()

	// Check if running as root
	if os.Geteuid() != 0 {
		log.Fatalf("Error: This tool requires root access to read system logs.\nRun: sudo %s [options]", os.Args[0])
	}

	fmt.Printf("=== Multi-Source Event Collection ===\n")

	// Parse time range
	timeRange, err := parseTimeRange(*incidentTime, *window)
	if err != nil {
		log.Fatalf("Failed to parse time range: %v", err)
	}

	// Create raw log collector
	collector := rawcollector.NewRawLogCollector()

	// Collect raw logs from requested sources
	requestedSources := strings.Split(*sources, ",")
	for _, srcName := range requestedSources {
		srcName = strings.TrimSpace(srcName)

		switch srcName {
		case "auditd":
			err := collector.CollectAuditd(*auditLogPath, timeRange)
			if err != nil {
				log.Printf("Warning: Failed to collect auditd logs: %v", err)
			}
		case "journalctl":
			err := collector.CollectJournalctl(timeRange)
			if err != nil {
				log.Printf("Warning: Failed to collect journalctl logs: %v", err)
			}
		}
	}

	// Get all raw logs
	rawLogs := collector.GetRawLogs()

	if len(rawLogs) == 0 {
		fmt.Printf("No events found in the specified time window.\n")
		return
	}

	// Show raw logs for now (AI too slow on this VM)
	fmt.Printf("=== System Changes Timeline (%d events) ===\n", len(rawLogs))
	for _, entry := range rawLogs {
		fmt.Printf("%s [%s] %s\n",
			entry.Timestamp.Format("15:04:05"),
			entry.Source,
			entry.Raw)
	}
}

func parseTimeRange(incidentTimeStr, windowStr string) (rawcollector.TimeRange, error) {
	window, err := parseWindow(windowStr)
	if err != nil {
		return rawcollector.TimeRange{}, err
	}

	var incidentTime time.Time
	if incidentTimeStr == "" {
		incidentTime = time.Now()
	} else {
		incidentTime, err = parseIncidentTime(incidentTimeStr)
		if err != nil {
			return rawcollector.TimeRange{}, err
		}
	}

	halfWindow := window / 2
	return rawcollector.TimeRange{
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
