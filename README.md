# changelog

converts cryptic Linux logs to human-readable incident timelines

**Current:** Multi-source readers (auditd + journalctl + dmesg + app logs)  
**Goal:** Time based clustering for incident timelines

```bash
# Basic usage
go run cmd/changelog/main.go

# Incident analysis  
go run cmd/changelog/main.go --incident-time "14:32:00" --window 10m

# Filter sources
go run cmd/changelog/main.go --sources auditd,journalctl --window 1h

go test ./...  # Run tests
```

Architecture: LogSource interface -> SystemEvent -> eventual correlation engine
