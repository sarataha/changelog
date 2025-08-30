# changelog

converts cryptic Linux logs to human-readable incident timelines

**Current:** Multi-source readers (auditd + journalctl + dmesg + app logs)  
**Goal:** Time based clustering for incident timelines

```bash
go run cmd/changelog/main.go [audit-log-path]
# Output: 2025-08-29 14:15:11 sara executed: tail -20 /var/log/audit/audit.log

go test ./...  # Run tests
```

Architecture: LogSource interface -> SystemEvent -> eventual correlation engine
