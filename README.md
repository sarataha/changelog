# changelog

converts cryptic Linux logs to human-readable incident timelines

**Architecture:** Raw log collection -> AI interpretation -> correlation timeline

```bash
# Basic usage
sudo ./changelog

# Incident analysis  
sudo ./changelog --incident-time "14:32:00" --window 10m

# Filter sources
sudo ./changelog --sources auditd,journalctl --window 1h

# Build
go build -o changelog cmd/changelog/main.go
```

**Next phase:** AI-powered log interpretation and correlation engine
