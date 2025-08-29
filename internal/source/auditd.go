package source

import (
	"io"

	"github.com/sarataha/changelog/internal/audit"
	"github.com/sarataha/changelog/internal/parser"
)

// AuditdLogSource implements LogSource for auditd logs
type AuditdLogSource struct {
	reader            audit.LogReader
	auditParser       *parser.AuditdParser
	userCmdInterpreter *parser.UserCommandInterpreter
	syscallInterpreter *parser.SyscallInterpreter
}

// NewAuditdLogSource creates a new auditd log source
func NewAuditdLogSource(reader io.Reader) (*AuditdLogSource, error) {
	logReader, err := audit.NewReaderLogReader(reader)
	if err != nil {
		return nil, err
	}

	return &AuditdLogSource{
		reader:            logReader,
		auditParser:       parser.NewAuditdParser(),
		userCmdInterpreter: parser.NewUserCommandInterpreter(),
		syscallInterpreter: parser.NewSyscallInterpreter(),
	}, nil
}

// Name returns the source name
func (a *AuditdLogSource) Name() string {
	return "auditd"
}

// ReadEvents reads and converts auditd events within the time range
func (a *AuditdLogSource) ReadEvents(timeRange TimeRange) ([]*SystemEvent, error) {
	var systemEvents []*SystemEvent

	for {
		rawEvent, err := a.reader.ReadEvent()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		event, err := a.auditParser.ParseLine(rawEvent.Raw)
		if err != nil {
			continue
		}

		// Filter by time range
		if !timeRange.Contains(event.Timestamp) {
			continue
		}

		var action *audit.SystemAction
		switch event.Type {
		case "USER_CMD":
			action, err = a.userCmdInterpreter.Interpret(event)
		case "SYSCALL":
			action, err = a.syscallInterpreter.Interpret(event)
		default:
			continue
		}

		if err != nil || action == nil {
			continue
		}

		systemEvent := &SystemEvent{
			Timestamp: event.Timestamp,
			Source:    "auditd",
			Type:      event.Type,
			User:      action.User,
			Action:    action.Action,
			Target:    action.Target,
			Process:   action.Process,
			Raw:       rawEvent.Raw,
		}

		systemEvents = append(systemEvents, systemEvent)
	}

	return systemEvents, nil
}

// Close closes the underlying reader
func (a *AuditdLogSource) Close() error {
	return a.reader.Close()
}