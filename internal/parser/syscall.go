package parser

import (
	"fmt"
	"strconv"

	"github.com/sarataha/changelog/internal/audit"
)

// SyscallInterpreter maps syscall numbers to human-readable actions
type SyscallInterpreter struct {
	syscallMap map[int]string
}

// NewSyscallInterpreter creates a new syscall interpreter with common syscalls
func NewSyscallInterpreter() *SyscallInterpreter {
	return &SyscallInterpreter{
		syscallMap: map[int]string{
			1:   "write",
			2:   "open",
			3:   "close",
			87:  "unlink",
			257: "openat",
			262: "newfstatat",
			263: "unlinkat",
		},
	}
}

// Interpret converts an AuditEvent to a SystemAction
func (s *SyscallInterpreter) Interpret(event *audit.AuditEvent) (*audit.SystemAction, error) {
	if event.Type != "SYSCALL" {
		return nil, fmt.Errorf("not a SYSCALL event: %s", event.Type)
	}

	syscallStr, exists := event.Fields["syscall"]
	if !exists {
		return nil, fmt.Errorf("missing syscall field")
	}

	syscallNum, err := strconv.Atoi(syscallStr)
	if err != nil {
		return nil, fmt.Errorf("invalid syscall number: %w", err)
	}

	action := &audit.SystemAction{
		Action:    s.GetSyscallName(syscallNum),
		Process:   event.Fields["comm"],
		User:      event.Fields["uid"],
		Timestamp: event.Timestamp.Format("2006-01-02 15:04:05"),
	}

	return action, nil
}

// GetSyscallName returns the human-readable name for a syscall number
func (s *SyscallInterpreter) GetSyscallName(syscallNum int) string {
	if name, exists := s.syscallMap[syscallNum]; exists {
		return name
	}
	return fmt.Sprintf("syscall_%d", syscallNum)
}