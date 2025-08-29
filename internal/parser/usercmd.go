package parser

import (
	"encoding/hex"
	"fmt"
	"path/filepath"

	"github.com/sarataha/changelog/internal/audit"
)

// UserCommandInterpreter handles USER_CMD events with hex-encoded commands
type UserCommandInterpreter struct {
	userResolver *UserResolver
}

// NewUserCommandInterpreter creates a new USER_CMD interpreter
func NewUserCommandInterpreter() *UserCommandInterpreter {
	return &UserCommandInterpreter{
		userResolver: NewUserResolver(),
	}
}

// Interpret converts a USER_CMD AuditEvent to a SystemAction
func (u *UserCommandInterpreter) Interpret(event *audit.AuditEvent) (*audit.SystemAction, error) {
	if event.Type != "USER_CMD" {
		return nil, fmt.Errorf("not a USER_CMD event: %s", event.Type)
	}

	cmdHex, exists := event.Fields["cmd"]
	if !exists {
		return nil, fmt.Errorf("missing cmd field")
	}

	decodedCmd := u.decodeHexCommand(cmdHex)
	exe := event.Fields["exe"]
	
	process := "unknown"
	if exe != "" {
		process = filepath.Base(exe)
	}

	action := &audit.SystemAction{
		Timestamp: event.Timestamp.Format("2006-01-02 15:04:05"),
		User:      u.userResolver.GetUsername(event.Fields["uid"]),
		Action:    "executed",
		Target:    decodedCmd,
		Process:   process,
	}

	return action, nil
}

// decodeHexCommand converts hex-encoded command string to readable text
func (u *UserCommandInterpreter) decodeHexCommand(hexCmd string) string {
	if hexCmd == "" {
		return ""
	}

	decoded, err := hex.DecodeString(hexCmd)
	if err != nil {
		return hexCmd
	}

	return string(decoded)
}